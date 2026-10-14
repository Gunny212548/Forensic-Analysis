"""Streaming parsers: yield one row at a time from a file on disk.

Everything here is a generator on purpose - the pipeline feeds rows into
DuckDB in batches, so peak memory stays flat regardless of file size
instead of scaling with it (the previous version read the whole file into
a list of dicts, which is what made a 45MB CSV cost hundreds of MB).
"""

import csv
import gzip
import json
import os
import sys
from collections.abc import Iterator
from pathlib import Path

# Palo Alto exports have very long "Characteristic of app" style columns.
csv.field_size_limit(min(sys.maxsize, 2**31 - 1))


def open_text(path: Path, newline: str | None = None):
    """Open a log for reading as text, gunzipping on the fly when the name
    ends in .gz - read as a stream, never extracted to disk (FR-2.3)."""
    if str(path).lower().endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8-sig", errors="replace", newline=newline)
    return open(path, "r", encoding="utf-8-sig", errors="replace", newline=newline)


# Delimiters worth considering. Comma is the fallback because it is what the
# overwhelming majority of real exports use.
_DELIMITERS = (",", "\t", ";", "|")


def sniff_delimiter(path: Path) -> str:
    """Pick a CSV delimiter by counting candidates in the header line.

    Not optional, and not decoration: everything that reads a delimited file
    here used to assume a comma. A tab-separated Palo Alto export therefore
    parsed as ONE column whose name was the whole header, `decode` matched its
    candidates inside that single giant string, and the file ingested with
    every address field NULL and a whole row sitting in `category` - which
    then produced 78 malware findings off the row text alone (CLAUDE.md
    gotcha #22). DuckDB's own sniffer got the same file right, so the two
    halves of the pipeline disagreed about the shape of the file.

    Counting beats csv.Sniffer here: the answer is explainable, and on a real
    117-column export the winner is unambiguous (116 tabs vs 0 commas, or the
    reverse). Ties and empty headers fall back to comma.
    """
    with open_text(path, newline="") as fh:
        header = fh.readline()
    counts = {d: header.count(d) for d in _DELIMITERS}
    best = max(_DELIMITERS, key=lambda d: counts[d])
    return best if counts[best] else ","


# How often the iterators report progress (FR-2.5) - cheap enough to not
# show in the ingest rate, frequent enough for a bar to move.
PROGRESS_EVERY = 5000


def _position(fh) -> int:
    """Bytes consumed from the file on disk behind a text handle - for a .gz
    that is the compressed position, which is what os.path.getsize measures."""
    buf = getattr(fh, "buffer", None)
    target = getattr(buf, "fileobj", None) or buf  # GzipFile keeps the raw file in .fileobj
    try:
        return target.tell()
    except (AttributeError, OSError, ValueError):
        return 0


def _reporter(path: Path, progress):
    """progress(fraction) from a handle's position, or a no-op."""
    if progress is None:
        return None
    total = max(1, os.path.getsize(path))
    return lambda fh: progress(min(1.0, _position(fh) / total))


def iter_csv(path: Path, progress=None) -> Iterator[dict]:
    delimiter = sniff_delimiter(path)
    report = _reporter(path, progress)
    with open_text(path, newline="") as fh:
        for i, row in enumerate(csv.DictReader(fh, delimiter=delimiter), 1):
            if report and i % PROGRESS_EVERY == 0:
                report(fh)
            yield {k: v for k, v in row.items() if k and v not in (None, "")}


# --------------------------------------------------------------------- JSON
#
# Three layouts, all streamed in stdlib - a 10 GB upload (FR-2.2) must not
# be read into memory, which the first version did for every layout:
#
# - JSON-lines / NDJSON: one record per line, read a line at a time.
# - one top-level array: elements decoded one at a time with raw_decode()
#   over a buffer that only ever holds the element being read.
# - one top-level object: parsed whole - the format gives no way to stream
#   it - and, when it wraps the records in an array (CloudTrail `Records`,
#   a Microsoft Graph export's `value`), those are the records.
#
# A record is flattened to dotted keys (`status.errorCode`), so the column
# mapping of logsources/decode sees every field and not a stringified dict.
# Anything that cannot be read as a record is kept as a `_raw` row - evidence
# is not dropped - and counted in `stats`, which the pipeline reports on the
# case's mapping (IAI-35: "unparseable lines counted and reported").

JSON_CHUNK = 1 << 20
# Past this an array element that still has not parsed is taken to be
# broken, not merely incomplete - otherwise one bad byte would buffer the
# rest of a 10 GB file looking for its end.
JSON_ELEMENT_MAX = 64 << 20
# Keys a log export wraps its records in. Only a list of objects counts.
WRAPPER_KEYS = ("Records", "value", "records", "events", "Events", "logs", "data",
                "items", "results", "entries")
FLATTEN_DEPTH = 4
UNPARSEABLE_SAMPLES = 3

_decoder = json.JSONDecoder()


def _scalar(v) -> str | None:
    if v is None:
        return None
    if isinstance(v, bool):
        return "true" if v else "false"
    return str(v)


def flatten(obj: dict, prefix: str = "", out: dict | None = None, depth: int = 0) -> dict:
    """{"status": {"errorCode": 0}} -> {"status.errorCode": "0"}. A list of
    scalars is joined; a list of objects (Entra's applied conditional access
    policies, dozens per sign-in) stays one compact JSON value rather than
    exploding into numbered columns no profile could name."""
    out = {} if out is None else out
    for k, v in obj.items():
        key = f"{prefix}{k}"
        if isinstance(v, dict) and depth < FLATTEN_DEPTH:
            flatten(v, f"{key}.", out, depth + 1)
        elif isinstance(v, list):
            if all(not isinstance(x, (dict, list)) for x in v):
                joined = ", ".join(s for s in map(_scalar, v) if s not in (None, ""))
                if joined:
                    out[key] = joined
            elif v:
                out[key] = json.dumps(v, separators=(",", ":"), ensure_ascii=False)[:2000]
        elif isinstance(v, dict):  # nested deeper than FLATTEN_DEPTH
            out[key] = json.dumps(v, separators=(",", ":"), ensure_ascii=False)[:2000]
        else:
            s = _scalar(v)
            if s not in (None, ""):
                out[key] = s
    return out


def _wrapped(obj) -> tuple[str | None, list | None]:
    if isinstance(obj, dict):
        for k in WRAPPER_KEYS:
            v = obj.get(k)
            if isinstance(v, list) and v and all(isinstance(x, dict) for x in v):
                return k, v
    return None, None


class _JsonStats:
    def __init__(self, stats: dict):
        self.s = stats
        stats.update(layout=None, records=0, unparseable=0, unparseable_at=[],
                     broken_at_byte=None, wrapper=None)

    def bad(self, where: str) -> None:
        self.s["unparseable"] += 1
        if len(self.s["unparseable_at"]) < UNPARSEABLE_SAMPLES:
            self.s["unparseable_at"].append(where)

    def records(self, obj, where: str) -> Iterator[dict]:
        """One decoded value -> the records it holds."""
        key, inner = _wrapped(obj)
        if key:
            self.s["wrapper"] = key
            for x in inner:
                self.s["records"] += 1
                yield flatten(x)
        elif isinstance(obj, dict):
            self.s["records"] += 1
            yield flatten(obj)
        else:
            # Valid JSON, but not a record (a bare string or number).
            self.bad(where)
            yield {"_raw": json.dumps(obj, ensure_ascii=False)[:2000]}


def _lines(head: str, fh) -> Iterator[str]:
    buf = head
    while True:
        *done, buf = buf.split("\n")
        yield from done
        chunk = fh.read(JSON_CHUNK)
        if not chunk:
            break
        buf += chunk
    if buf:
        yield buf


def iter_json(path: Path, progress=None, stats: dict | None = None) -> Iterator[dict]:
    """JSON-lines, a top-level array or a top-level object - see above.
    `stats` (a dict, filled in place) says which layout was read and how many
    records could not be."""
    st = _JsonStats(stats if stats is not None else {})
    report = _reporter(path, progress)
    with open_text(path) as fh:
        head = fh.read(JSON_CHUNK)
        start = head.lstrip()
        if not start:
            return
        if start[0] == "[":
            st.s["layout"] = "array"
            yield from _iter_array(head, fh, st, report)
            return
        first_line = start.split("\n", 1)[0].strip()
        # Pretty-printed only when the first line opens a structure and stops
        # (`{` or `{"value": [`). A first line that is merely broken JSON is
        # a JSON-lines file with one bad line - reading it as one document
        # would pull a 10 GB file into memory to find that out.
        if start[0] == "{" and first_line.endswith(("{", "[")) and not _parses(first_line):
            # A pretty-printed object: the only layout that cannot stream.
            st.s["layout"] = "object"
            text = head + fh.read()
            try:
                obj = json.loads(text)
            except json.JSONDecodeError:
                obj = None
            if obj is not None:
                yield from st.records(obj, "document")
                return
            # Not one document: pretty-printed records one after another
            # (PowerShell's ConvertTo-Json per object does this), decoded as
            # consecutive values. Where that breaks, the rest is read a line
            # at a time, so each bad line is counted rather than the whole
            # file refused.
            st.s["layout"] = "concatenated"
            rest = yield from _iter_concat(text, st)
            if rest:
                # Line numbers stay those of the file, not of the tail.
                first = text.count("\n", 0, len(text) - len(rest)) + 1
                yield from _iter_lines_json(_lines(rest, _Empty()), st, None, fh, first)
            return
        st.s["layout"] = "lines"
        yield from _iter_lines_json(_lines(head, fh), st, report, fh)


class _Empty:
    def read(self, _n=-1):
        return ""


def _parses(text: str) -> bool:
    try:
        json.loads(text)
        return True
    except json.JSONDecodeError:
        return False


def _iter_concat(text: str, st: _JsonStats):
    """Yield records from back-to-back JSON values; return the unread tail
    from the first value that does not decode (empty when all did)."""
    pos, n = 0, 0
    while True:
        while pos < len(text) and text[pos] in " \t\r\n":
            pos += 1
        if pos >= len(text):
            return ""
        try:
            obj, pos2 = _decoder.raw_decode(text, pos)
        except json.JSONDecodeError:
            return text[pos:]
        n += 1
        yield from st.records(obj, f"record {n}")
        pos = pos2


def _iter_lines_json(lines, st: _JsonStats, report, fh, first: int = 1) -> Iterator[dict]:
    for i, line in enumerate(lines, first):
        if report and i % PROGRESS_EVERY == 0:
            report(fh)
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            st.bad(f"line {i}")
            yield {"_raw": line}
            continue
        yield from st.records(obj, f"line {i}")


def _iter_array(head: str, fh, st: _JsonStats, report) -> Iterator[dict]:
    buf = head
    pos = buf.index("[") + 1
    consumed = 0  # characters dropped from the front of buf so far
    eof = False
    n = 0

    def more() -> bool:
        nonlocal buf, eof
        chunk = fh.read(JSON_CHUNK)
        if not chunk:
            eof = True
            return False
        buf += chunk
        return True

    while True:
        # Skip whitespace and the comma between elements.
        while True:
            while pos < len(buf) and buf[pos] in " \t\r\n,":
                pos += 1
            if pos < len(buf) or not more():
                break
        if pos >= len(buf):
            st.s["broken_at_byte"] = consumed + pos  # no closing bracket
            return
        if buf[pos] == "]":
            return
        try:
            obj, end = _decoder.raw_decode(buf, pos)
        except json.JSONDecodeError as exc:
            incomplete = exc.pos >= len(buf) - 1 or exc.msg.startswith("Unterminated")
            if incomplete and not eof and len(buf) - pos < JSON_ELEMENT_MAX and more():
                continue
            # Broken mid-array: nothing after this point can be located
            # reliably, so stop and say where - never pretend it ended.
            st.s["broken_at_byte"] = consumed + exc.pos
            st.bad(f"record {n + 1}")
            yield {"_raw": buf[pos:pos + 2000]}
            return
        n += 1
        yield from st.records(obj, f"record {n}")
        pos = end
        if report and n % PROGRESS_EVERY == 0:
            report(fh)
        if pos > JSON_CHUNK:
            # Keep only the unread tail, so memory is one element, not the file.
            consumed += pos
            buf, pos = buf[pos:], 0


def iter_lines(path: Path, progress=None) -> Iterator[dict]:
    report = _reporter(path, progress)
    with open_text(path) as fh:
        for i, line in enumerate(fh, 1):
            if report and i % PROGRESS_EVERY == 0:
                report(fh)
            line = line.rstrip("\n\r")
            if line.strip():
                yield {"line": line}


def iter_rows(path: Path, kind: str, progress=None, stats: dict | None = None) -> Iterator[dict]:
    """`progress(fraction)` is called every PROGRESS_EVERY rows, if given.
    `stats` is filled by the JSON reader (layout, unparseable records)."""
    if kind == "csv":
        return iter_csv(path, progress)
    if kind == "json":
        return iter_json(path, progress, stats)
    return iter_lines(path, progress)
