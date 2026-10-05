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


def iter_json(path: Path, progress=None) -> Iterator[dict]:
    """Handles a JSON array, a single object, or JSON-lines. Only JSON-lines
    truly streams; a single giant JSON array has to be parsed whole (the
    format doesn't allow otherwise without a streaming parser dependency)."""
    with open_text(path) as fh:
        text = fh.read().strip()
    if not text:
        return

    if text[0] in "[{":
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            data = None
        if isinstance(data, list):
            for i, obj in enumerate(data, 1):
                if progress and i % PROGRESS_EVERY == 0:
                    progress(i / len(data))
                yield obj if isinstance(obj, dict) else {"_raw": str(obj)}
            return
        if isinstance(data, dict):
            yield data
            return

    lines = text.splitlines()
    for i, line in enumerate(lines, 1):
        if progress and i % PROGRESS_EVERY == 0:
            progress(i / len(lines))
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            yield obj if isinstance(obj, dict) else {"_raw": line}
        except json.JSONDecodeError:
            yield {"_raw": line}


def iter_lines(path: Path, progress=None) -> Iterator[dict]:
    report = _reporter(path, progress)
    with open_text(path) as fh:
        for i, line in enumerate(fh, 1):
            if report and i % PROGRESS_EVERY == 0:
                report(fh)
            line = line.rstrip("\n\r")
            if line.strip():
                yield {"line": line}


def iter_rows(path: Path, kind: str, progress=None) -> Iterator[dict]:
    """`progress(fraction)` is called every PROGRESS_EVERY rows, if given."""
    if kind == "csv":
        return iter_csv(path, progress)
    if kind == "json":
        return iter_json(path, progress)
    return iter_lines(path, progress)
