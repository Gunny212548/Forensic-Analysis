"""Streaming parsers: yield one row at a time from a file on disk.

Everything here is a generator on purpose - the pipeline feeds rows into
DuckDB in batches, so peak memory stays flat regardless of file size
instead of scaling with it (the previous version read the whole file into
a list of dicts, which is what made a 45MB CSV cost hundreds of MB).
"""

import csv
import json
import sys
from collections.abc import Iterator
from pathlib import Path

# Palo Alto exports have very long "Characteristic of app" style columns.
csv.field_size_limit(min(sys.maxsize, 2**31 - 1))


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
    with open(path, "r", encoding="utf-8-sig", errors="replace", newline="") as fh:
        header = fh.readline()
    counts = {d: header.count(d) for d in _DELIMITERS}
    best = max(_DELIMITERS, key=lambda d: counts[d])
    return best if counts[best] else ","


def iter_csv(path: Path) -> Iterator[dict]:
    delimiter = sniff_delimiter(path)
    with open(path, "r", encoding="utf-8-sig", errors="replace", newline="") as fh:
        for row in csv.DictReader(fh, delimiter=delimiter):
            yield {k: v for k, v in row.items() if k and v not in (None, "")}


def iter_json(path: Path) -> Iterator[dict]:
    """Handles a JSON array, a single object, or JSON-lines. Only JSON-lines
    truly streams; a single giant JSON array has to be parsed whole (the
    format doesn't allow otherwise without a streaming parser dependency)."""
    text = path.read_text(encoding="utf-8-sig", errors="replace").strip()
    if not text:
        return

    if text[0] in "[{":
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            data = None
        if isinstance(data, list):
            for obj in data:
                yield obj if isinstance(obj, dict) else {"_raw": str(obj)}
            return
        if isinstance(data, dict):
            yield data
            return

    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            yield obj if isinstance(obj, dict) else {"_raw": line}
        except json.JSONDecodeError:
            yield {"_raw": line}


def iter_lines(path: Path) -> Iterator[dict]:
    with open(path, "r", encoding="utf-8-sig", errors="replace") as fh:
        for line in fh:
            line = line.rstrip("\n\r")
            if line.strip():
                yield {"line": line}


def iter_rows(path: Path, kind: str) -> Iterator[dict]:
    if kind == "csv":
        return iter_csv(path)
    if kind == "json":
        return iter_json(path)
    return iter_lines(path)
