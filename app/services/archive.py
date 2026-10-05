"""Compressed uploads (FR-2.3): .gz streamed, .zip unpacked into ONE case.

Kept apart from the pipeline because two different moments need it: the
upload request (FR-2.2's 10 GB limit is measured after decompression, so the
decompressed size has to be known before the upload is accepted) and the
ingest itself.

- A .gz is never extracted. The compressed upload is what lands in raw/ (the
  audit trail keeps the analyst's bytes), DuckDB's read_csv reads .csv.gz
  natively, and the Python decoders open it through gzip.open - both stream.
- A .zip becomes one case even when its members are different formats. Each
  member is ingested into the same raw_events table, one after another, and
  the rules then run once over all of them - so correlation works across
  files, which is the point of handing over several logs as one case.
  Members are written to a temp file one at a time and deleted after; the
  CSV ones need a real path for DuckDB's fast reader, and a CSV inside a zip
  must decode exactly as it would uploaded alone.
"""

import os
import zlib
import zipfile
from dataclasses import dataclass
from pathlib import Path

CHUNK = 1024 * 1024

# Extensions a log member may have. Anything else in a zip (a PDF with the
# ticket, a screenshot, a nested zip) is skipped and listed, not decoded as
# garbage lines.
_LOG_EXTS = {".csv", ".json", ".jsonl", ".ndjson", ".log", ".txt", ""}


def detect(filename: str) -> tuple[str, str | None]:
    """(kind, compression) for an uploaded name.

    kind is what the decoder reads - "csv" | "json" | "log" - or "zip";
    compression is "gz", "zip" or None. "fw.csv.gz" -> ("csv", "gz").
    """
    name = (filename or "").lower()
    if name.endswith(".zip"):
        return "zip", "zip"
    compression = None
    if name.endswith(".gz"):
        compression = "gz"
        name = name[:-3]
    ext = os.path.splitext(name)[1]
    if ext == ".csv":
        return "csv", compression
    if ext in (".json", ".jsonl", ".ndjson"):
        return "json", compression
    return "log", compression


class TooLarge(Exception):
    """Decompressed content went over the limit."""


class GzipCounter:
    """Counts the decompressed size of a gzip stream as it is uploaded,
    without keeping or writing any of it.

    Output is pulled in bounded pieces (max_length), because a gzip bomb
    turns a 1MB chunk into gigabytes and decompress() would otherwise return
    all of it at once. Handles multi-member files (`cat a.gz b.gz`), which
    zcat and gzip.open both read as one stream."""

    def __init__(self, limit: int):
        self.limit = limit
        self.size = 0
        self._d = zlib.decompressobj(16 + zlib.MAX_WBITS)

    def feed(self, data: bytes) -> None:
        while data:
            out = self._d.decompress(data, CHUNK)
            self.size += len(out)
            if self.size > self.limit:
                raise TooLarge(self.size)
            if self._d.unconsumed_tail:
                data = self._d.unconsumed_tail
            elif self._d.eof and self._d.unused_data:
                data = self._d.unused_data
                self._d = zlib.decompressobj(16 + zlib.MAX_WBITS)
            else:
                data = b""

    def finish(self) -> int:
        while True:
            out = self._d.flush(CHUNK)
            if not out:
                break
            self.size += len(out)
        if not self._d.eof:
            raise ValueError("gzip stream is truncated")
        return self.size


@dataclass
class Member:
    name: str          # path inside the zip, for the manifest and the analyst
    kind: str          # csv | json | log
    compression: str | None
    size: int          # declared uncompressed size


def plan_zip(path: Path) -> tuple[list[Member], list[dict]]:
    """Which members of a zip will be ingested, and which skipped and why.
    Reads the central directory only."""
    members, skipped = [], []
    with zipfile.ZipFile(path) as zf:
        for info in zf.infolist():
            name = info.filename
            base = name.rsplit("/", 1)[-1]
            if info.is_dir():
                continue
            if name.startswith("__MACOSX/") or base.startswith("._") or base in (".DS_Store", "Thumbs.db"):
                continue  # OS metadata, not the analyst's files
            if info.flag_bits & 0x1:
                skipped.append({"name": name, "reason": "encrypted"})
                continue
            kind, compression = detect(base)
            if kind == "zip":
                skipped.append({"name": name, "reason": "nested zip"})
                continue
            if compression == "gz":
                # Its decompressed size could not be held to the budget the
                # way a plain member's is, so a .gz inside a zip is listed
                # rather than trusted. Upload it on its own instead.
                skipped.append({"name": name, "reason": "compressed file inside zip"})
                continue
            ext = os.path.splitext(base.lower())[1]
            # Rotated logs ("auth.log.1", "syslog.2") are line logs too.
            if ext not in _LOG_EXTS and not ext[1:].isdigit():
                skipped.append({"name": name, "reason": "not a log file type"})
                continue
            if info.file_size == 0:
                skipped.append({"name": name, "reason": "empty"})
                continue
            members.append(Member(name, kind, compression, info.file_size))
    return members, skipped


def extract_member(path: Path, member: Member, dest: Path, budget: int) -> int:
    """Copy one member out to `dest`, stopping at `budget` bytes whatever the
    zip's directory claims - declared sizes can lie (zip bombs). The member's
    own name is never used as a path, so "../../x" entries cannot escape."""
    written = 0
    with zipfile.ZipFile(path) as zf, zf.open(member.name) as src, open(dest, "wb") as out:
        while chunk := src.read(CHUNK):
            written += len(chunk)
            if written > budget:
                raise TooLarge(written)
            out.write(chunk)
    return written
