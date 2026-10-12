"""Evidence integrity and chain of custody for every uploaded file.

What the standards ask, and where each part lives:

- **Integrity** (ISO/IEC 27037:2012, NIST SP 800-86): compute a
  cryptographic digest when evidence is acquired, and re-compute it whenever
  the evidence is used, to show it has not changed. SHA-256 (FIPS 180-4) is
  computed while the upload streams to disk - over exactly the bytes kept in
  `raw/`, compressed ones compressed - and stored on the manifest as
  `evidence`. `pipeline.process_case()` re-computes it before every run and
  refuses to analyse a file whose digest no longer matches.
- **Chain of custody** (RFC 3227 sec. 4.1, ISO/IEC 27037): who handled the
  evidence, when, from where, and what was done to it. One append-only JSON
  line per event in `custody/{case_id}.jsonl` - acquired, derived (merge),
  verified, processed, integrity failure.
- **Tamper evidence** (hashchain.py, shared with the review log): each
  line carries the SHA-256 of the line before it
  (`prev`) and of itself (`hash`), so editing, reordering or deleting an
  earlier line breaks every hash after it. `verify_chain()` checks that. It
  shows *that* the log was altered, not who did it - anyone who can write
  the file can rebuild the whole chain, which only an external timestamp or
  a copy held elsewhere would prevent.

Kept outside the case's DuckDB for the same reason as the review log
(review.py): re-processing drops and rebuilds that file.

Cases uploaded before this existed have no acquisition digest. A digest
recorded later is marked `retroactive`: it proves the file has not changed
*since that moment*, and says nothing about the time before it.
"""

import hashlib
from datetime import datetime, timezone
from pathlib import Path

from .. import config
from . import hashchain

CHUNK = 1024 * 1024

# Shown with the evidence so the analyst can cite them.
STANDARDS = [
    {"id": "ISO/IEC 27037:2012",
     "title": "Guidelines for identification, collection, acquisition and preservation of digital evidence"},
    {"id": "NIST SP 800-86",
     "title": "Guide to Integrating Forensic Techniques into Incident Response"},
    {"id": "RFC 3227", "title": "Guidelines for Evidence Collection and Archiving (chain of custody)"},
    {"id": "FIPS 180-4", "title": "Secure Hash Standard (SHA-256)"},
]


def custody_dir() -> Path:
    return Path(config.DATA_DIR) / "custody"


def custody_path(case_id: str) -> Path:
    return custody_dir() / f"{case_id}.jsonl"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while chunk := fh.read(CHUNK):
            h.update(chunk)
    return h.hexdigest()


def entries(case_id: str) -> list[dict]:
    return hashchain.entries(custody_path(case_id))


def record(case_id: str, action: str, actor: str, **details) -> dict:
    """Append one custody event to the hash-chained log (hashchain.py).
    Never rewrites earlier lines."""
    return hashchain.append(custody_path(case_id), {"action": action, "actor": actor, **details})


def verify_chain(case_id: str) -> tuple[bool, str | None]:
    """(intact, first problem found). An empty log is intact - there is
    nothing to contradict - and the UI says separately that it is empty.
    A custody log is chained from its first line, so any unchained line in
    it is itself a problem."""
    v = hashchain.verify(custody_path(case_id))
    if v["intact"] and v["sealed_legacy"]:
        return False, f"{v['sealed_legacy']} unchained entr{'y' if v['sealed_legacy'] == 1 else 'ies'} " \
                      "before the chain - a custody log is chained from its first line"
    return v["intact"], v["problem"]


def evidence(sha256: str, size: int, actor: str, retroactive: bool = False) -> dict:
    """The manifest's `evidence` block."""
    return {"sha256": sha256, "bytes": size, "algorithm": "SHA-256",
            "recorded_at": _now(), "recorded_by": actor, "retroactive": retroactive}


def check(case_id: str, path: Path, recorded: dict | None) -> tuple[bool | None, str]:
    """Re-compute the digest of the preserved file. Returns (matches, actual
    digest); matches is None when no digest was ever recorded."""
    actual = sha256_file(path)
    if not recorded or not recorded.get("sha256"):
        return None, actual
    return actual == recorded["sha256"], actual
