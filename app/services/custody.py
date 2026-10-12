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
- **Tamper evidence**: each line carries the SHA-256 of the line before it
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
import json
import threading
from datetime import datetime, timezone
from pathlib import Path

from .. import config

CHUNK = 1024 * 1024
GENESIS = "0" * 64
_lock = threading.Lock()

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


def _digest(entry: dict) -> str:
    """Hash of an entry without its own `hash` - canonical JSON, so the same
    entry always hashes the same."""
    body = {k: v for k, v in entry.items() if k != "hash"}
    return hashlib.sha256(
        json.dumps(body, sort_keys=True, ensure_ascii=False, default=str).encode()
    ).hexdigest()


def entries(case_id: str) -> list[dict]:
    path = custody_path(case_id)
    if not path.exists():
        return []
    out = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out


def record(case_id: str, action: str, actor: str, **details) -> dict:
    """Append one custody event. Never rewrites earlier lines.

    Locked because the chain is read-then-append: the pipeline thread and a
    verify request landing together would otherwise both link to the same
    previous entry. One lock per process is enough - the app runs a single
    uvicorn worker."""
    with _lock:
        prior = entries(case_id)
        entry = {
            "seq": len(prior) + 1,
            "ts": _now(),
            "action": action,
            "actor": actor,
            **details,
            "prev": prior[-1]["hash"] if prior else GENESIS,
        }
        entry["hash"] = _digest(entry)
        custody_dir().mkdir(parents=True, exist_ok=True)
        with open(custody_path(case_id), "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, ensure_ascii=False, default=str) + "\n")
    return entry


def verify_chain(case_id: str) -> tuple[bool, str | None]:
    """(intact, first problem found). An empty log is intact - there is
    nothing to contradict - and the UI says separately that it is empty."""
    prev = GENESIS
    for i, e in enumerate(entries(case_id), 1):
        if e.get("seq") != i:
            return False, f"entry {i}: sequence number is {e.get('seq')}, expected {i}"
        if e.get("prev") != prev:
            return False, f"entry {i}: does not follow entry {i - 1}"
        if _digest(e) != e.get("hash"):
            return False, f"entry {i}: content does not match its hash"
        prev = e["hash"]
    return True, None


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
