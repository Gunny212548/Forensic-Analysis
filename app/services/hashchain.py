"""Append-only JSON-lines logs whose entries are hash-chained.

Used by the chain of custody (custody.py) and the analyst review log
(review.py) - the two audit trails ISO/IEC 27037 / RFC 3227 and
ISO/IEC 27001 A.8.15 ask to be protected against tampering.

Each entry carries `seq` (its line number), `prev` (the previous entry's
`hash`) and `hash` (SHA-256 of the entry's canonical JSON without `hash`).
Editing, deleting or reordering any line breaks every hash after it, and
`verify()` names the first broken line.

**Lines written before chaining existed** (the review log predates it) are
*sealed*, not rewritten: the first chained entry's `prev` is
`seal:<SHA-256 of every byte before it>`. From then on those lines cannot
change undetected either; nothing can prove what happened to them *before*
the seal, and `verify()` reports how many there are.

What this does not do: anyone with write access to the file can recompute
the whole chain. Only a digest kept elsewhere (or an external timestamp)
would stop that.
"""

import hashlib
import json
import threading
from datetime import datetime, timezone
from pathlib import Path

GENESIS = "0" * 64
SEAL = "seal:"
_lock = threading.Lock()


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def digest(entry: dict) -> str:
    body = {k: v for k, v in entry.items() if k != "hash"}
    return hashlib.sha256(
        json.dumps(body, sort_keys=True, ensure_ascii=False, default=str).encode()
    ).hexdigest()


def _lines(path: Path) -> list[bytes]:
    """Raw lines, each with its newline, exactly as stored."""
    if not path.exists():
        return []
    return path.read_bytes().splitlines(keepends=True)


def entries(path: Path) -> list[dict]:
    out = []
    for raw in _lines(path):
        line = raw.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue  # a truncated tail must not hide the rest of the history
    return out


def append(path: Path, entry: dict) -> dict:
    """Append one entry (adding `ts` if absent). Never rewrites a line.
    Locked: the chain is read-then-append, and two writers at once would
    both link to the same previous entry. One process-wide lock is enough -
    the app runs one uvicorn worker."""
    with _lock:
        raw = _lines(path)
        # A file whose last line lacks its newline gets one first, and the
        # seal is taken over the bytes as they will then stand - which are
        # exactly the bytes verify() reads back before this entry.
        missing_newline = bool(raw) and not raw[-1].endswith(b"\n")
        if missing_newline:
            raw[-1] += b"\n"
        prior = entries(path)
        last = prior[-1] if prior else None
        if last and last.get("hash"):
            prev = last["hash"]
        elif prior:
            prev = SEAL + hashlib.sha256(b"".join(raw)).hexdigest()
        else:
            prev = GENESIS
        entry = {"ts": now(), **entry}
        entry["seq"] = len(prior) + 1
        entry["prev"] = prev
        entry["hash"] = digest(entry)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "ab") as fh:
            if missing_newline:
                fh.write(b"\n")
            fh.write((json.dumps(entry, ensure_ascii=False, default=str) + "\n").encode())
    return entry


def verify(path: Path) -> dict:
    """{"intact": bool, "problem": str | None, "entries": n,
    "sealed_legacy": number of pre-chain lines sealed by the first link}."""
    raw = _lines(path)
    seen = b""
    prev = None
    legacy = 0
    n = 0
    for line in raw:
        text = line.strip()
        if not text:
            seen += line
            continue
        n += 1
        try:
            e = json.loads(text)
        except json.JSONDecodeError:
            return {"intact": False, "problem": f"entry {n}: not valid JSON",
                    "entries": n, "sealed_legacy": legacy}
        if "hash" not in e:
            if prev is not None:
                return {"intact": False, "problem": f"entry {n}: unchained entry after the chain began",
                        "entries": n, "sealed_legacy": legacy}
            legacy += 1
            seen += line
            continue
        expected = prev if prev is not None else (
            SEAL + hashlib.sha256(seen).hexdigest() if legacy else GENESIS)
        if e.get("seq") != n:
            return {"intact": False, "problem": f"entry {n}: sequence number is {e.get('seq')}",
                    "entries": n, "sealed_legacy": legacy}
        if e.get("prev") != expected:
            what = "the earlier unchained entries were changed" if prev is None and legacy \
                else f"does not follow entry {n - 1}"
            return {"intact": False, "problem": f"entry {n}: {what}",
                    "entries": n, "sealed_legacy": legacy}
        if digest(e) != e["hash"]:
            return {"intact": False, "problem": f"entry {n}: content does not match its hash",
                    "entries": n, "sealed_legacy": legacy}
        prev = e["hash"]
        seen += line
    return {"intact": True, "problem": None, "entries": n, "sealed_legacy": legacy}
