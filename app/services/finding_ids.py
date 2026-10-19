"""Finding ids: FD-YYYY-nnnn (FR-4.4).

A finding is a collapsed (rule, source, account) of one case, and only the
ones that enter the workflow (lifecycle.tracked) get an id. The id is handed
out once, when the case finishes processing, and never changes: re-processing
the case reuses it because the finding key is the same.

The numbering is **per customer and per year**, because each customer's
evidence lives in its own store and nothing of it is shared with another
(gotcha #40). Two customers can therefore both have an FD-2026-0001; the
Findings page always shows the customer beside the id.

The registry is an append-only, hash-chained log in the customer's store
(`customers/<id>/findings/ids.jsonl`, hashchain.py) - an id, once printed in a
report, must not be reassigned or quietly rewritten.
"""

import threading
from pathlib import Path

from . import db, hashchain, lifecycle, storage

_lock = threading.Lock()


def _path(company_id: str) -> Path:
    d = storage.customer_dir(company_id) / "findings"
    d.mkdir(parents=True, exist_ok=True)
    return d / "ids.jsonl"


def lookup(case_id: str) -> dict[str, str]:
    """{finding_key: id} for the case; reads only, assigns nothing."""
    company_id = storage.case_company(case_id)
    if not company_id:
        return {}
    path = storage.customer_dir(company_id) / "findings" / "ids.jsonl"
    return {e["finding_key"]: e["fd"] for e in hashchain.entries(path)
            if e.get("case_id") == case_id and e.get("action") == "assigned"}


def ensure(case_id: str, manifest: dict | None = None, findings: list[dict] | None = None) -> dict[str, str]:
    """Give every tracked finding of the case an id (those that have one keep
    it) and return {finding_key: id}. Idempotent; new ids are numbered in the
    order the findings were first seen in the data, then by key, so a re-run
    on the same data allocates the same numbers."""
    company_id = storage.case_company(case_id)
    if not company_id:
        return {}
    manifest = manifest or storage.load_manifest(case_id) or {}
    if findings is None:
        findings = db.collapsed_findings(case_id)
    wanted = sorted((f for f in findings if lifecycle.tracked(f)),
                    key=lambda f: (f.get("ts_min") is None, str(f.get("ts_min") or ""), f["key"]))
    if not wanted:
        return {}
    with _lock:
        path = _path(company_id)
        existing = hashchain.entries(path)
        have = {e["finding_key"]: e["fd"] for e in existing
                if e.get("case_id") == case_id and e.get("action") == "assigned"}
        missing = [f for f in wanted if f["key"] not in have]
        if missing:
            year = _year(case_id, manifest)
            used = [int(e["fd"].rsplit("-", 1)[1]) for e in existing
                    if e.get("action") == "assigned" and e["fd"].startswith(f"FD-{year}-")]
            n = max(used, default=0)
            for f in missing:
                n += 1
                fd = f"FD-{year}-{n:04d}"
                hashchain.append(path, {"action": "assigned", "fd": fd, "case_id": case_id,
                                        "finding_key": f["key"]})
                have[f["key"]] = fd
        return {f["key"]: have[f["key"]] for f in wanted}


def _year(case_id: str, manifest: dict) -> str:
    """The year the case's findings were created: its first `processed` custody
    entry, else the upload time (the same moment MTTC counts from)."""
    from . import custody
    for e in custody.entries(case_id):
        if e.get("action") == "processed" and e.get("ts"):
            return e["ts"][:4]
    return (manifest.get("uploaded_at") or "")[:4] or "0000"
