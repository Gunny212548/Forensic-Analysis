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
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .. import config
from . import custody, db, hashchain, lifecycle, storage

_lock = threading.Lock()


def _path(company_id: str) -> Path:
    d = storage.customer_dir(company_id) / "findings"
    d.mkdir(parents=True, exist_ok=True)
    return d / "ids.jsonl"


def registry_path(company_id: str) -> Path:
    """Where the registry is, without creating it - for readers and cache stamps."""
    return storage.customer_dir(company_id) / "findings" / "ids.jsonl"


def lookup(case_id: str) -> dict[str, str]:
    """{finding_key: id} for the case; reads only, assigns nothing."""
    company_id = storage.case_company(case_id)
    if not company_id:
        return {}
    path = registry_path(company_id)
    return {e["finding_key"]: e["fd"] for e in hashchain.entries(path)
            if e.get("case_id") == case_id and e.get("action") == "assigned"}


def created(case_id: str) -> dict[str, str]:
    """{finding_key: when the finding was given its id (UTC ISO)} - the moment it
    entered the workflow, as recorded in the hash-chained registry."""
    company_id = storage.case_company(case_id)
    if not company_id:
        return {}
    path = registry_path(company_id)
    return {e["finding_key"]: e["ts"] for e in hashchain.entries(path)
            if e.get("case_id") == case_id and e.get("action") == "assigned" and e.get("ts")}


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
    """The year the case's findings were created, in the GMT+7 the UI shows
    (config.EVENT_TZ_*): the same moment MTTC counts from (custody.created_at).
    An upload a minute after midnight in Bangkok is the new year there, whatever
    UTC says."""
    ts = custody.created_at(case_id, manifest)
    try:
        when = datetime.fromisoformat(ts)
    except (TypeError, ValueError):
        return "0000"
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    return str(when.astimezone(timezone(timedelta(hours=config.EVENT_TZ_OFFSET_HOURS))).year)
