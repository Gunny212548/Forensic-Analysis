"""The Findings page: every finding that entered the workflow, across cases (FR-4.4).

Only high and critical findings enter the workflow and have a status
(lifecycle.tracked); the rest stay on their case page. A row here is one such
finding: its id, the rule's name and the host or account, the customer, its
severity and status, the log type, the file it was found in, the assignee and
when the activity was first seen.

Building a row means reading the case's DuckDB, so a case's rows are cached
against the modification time of what they come from - the case database, its
review log (decisions and lifecycle share it) and the customer's id registry.
"""

import threading

from . import areas, case_views, finding_ids, lifecycle, review, storage
from .rules import RULE_LABELS
from .severity import WEIGHT

_cache: dict[str, tuple[tuple, list[dict]]] = {}
_lock = threading.Lock()

STATUS_RANK = {lifecycle.OPEN: 0, lifecycle.INVESTIGATING: 1, lifecycle.CONTAINED: 2,
               lifecycle.RESOLVED: 3}
SEVERITIES = tuple(WEIGHT)


def _mtime(path) -> float:
    try:
        return path.stat().st_mtime
    except OSError:
        return 0.0


def _stamp(case_id: str, company_id: str) -> tuple:
    from . import db
    ids = storage.customer_dir(company_id) / "findings" / "ids.jsonl"
    return (_mtime(db.db_path(case_id)), _mtime(review.review_path(case_id)), _mtime(ids))


def case_rows(manifest: dict) -> list[dict]:
    """The workflow findings of one ready case."""
    case_id, company_id = manifest["case_id"], manifest["company_id"]
    stamp = _stamp(case_id, company_id)
    with _lock:
        hit = _cache.get(case_id)
        if hit and hit[0] == stamp:
            return hit[1]

    log_type = case_views.log_type(manifest)
    rows = []
    for f in case_views.findings_view(case_id, manifest):
        lc = f["lifecycle"]
        if not lc.get("tracked"):
            continue
        rows.append({
            "fd": f["fd"],
            "key": f["key"],
            "case_id": case_id,
            "company_id": company_id,
            "company_name": manifest.get("company_name"),
            "project_name": manifest.get("project_name"),
            "rid": f["rid"],
            "area": areas.AREA_OF.get(f["rid"]),
            "name": RULE_LABELS.get(f["rid"], f["rid"]),
            "descr": f["descr"],
            "host": f["srcip"] or f["username"],
            "srcip": f["srcip"],
            "username": f["username"],
            "level": f["level"],
            "lvl": f["lvl"] or 0,
            "status": lc["status"],
            "assignee": lc.get("assignee"),
            "review": f["review"]["status"],
            "confidence": f["confidence"],
            "log_type": log_type,
            "source_file": case_views.source_file(manifest, f["sample_row_id"]),
            "detected": f["ts_first"],
            "detected_ts": str(f["ts_min"]) if f.get("ts_min") else "",
            "events": f["cnt"],
            "related_count": f["related_count"],
        })
    with _lock:
        _cache[case_id] = (stamp, rows)
    return rows


def _matches(row: dict, q: str) -> bool:
    hay = " ".join(str(row.get(k) or "") for k in
                   ("fd", "name", "rid", "host", "company_name", "source_file", "log_type",
                    "assignee", "case_id")).lower()
    return all(term in hay for term in q.lower().split())


def listing(company_id: str | None = None, status: str | None = None, severity: str | None = None,
            q: str | None = None, limit: int = 100, offset: int = 0,
            area: str | None = None, unassigned: bool = False) -> dict:
    """Workflow findings for one customer, or for every customer. The counts in
    the header describe the customer scope, before the status / severity / text
    filters narrow the table."""
    rows = []
    for m in storage.list_manifests(company_id):
        if m.get("status") == "ready" and m.get("company_id"):
            rows += case_rows(m)

    by_severity = {s: 0 for s in SEVERITIES if WEIGHT[s] >= lifecycle.ADMIT_LEVEL}
    by_status = {s: 0 for s in lifecycle.STATES}
    for r in rows:
        by_severity[r["level"]] = by_severity.get(r["level"], 0) + 1
        by_status[r["status"]] += 1
    open_count = sum(n for s, n in by_status.items() if s != lifecycle.RESOLVED)

    shown = [r for r in rows
             if (not status or r["status"] == status)
             and (not severity or r["level"] == severity)
             and (not area or r["area"] == area)
             and (not unassigned or not r["assignee"])
             and (not q or _matches(r, q))]
    shown.sort(key=lambda r: (r["company_name"] or "", r["fd"] or ""))
    shown.sort(key=lambda r: r["detected_ts"], reverse=True)
    shown.sort(key=lambda r: (-r["lvl"], STATUS_RANK[r["status"]]))

    return {
        "total": len(shown),
        "scope_total": len(rows),
        "open_count": open_count,
        "by_severity": by_severity,
        "by_status": by_status,
        "areas": [{"id": a["id"], "name": a["name"]} for a in areas.AREAS],
        "limit": limit,
        "offset": offset,
        "rows": shown[offset:offset + limit],
    }
