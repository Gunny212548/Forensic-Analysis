"""Deleting a customer (specs/customer_delete.md, the user's D1-D4 of 2026-10-28).

An administrator or a manager deletes a customer for good, with every case it
holds, its projects and its evidence - the customer's whole store (gotcha #40).
Refused while one of its cases is processed or has an AI narrative running, the
same rule as deleting one case (case_delete.py).

The store holds the customer's own records of what was done to it - the cases
deleted from it, the FD-id registry - so the deletion is recorded outside every
store, in the shared hash-chained `DATA_DIR/deleted/customers.jsonl`: who, when,
the customer, its projects, each case's evidence digest and FD ids, and its
earlier case deletions carried over. Metadata only; no event or evidence.
"""

import secrets
import shutil
from pathlib import Path

from .. import config
from . import case_delete, db, finding_ids, hashchain, review, storage


class Busy(Exception):
    """A case of the customer is being processed or analysed; deleting now would race it."""


def log_path() -> Path:
    return Path(config.DATA_DIR) / "deleted" / "customers.jsonl"


def records() -> list[dict]:
    path = log_path()
    return hashchain.entries(path) if path.exists() else []


def preview(company_id: str) -> dict:
    """What deleting the customer would remove, and the cases that block it now.
    Raises LookupError for a customer that does not exist."""
    company = storage.load_company(company_id)
    if company is None:
        raise LookupError(company_id)
    manifests = storage.list_manifests(company_id)
    suggestions = decisions = fd_ids = 0
    for m in manifests:
        if db.db_path(m["case_id"]).exists():
            suggestions += len(db.collapsed_findings(m["case_id"]))
        decisions += sum(1 for s in review.current(m["case_id"]).values()
                         if s.get("status", review.UNREVIEWED) != review.UNREVIEWED)
        fd_ids += len(finding_ids.lookup(m["case_id"]))
    return {"company_id": company_id, "name": company.get("name"), "cases": len(manifests),
            "projects": len(storage.list_projects(company_id)), "suggestions": suggestions,
            "decisions": decisions, "fd_ids": fd_ids, "busy": case_delete.busy(manifests)}


def delete(company_id: str, actor: str) -> dict:
    """Delete one customer and everything in its store; returns the deletion
    record. Raises Busy, or LookupError for a customer that does not exist."""
    company = storage.load_company(company_id)
    if company is None:
        raise LookupError(company_id)
    manifests = storage.list_manifests(company_id)
    busy = case_delete.busy(manifests)
    if busy:
        raise Busy("wait until these cases are done: "
                   + "; ".join(f"{b['file'] or b['case_id']} ({b['reason']})" for b in busy))

    cases = []
    for m in manifests:
        rows, flagged = db.counts(m["case_id"])
        cases.append({
            "case_id": m["case_id"],
            "original_filename": m.get("original_filename"),
            "project_id": m.get("project_id"),
            "uploaded_at": m.get("uploaded_at"),
            "evidence_sha256": (m.get("evidence") or {}).get("sha256"),
            "size_bytes": m.get("size_bytes"),
            "rows": rows,
            "flagged": flagged,
            "fd_ids": sorted(finding_ids.lookup(m["case_id"]).values()),
        })
    projects = [{"project_id": p.get("project_id"), "name": p.get("name")}
                for p in storage.list_projects(company_id)]
    earlier = case_delete.records(company_id)

    # One atomic rename takes the store out of the customers directory: from here no
    # list, page, upload or MCP call can see the customer, then its files go.
    store = storage.customer_dir(company_id)
    trash = storage.customers_dir() / f".deleting-{company_id}-{secrets.token_hex(4)}"
    store.rename(trash)
    for c in cases:
        storage.forget_case(c["case_id"])
    left_behind = None
    try:
        shutil.rmtree(trash)
    except OSError as exc:
        left_behind = {"path": trash.name, "error": f"{type(exc).__name__}: {exc}"[:300]}

    log = log_path()
    log.parent.mkdir(parents=True, exist_ok=True)
    return hashchain.append(log, {
        "action": "customer_deleted",
        "actor": actor,
        "company_id": company_id,
        "company_name": company.get("name"),
        "created_at": company.get("created_at"),
        "projects": projects,
        "cases": cases,
        "case_deletions_before": earlier,
        **({"left_behind": left_behind} if left_behind else {}),
    })
