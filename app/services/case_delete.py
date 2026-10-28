"""Deleting a case (specs/case_delete.md, the user's Q72-Q75 of 2026-10-22).

An administrator or a manager deletes a case for good: its manifest, DuckDB,
raw evidence, AI analysis, review and lifecycle log, chain of custody and job
file - every file `storage.case_files` names, in the case's own customer store
and nowhere else (gotcha #40). No reason is asked (Q73).

The case's custody log goes with it, so the deletion is recorded *outside* the
case, in its customer's hash-chained `deleted/log.jsonl` (hashchain.py): who,
when, the case, its file and customer, the evidence's SHA-256 at acquisition,
its rows and findings and the FD ids it held. That line is the chain of
custody's last entry - the evidence's disposal - and outlives the case. FD ids
are never handed out again: the registry (finding_ids.py) is append-only and
untouched.

The report kept at deletion (Q74, a PDF - Q76) is not built yet.
"""

from pathlib import Path

from . import analysis_jobs, db, finding_ids, hashchain, storage

BUSY = ("queued", "processing")


class Busy(Exception):
    """The case is being processed or analysed; deleting it now would race it."""


def log_path(company_id: str) -> Path:
    return storage.customer_dir(company_id) / "deleted" / "log.jsonl"


def records(company_id: str) -> list[dict]:
    path = log_path(company_id)
    return hashchain.entries(path) if path.exists() else []


def busy(manifests: list[dict]) -> list[dict]:
    """The cases among `manifests` that cannot be deleted now, and why - the rule
    delete() applies, asked first by whatever deletes many cases at once (a
    customer, a project), so nothing goes unless everything can."""
    out = []
    for m in manifests:
        if m.get("status") in BUSY:
            out.append({"case_id": m["case_id"], "file": m.get("original_filename"),
                        "reason": f"the case is {m.get('status')}"})
        elif analysis_jobs.job_running(storage.load_analysis_job(m["case_id"])):
            out.append({"case_id": m["case_id"], "file": m.get("original_filename"),
                        "reason": "an AI analysis of the case is running"})
    return out


def delete(case_id: str, actor: str) -> dict:
    """Delete one case; returns the deletion record. Raises Busy, or
    LookupError for a case that does not exist."""
    manifest = storage.load_manifest(case_id)
    company_id = storage.case_company(case_id)
    if manifest is None or company_id is None:
        raise LookupError(case_id)
    if manifest.get("status") in BUSY:
        raise Busy(f"the case is {manifest.get('status')} - wait until it is done")
    if analysis_jobs.job_running(storage.load_analysis_job(case_id)):
        raise Busy("an AI analysis of the case is running - wait until it is done")

    total_rows, flagged = db.counts(case_id)
    fd_ids = sorted(finding_ids.lookup(case_id).values())
    store = storage.customer_dir(company_id)
    files = storage.case_files(store, case_id)
    removed = []
    for path in files:
        path.unlink()
        removed.append(path.relative_to(store).as_posix())
    storage.forget_case(case_id)

    evidence = manifest.get("evidence") or {}
    log = log_path(company_id)
    log.parent.mkdir(parents=True, exist_ok=True)
    return hashchain.append(log, {
        "action": "case_deleted",
        "actor": actor,
        "case_id": case_id,
        "original_filename": manifest.get("original_filename"),
        "company_id": company_id,
        "company_name": manifest.get("company_name"),
        "project_id": manifest.get("project_id"),
        "uploaded_at": manifest.get("uploaded_at"),
        "evidence_sha256": evidence.get("sha256"),
        "size_bytes": manifest.get("size_bytes"),
        "rows": total_rows,
        "flagged": flagged,
        "fd_ids": fd_ids,
        "files_removed": removed,
    })
