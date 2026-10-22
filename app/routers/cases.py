import asyncio
import re
from datetime import datetime, timezone

from fastapi import APIRouter, BackgroundTasks, Body, HTTPException, Query, Request
from fastapi.responses import JSONResponse

from .. import config
from ..services import (analysis, analysis_jobs, attack_layer, auth, case_delete, case_flow, case_views, custody,
                        db, authz, investigation, jobs, lifecycle, merge, profiles, provenance, review,
                        stix_export, storage, veris)
from ..services.rules import RULE_ID_PATTERN

router = APIRouter(prefix="/api/cases", tags=["cases"])


def _authorize(request: Request, action: str, company_id: str | None = None) -> None:
    """Ask the authz seam (services/authz.py); a refusal is a 403."""
    try:
        authz.require(request.state.user, action, company_id)
    except authz.Forbidden as exc:
        raise HTTPException(403, str(exc))


def _case_workers() -> list[dict]:
    """The accounts a finding can be assigned to: those who work cases
    (IAI-14; an admin too since the user's decision of 2026-10-22)."""
    return [u for u in sorted(auth.load_users().values(), key=lambda u: u["email"])
            if authz.can(u, authz.REVIEW) and not u.get("disabled")]


@router.get("")
async def list_cases(company_id: str | None = None):
    if company_id is not None and storage.load_company(company_id) is None:
        raise HTTPException(404, "Customer not found")
    manifests = storage.list_manifests(company_id)
    for m in manifests:
        m["has_analysis"] = storage.load_analysis(m["case_id"]) is not None
    return manifests


@router.get("/{case_id}")
async def get_case(case_id: str):
    manifest = storage.load_manifest(case_id)
    if manifest is None:
        raise HTTPException(404, "Case not found")
    return manifest


# Behaviour profiles (profiles.py): kind -> (one, highest-on-a-fact, the facts it ranks).
_PROFILE_KINDS = {
    "source": (profiles.source, profiles.sources_by, profiles.RANKED),
    "account": (profiles.account, profiles.accounts_by, profiles.RANKED_ACCOUNT),
}


@router.get("/{case_id}/profiles/{kind}")
async def list_profiles(
    case_id: str,
    kind: str,
    by: str = Query("fail_max_10m"),
    limit: int = Query(20, ge=1, le=200),
):
    """Source addresses or accounts highest on one profile fact."""
    if storage.load_manifest(case_id) is None:
        raise HTTPException(404, "Case not found")
    if kind not in _PROFILE_KINDS:
        raise HTTPException(404, f"No {kind} profiles - kinds are {sorted(_PROFILE_KINDS)}")
    _, many, ranked = _PROFILE_KINDS[kind]
    if by not in ranked:
        raise HTTPException(422, f"by must be one of {sorted(ranked)}")
    try:
        return {"case_id": case_id, "kind": kind, "by": by, "profiles": many(case_id, by, limit)}
    except LookupError as exc:
        raise HTTPException(409, str(exc))


# :path, so an account name with a "/" in it still reaches the route.
@router.get("/{case_id}/profiles/{kind}/{value:path}")
async def get_profile(case_id: str, kind: str, value: str):
    """One source address's or account's behaviour profile - layer C facts,
    not a verdict."""
    if storage.load_manifest(case_id) is None:
        raise HTTPException(404, "Case not found")
    if kind not in _PROFILE_KINDS:
        raise HTTPException(404, f"No {kind} profiles - kinds are {sorted(_PROFILE_KINDS)}")
    try:
        found = _PROFILE_KINDS[kind][0](case_id, value)
    except LookupError as exc:
        raise HTTPException(409, str(exc))
    if found is None:
        raise HTTPException(404, f"No events for {kind} {value} in this case")
    return found


def _raw_file(case_id: str):
    """The preserved original, whatever its extension (.csv, .log.gz, .zip)."""
    found = sorted(storage.case_dir(case_id, "raw").glob(f"{case_id}.*"))
    return found[0] if found else None


@router.get("/{case_id}/attack-layer")
async def get_attack_layer(case_id: str):
    """The case's techniques as an ATT&CK Navigator layer (format 4.5),
    served as a download (services/attack_layer.py)."""
    manifest = storage.load_manifest(case_id)
    if manifest is None:
        raise HTTPException(404, "Case not found")
    # A failed case may still hold findings from an earlier run - including
    # one refused because its evidence changed (custody.py). Exporting those
    # would hand on findings the tool itself no longer stands behind.
    if manifest.get("status") != "ready":
        raise HTTPException(409, f"Case is {manifest.get('status')}, not ready - nothing to export")
    return JSONResponse(
        attack_layer.build(case_id, manifest),
        headers={"Content-Disposition": f'attachment; filename="{case_id}-attack-layer.json"'},
    )


@router.get("/{case_id}/stix")
async def get_stix(case_id: str):
    """The case as a STIX 2.1 bundle, served as a download
    (services/stix_export.py). Ready cases only, as the layer export."""
    manifest = storage.load_manifest(case_id)
    if manifest is None:
        raise HTTPException(404, "Case not found")
    if manifest.get("status") != "ready":
        raise HTTPException(409, f"Case is {manifest.get('status')}, not ready - nothing to export")
    bundle = stix_export.build(case_id, manifest, case_views.findings_view(case_id, manifest),
                               case_views.created_at(case_id, manifest))
    return JSONResponse(
        bundle,
        headers={"Content-Disposition": f'attachment; filename="{case_id}-stix21.json"'},
    )


@router.get("/{case_id}/veris")
async def get_veris(case_id: str):
    """The case as a VERIS 1.4 incident record (services/veris.py), as a
    download. 409 unless the case is ready and has high/critical findings."""
    manifest = storage.load_manifest(case_id)
    if manifest is None:
        raise HTTPException(404, "Case not found")
    if manifest.get("status") != "ready":
        raise HTTPException(409, f"Case is {manifest.get('status')}, not ready - nothing to export")
    record = veris.build(case_id, manifest, case_views.findings_view(case_id, manifest))
    if record is None:
        raise HTTPException(409, "No high or critical finding - there is no incident to classify")
    return JSONResponse(
        record, headers={"Content-Disposition": f'attachment; filename="{case_id}-veris.json"'})


@router.get("/{case_id}/custody")
async def get_custody(case_id: str):
    """The evidence digest and the full chain-of-custody log, with the log's
    own hash chain checked on every read (custody.py)."""
    manifest = storage.load_manifest(case_id)
    if manifest is None:
        raise HTTPException(404, "Case not found")
    return case_views.custody_view(case_id, manifest)


@router.post("/{case_id}/verify")
async def verify_evidence(case_id: str, request: Request):
    """Re-compute the preserved file's SHA-256 now, on demand, and record the
    check - who asked, when, and whether it matched - in the custody log."""
    manifest = storage.load_manifest(case_id)
    if manifest is None:
        raise HTTPException(404, "Case not found")
    _authorize(request, authz.VERIFY, manifest.get("company_id"))
    raw = _raw_file(case_id)
    if raw is None:
        raise HTTPException(409, "The preserved original file is missing")
    recorded = manifest.get("evidence")
    # Hashing a 10 GB file takes a while; keep it off the event loop.
    ok, actual = await asyncio.to_thread(custody.check, case_id, raw, recorded)
    actor = request.state.user["email"]
    if ok is False:
        custody.record(case_id, "integrity_failed", actor, sha256=actual,
                       expected=recorded["sha256"], purpose="on request")
    else:
        custody.record(case_id, "verified" if ok else "unverified", actor, sha256=actual,
                       purpose="on request",
                       **({} if ok else {"note": "no acquisition digest was recorded for this file"}))
    return {"match": ok, "sha256": actual, **case_views.custody_view(case_id, manifest)}


@router.delete("/{case_id}")
async def delete_case(case_id: str, request: Request):
    """Delete the case and its evidence for good (specs/case_delete.md): admin
    and manager only; refused while it is processed or analysed. The deletion
    is recorded, hash-chained, in the customer's deleted/log.jsonl."""
    manifest = storage.load_manifest(case_id)
    if manifest is None:
        raise HTTPException(404, "Case not found")
    _authorize(request, authz.DELETE_CASE, manifest.get("company_id"))
    try:
        record = await asyncio.to_thread(case_delete.delete, case_id, request.state.user["email"])
    except case_delete.Busy as exc:
        raise HTTPException(409, str(exc))
    except LookupError:
        raise HTTPException(404, "Case not found")
    return {"deleted": case_id, "record": record}


@router.get("/{case_id}/ingest")
async def get_ingest(case_id: str):
    """What the Ingest step shows beyond custody (story 3): the investigation's
    question, each evidence item's provenance and the time settings its last
    run applied, a duplicate upload, and the reproducibility record."""
    manifest = storage.load_manifest(case_id)
    if manifest is None:
        raise HTTPException(404, "Case not found")
    return case_views.ingest_view(case_id, manifest)


@router.put("/{case_id}/question")
async def put_question(case_id: str, request: Request, body: dict = Body(...)):
    """The question of the investigation this case belongs to - its project's,
    or its own when it has no project (investigation.py). Only the fields sent
    change; each change is a hash-chained line."""
    manifest = storage.load_manifest(case_id)
    if manifest is None:
        raise HTTPException(404, "Case not found")
    _authorize(request, authz.QUESTION, manifest.get("company_id"))
    try:
        return investigation.save(case_id, body, request.state.user["email"])
    except ValueError as exc:
        raise HTTPException(400, str(exc))


@router.put("/{case_id}/provenance")
async def put_provenance(case_id: str, request: Request, body: dict = Body(...),
                         item: str | None = Query(None, max_length=512)):
    """One evidence item's provenance (provenance.py); `item` names a zip
    member. A changed zone or clock offset applies on the next re-process,
    which the response says is needed - nothing re-processes on its own."""
    manifest = storage.load_manifest(case_id)
    if manifest is None:
        raise HTTPException(404, "Case not found")
    _authorize(request, authz.PROVENANCE, manifest.get("company_id"))
    try:
        return provenance.save(case_id, item, body, request.state.user["email"])
    except LookupError as exc:
        raise HTTPException(404, str(exc))
    except ValueError as exc:
        raise HTTPException(400, str(exc))


@router.post("/{case_id}/reprocess")
async def reprocess(case_id: str, request: Request, body: dict = Body(default={})):
    """Run the pipeline again over the preserved original (ACPO principle 3).
    Review decisions survive: they are keyed by finding, not stored in the
    case DuckDB (gotcha #19)."""
    manifest = storage.load_manifest(case_id)
    if manifest is None:
        raise HTTPException(404, "Case not found")
    _authorize(request, authz.REPROCESS, manifest.get("company_id"))
    if manifest.get("status") in ("queued", "processing"):
        raise HTTPException(409, "The case is already queued or processing")
    raw = _raw_file(case_id)
    if raw is None:
        raise HTTPException(409, "The preserved original file is missing")
    reason = str(body.get("reason") or "").strip()[:500] or "analyst request"
    custody.record(case_id, "reprocess_requested", request.state.user["email"], reason=reason)
    storage.update_status(case_id, "queued")
    try:
        jobs.submit(case_id, raw, manifest["file_kind"])
    except jobs.JobActive as exc:
        raise HTTPException(409, str(exc))
    return storage.load_manifest(case_id)


@router.post("/merge")
async def merge_cases_route(request: Request, body: dict = Body(...)):
    """Concatenate several already-ingested line-log cases into one new case
    and run the normal pipeline over it (rules in services/merge.py)."""
    _authorize(request, authz.MERGE)
    try:
        return await merge.merge_cases(body, request.state.user["email"])
    except merge.MergeRefused as exc:
        raise HTTPException(exc.status, exc.message)




@router.get("/{case_id}/events")
async def get_case_events(
    case_id: str,
    only_flagged: bool = True,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    # "time" for the Timeline step (event time, then row); "row" is file order.
    order: str = Query("row", pattern="^(row|time)$"),
):
    manifest = storage.load_manifest(case_id)
    if manifest is None:
        raise HTTPException(404, "Case not found")

    total_rows, flagged = db.counts(case_id)
    if only_flagged:
        events = db.list_findings(case_id, limit, offset)
        total = flagged
    else:
        events = db.list_raw(case_id, limit, offset, order=order)
        total = total_rows

    return {
        "case_id": case_id,
        "events": events,
        "count": len(events),
        "total": total,
        "total_rows": total_rows,
        "flagged_count": flagged,
        "limit": limit,
        "offset": offset,
    }


@router.get("/{case_id}/findings/events")
async def get_finding_events(
    case_id: str,
    key: str = Query(..., max_length=300, description="finding_key: rid|srcip|username"),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
):
    """The events behind one finding, each with the file it came from: how a
    finding is traced back to its source (FR-4.1). Not the finding's own rows
    only - `total` is how many there are, `rows` is the page asked for."""
    manifest = storage.load_manifest(case_id)
    if manifest is None:
        raise HTTPException(404, "Case not found")
    # A case refused for integrity still lists its findings, so their events
    # must open too - that is how an analyst checks them against the evidence.
    if manifest.get("status") != "ready" and not case_views.integrity_refused(manifest):
        raise HTTPException(409, f"Case is not ready yet (status: {manifest.get('status')})")
    if not re.match(rf"^{RULE_ID_PATTERN}\|", key) or key.count("|") != 2:
        raise HTTPException(400, "key must be a finding key: rid|srcip|username")
    res = await asyncio.to_thread(case_views.finding_sources, case_id, manifest, key, limit, offset)
    if not res["total"]:
        raise HTTPException(404, "No events for this finding in this case")
    return res


@router.get("/{case_id}/findings")
async def get_case_findings(case_id: str):
    """Findings collapsed to the unit an analyst actually reviews, each with
    a computed confidence and its current review status."""
    manifest = storage.load_manifest(case_id)
    if manifest is None:
        raise HTTPException(404, "Case not found")

    findings = case_views.findings_view(case_id, manifest)
    counts = review.summary(case_id, [f["key"] for f in findings])
    return {
        "case_id": case_id,
        "findings": findings,
        "count": len(findings),
        "review_summary": counts,
        "lifecycle_summary": lifecycle.summary(findings, case_views.created_at(case_id, manifest)),
        "classifications": lifecycle.CLASSIFICATIONS,
        "assignees": [{"email": u["email"], "name": u.get("name") or u["email"], "role": u.get("role")}
                      for u in _case_workers()],
        # FR-5.6: the export gate reads exactly this - nothing may be left
        # Unreviewed when a final report is produced.
        "ready_for_report": counts.get(review.UNREVIEWED, 0) == 0 and bool(findings),
        "reason_codes": review.REASON_CODES,
        # Whether the decision history behind these statuses is untampered.
        "review_chain": review.verify(case_id),
    }


@router.get("/{case_id}/flow")
def get_case_flow(case_id: str):
    """The case as six steps and where it stands on each (case_flow.py).
    A plain `def`: it reads the case DuckDB and several logs, so FastAPI runs
    it in its threadpool rather than on the event loop."""
    manifest = storage.load_manifest(case_id)
    if manifest is None:
        raise HTTPException(404, "Case not found")
    return case_flow.build(case_id, manifest)


@router.get("/{case_id}/graph")
def get_case_graph(case_id: str):
    """The attack graph and the risk ranking, straight from the findings in
    SQL - the same two the narrative is built around (analysis_jobs), served
    without it, so the Investigate step never waits for the AI."""
    manifest = storage.load_manifest(case_id)
    if manifest is None:
        raise HTTPException(404, "Case not found")
    if not case_views.holds_findings(manifest):
        raise HTTPException(409, f"Case is not ready yet (status: {manifest.get('status')})")
    return {"graph": db.build_graph(case_id), "risk": db.risk_scores(case_id)}


@router.post("/{case_id}/lifecycle")
async def change_lifecycle(case_id: str, request: Request, body: dict = Body(...)):
    """One status change or assignment on a tracked finding (lifecycle.py).
    The actor is the signed-in account; the rules are enforced here, not
    only by the UI."""
    manifest = storage.load_manifest(case_id)
    if manifest is None:
        raise HTTPException(404, "Case not found")
    _authorize(request, authz.LIFECYCLE, manifest.get("company_id"))
    # The key exactly as sent: a user name can end in a space (a Check Point
    # src_user_name did), and a stripped key then matches no finding.
    key = body.get("finding_key") or ""
    finding = next((f for f in db.collapsed_findings(case_id) if f["key"] == key), None)
    if finding is None:
        raise HTTPException(404, "Finding not found in this case")
    if not lifecycle.tracked(finding):
        raise HTTPException(400, "This finding is below the workflow threshold (high) and has no lifecycle")
    current = lifecycle.state(case_id).get(key)
    action = body.get("action") or ""
    # Which change this role may make on this finding (an analyst: their own, IAI-14).
    try:
        authz.require_lifecycle(request.state.user, action, current, body, manifest.get("company_id"))
    except authz.Forbidden as exc:
        raise HTTPException(403, str(exc))
    review_status = (review.current(case_id).get(key) or {}).get("status", review.UNREVIEWED)
    try:
        entry = lifecycle.apply(
            case_id, finding, current, action,
            request.state.user["email"], body, review_status, {u["email"] for u in _case_workers()},
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    return {"entry": entry, "lifecycle": lifecycle.state(case_id).get(key)}


@router.post("/{case_id}/review")
async def record_review(case_id: str, request: Request, body: dict = Body(...)):
    """Record one review decision. Appends to the case's audit log; never
    overwrites an earlier decision.

    The actor is the signed-in account, not whatever the body says: an audit
    log whose author the client picks is not an audit log (FR-7.6)."""
    manifest = storage.load_manifest(case_id)
    if manifest is None:
        raise HTTPException(404, "Case not found")
    _authorize(request, authz.REVIEW, manifest.get("company_id"))

    key = body.get("finding_key") or ""  # as sent, never stripped (see the lifecycle route)
    if not isinstance(key, str) or not key.strip():
        raise HTTPException(400, "finding_key is required")
    if key not in {f["key"] for f in db.collapsed_findings(case_id)}:
        raise HTTPException(404, f"No finding '{key}' in this case")

    try:
        entry = review.record_review(
            case_id,
            finding_key=key,
            action=(body.get("action") or "").strip(),
            actor=request.state.user["email"],
            reason_code=(body.get("reason_code") or "").strip(),
            note=body.get("note") or "",
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    return entry


@router.get("/{case_id}/review-log")
async def get_review_log(case_id: str):
    """The full decision history for this case, oldest first (audit trail)."""
    if storage.load_manifest(case_id) is None:
        raise HTTPException(404, "Case not found")
    return {"case_id": case_id, "entries": review.log(case_id), "chain": review.verify(case_id)}


@router.get("/{case_id}/analysis")
async def get_case_analysis(case_id: str):
    """Poll point for both the fast path and a queued map-reduce job.

    How a caller tells the three states apart:
      404                                  -> never analysed, none queued
      200 + analysis_status "ready"        -> the analysis (as before)
      202 + analysis_status "running"      -> queued, nothing cached yet
      200 + analysis_status "running"      -> queued, an OLDER analysis is
                                              being returned meanwhile
      200 + analysis_status "failed"       -> the queued job gave up; `summary`
                                              carries the reason
    """
    manifest = storage.load_manifest(case_id)
    if manifest is None:
        raise HTTPException(404, "Case not found")

    job = storage.load_analysis_job(case_id)
    result = storage.load_analysis(case_id)

    if result is not None:
        # Every existing key is untouched; only the status fields are added.
        result["analysis_status"] = "running" if analysis_jobs.job_running(job) else "ready"
        if analysis_jobs.job_running(job):
            result["analysis_job"] = job
        return result

    if analysis_jobs.job_running(job):
        return JSONResponse(analysis_jobs.job_view(job), status_code=202)
    if job and job.get("status") == "failed":
        return analysis_jobs.job_view(job)

    raise HTTPException(404, "No analysis yet for this case - POST /analyze first")


@router.post("/{case_id}/analyze")
async def analyze_case(case_id: str, request: Request, background_tasks: BackgroundTasks, force: bool = False):
    """Write the narrative for this case.

    Small cases (evidence that fits one model call) are answered inline, 200,
    exactly as before. A case with more distinct findings than one call can
    hold is queued instead: N batch calls plus one synthesis call at roughly
    one call's worth of output budget per minute is minutes of wall clock, far
    too long to hold an HTTP request open, so it returns 202 immediately and
    the client polls GET .../analysis.
    """
    manifest = storage.load_manifest(case_id)
    if manifest is None:
        raise HTTPException(404, "Case not found")
    _authorize(request, authz.ANALYZE, manifest.get("company_id"))
    if manifest.get("status") != "ready":
        raise HTTPException(409, f"Case is not ready yet (status: {manifest.get('status')})")

    # A job already in flight wins over any new request, force or not: a
    # second one would race the first for the same per-minute token budget and
    # both would crawl.
    job = storage.load_analysis_job(case_id)
    if analysis_jobs.job_running(job):
        return JSONResponse(dict(analysis_jobs.job_view(job), already_running=True), status_code=202)

    if not force:
        cached = storage.load_analysis(case_id)
        if cached is not None:
            cached["analysis_status"] = "ready"
            return cached

    distinct_total = db.distinct_finding_count(case_id)
    plan = analysis.plan_map_reduce(distinct_total)

    if plan["needed"]:
        job = storage.save_analysis_job(case_id, {
            "status": "running",
            "mode": "map_reduce",
            "step": "queued",
            "chunks_total": plan["chunks"],
            "chunks_done": 0,
            "pool_size": plan["pool_size"],
            "distinct_total": distinct_total,
            "map_reduce_capped": plan["capped"],
            "expected_groq_calls": plan["calls"],
            # ~1 call's worth of output budget a minute, so N+1 calls is
            # roughly N+1 minutes. Stated so the caller knows what to expect
            # from polling rather than inferring it from silence.
            "estimated_seconds": plan["calls"] * 60,
            "started_at": datetime.now(timezone.utc).isoformat(),
            "error": None,
        })
        background_tasks.add_task(analysis_jobs.run_map_reduce_job, case_id, plan)
        return JSONResponse(analysis_jobs.job_view(job), status_code=202)

    # Fast path, unchanged: one SQL query collapses repeats and returns only
    # the most severe distinct findings, and one call writes the narrative.
    events = db.top_distinct_findings(case_id, config.MAX_EVENTS_FOR_ANALYSIS)
    _, flagged = db.counts(case_id)
    graph, profiles, risk = analysis_jobs.sql_context(case_id, events)

    try:
        result = await analysis.run_analysis(
            case_id, events, distinct_total, flagged, graph=graph,
            profiles=profiles, risk=risk, veris=case_views.veris_line(case_id),
            escalations=db.escalation_paths(case_id),
        )
    except analysis.AnalysisNotConfigured as exc:
        raise HTTPException(501, str(exc))
    except analysis.AnalysisRateLimited as exc:
        headers = {"Retry-After": str(int(exc.retry_after) + 1)} if exc.retry_after else None
        raise HTTPException(429, str(exc), headers=headers)
    except analysis.AnalysisError as exc:
        raise HTTPException(502, str(exc))

    storage.save_analysis(case_id, result)
    result["analysis_status"] = "ready"
    return result
