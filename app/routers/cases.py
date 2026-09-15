from fastapi import APIRouter, Body, HTTPException, Query

from .. import config
from ..services import analysis, db, review, storage

router = APIRouter(prefix="/api/cases", tags=["cases"])


@router.get("")
async def list_cases():
    manifests = storage.list_manifests()
    for m in manifests:
        m["has_analysis"] = storage.load_analysis(m["case_id"]) is not None
    return manifests


@router.get("/{case_id}")
async def get_case(case_id: str):
    manifest = storage.load_manifest(case_id)
    if manifest is None:
        raise HTTPException(404, "Case not found")
    return manifest


@router.get("/{case_id}/events")
async def get_case_events(
    case_id: str,
    only_flagged: bool = True,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
):
    manifest = storage.load_manifest(case_id)
    if manifest is None:
        raise HTTPException(404, "Case not found")

    total_rows, flagged = db.counts(case_id)
    if only_flagged:
        events = db.list_findings(case_id, limit, offset)
        total = flagged
    else:
        events = db.list_raw(case_id, limit, offset)
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


@router.get("/{case_id}/findings")
async def get_case_findings(case_id: str):
    """Findings collapsed to the unit an analyst actually reviews, each with
    a computed confidence and its current review status."""
    manifest = storage.load_manifest(case_id)
    if manifest is None:
        raise HTTPException(404, "Case not found")

    findings = db.collapsed_findings(case_id)
    state = review.current(case_id)
    for f in findings:
        r = state.get(f["key"])
        f["review"] = r or {"status": review.UNREVIEWED, "actor": "",
                            "reason_code": "", "note": "", "ts": None}

    counts = review.summary(case_id, [f["key"] for f in findings])
    return {
        "case_id": case_id,
        "findings": findings,
        "count": len(findings),
        "review_summary": counts,
        # FR-5.6: the export gate reads exactly this - nothing may be left
        # Unreviewed when a final report is produced.
        "ready_for_report": counts.get(review.UNREVIEWED, 0) == 0 and bool(findings),
        "reason_codes": review.REASON_CODES,
    }


@router.post("/{case_id}/review")
async def record_review(case_id: str, body: dict = Body(...)):
    """Record one review decision. Appends to the case's audit log; never
    overwrites an earlier decision."""
    manifest = storage.load_manifest(case_id)
    if manifest is None:
        raise HTTPException(404, "Case not found")

    key = (body.get("finding_key") or "").strip()
    if not key:
        raise HTTPException(400, "finding_key is required")
    if key not in {f["key"] for f in db.collapsed_findings(case_id)}:
        raise HTTPException(404, f"No finding '{key}' in this case")

    try:
        entry = review.record_review(
            case_id,
            finding_key=key,
            action=(body.get("action") or "").strip(),
            actor=(body.get("actor") or "").strip(),
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
    return {"case_id": case_id, "entries": review.log(case_id)}


@router.get("/{case_id}/analysis")
async def get_case_analysis(case_id: str):
    manifest = storage.load_manifest(case_id)
    if manifest is None:
        raise HTTPException(404, "Case not found")
    result = storage.load_analysis(case_id)
    if result is None:
        raise HTTPException(404, "No analysis yet for this case - POST /analyze first")
    return result


@router.post("/{case_id}/analyze")
async def analyze_case(case_id: str, force: bool = False):
    manifest = storage.load_manifest(case_id)
    if manifest is None:
        raise HTTPException(404, "Case not found")
    if manifest.get("status") != "ready":
        raise HTTPException(409, f"Case is not ready yet (status: {manifest.get('status')})")

    if not force:
        cached = storage.load_analysis(case_id)
        if cached is not None:
            return cached

    # One SQL query collapses repeats and returns only the most severe
    # distinct findings - a case with 25k findings costs the same as one
    # with 20.
    events = db.top_distinct_findings(case_id, config.MAX_EVENTS_FOR_ANALYSIS)
    distinct_total = db.distinct_finding_count(case_id)
    _, flagged = db.counts(case_id)

    # The attack graph is derived from findings in SQL, not asked of the
    # model - exact, complete, and it leaves the whole output budget for the
    # narrative.
    graph = db.build_graph(case_id)

    # How each source behaved over the whole case - the context that tells a
    # habitual user apart from an intruder. Computed, not guessed.
    ips = list(dict.fromkeys(e["srcip"] for e in events if e.get("srcip")))
    profiles = db.source_profiles(case_id, ips)

    # Which entities carry the most accumulated severity - the answer to
    # "where do I look first" in a case with tens of thousands of findings.
    risk = db.risk_scores(case_id)

    try:
        result = await analysis.run_analysis(
            case_id, events, distinct_total, flagged, graph=graph,
            profiles=profiles, risk=risk,
        )
    except analysis.AnalysisNotConfigured as exc:
        raise HTTPException(501, str(exc))
    except analysis.AnalysisRateLimited as exc:
        headers = {"Retry-After": str(int(exc.retry_after) + 1)} if exc.retry_after else None
        raise HTTPException(429, str(exc), headers=headers)
    except analysis.AnalysisError as exc:
        raise HTTPException(502, str(exc))

    storage.save_analysis(case_id, result)
    return result
