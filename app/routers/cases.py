import asyncio
import hashlib
from datetime import datetime, timezone

from fastapi import APIRouter, BackgroundTasks, Body, HTTPException, Query, Request
from fastapi.responses import JSONResponse

from .. import config
from ..services import (analysis, attack_layer, auth, confidence, custody, db, lifecycle, review,
                        stix_export, storage, veris)
from .upload import CHUNK, _run_pipeline

router = APIRouter(prefix="/api/cases", tags=["cases"])


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


def _raw_file(case_id: str):
    """The preserved original, whatever its extension (.csv, .log.gz, .zip)."""
    found = sorted(storage.case_dir(case_id, "raw").glob(f"{case_id}.*"))
    return found[0] if found else None


def _custody_view(case_id: str, manifest: dict) -> dict:
    intact, problem = custody.verify_chain(case_id)
    return {
        "evidence": manifest.get("evidence"),
        "standards": custody.STANDARDS,
        "chain_intact": intact,
        "chain_problem": problem,
        "entries": custody.entries(case_id),
    }


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
    bundle = stix_export.build(case_id, manifest, _findings_view(case_id, manifest),
                               _created_at(case_id, manifest))
    return JSONResponse(
        bundle,
        headers={"Content-Disposition": f'attachment; filename="{case_id}-stix21.json"'},
    )


def _veris_line(case_id: str) -> str | None:
    """The computed VERIS classification as one prompt line (veris.py), or
    None - a failure here must never stop the narrative."""
    try:
        manifest = storage.load_manifest(case_id) or {}
        return veris.summary_line(veris.build(case_id, manifest, _findings_view(case_id, manifest)))
    except Exception:  # noqa: BLE001
        return None


@router.get("/{case_id}/veris")
async def get_veris(case_id: str):
    """The case as a VERIS 1.4 incident record (services/veris.py), as a
    download. 409 unless the case is ready and has high/critical findings."""
    manifest = storage.load_manifest(case_id)
    if manifest is None:
        raise HTTPException(404, "Case not found")
    if manifest.get("status") != "ready":
        raise HTTPException(409, f"Case is {manifest.get('status')}, not ready - nothing to export")
    record = veris.build(case_id, manifest, _findings_view(case_id, manifest))
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
    return _custody_view(case_id, manifest)


@router.post("/{case_id}/verify")
async def verify_evidence(case_id: str, request: Request):
    """Re-compute the preserved file's SHA-256 now, on demand, and record the
    check - who asked, when, and whether it matched - in the custody log."""
    manifest = storage.load_manifest(case_id)
    if manifest is None:
        raise HTTPException(404, "Case not found")
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
    return {"match": ok, "sha256": actual, **_custody_view(case_id, manifest)}


def _concat_raw(sources: list, dest) -> tuple[int, str, list[str]]:
    """Append raw log files byte for byte. Returns (bytes written, SHA-256 of
    the merged file, SHA-256 of each source as it was read) - the digests are
    taken in the same pass, so a source is verified on exactly the bytes that
    went into the merge (custody.py).

    Nothing is parsed: syslog/FortiGate lines are self-delimited by newlines
    and carry no cross-file state, so concatenation is the whole merge. Copied
    in chunks because a single source can be ~1GB, and deliberately not bounded
    by config.MAX_UPLOAD_BYTES - that limit guards the streaming HTTP endpoint
    against one oversized POST body, and these bytes are already on disk and
    already ingested.
    """
    size = 0
    tail = b"\n"
    merged = hashlib.sha256()
    per_source = []
    with open(dest, "wb") as out:
        for src in sources:
            # A source not ending in a newline would otherwise glue its last
            # line onto the next file's first line, losing both to the
            # decoder. `tail` starts as a newline so nothing leads the file.
            if tail != b"\n":
                out.write(b"\n")
                merged.update(b"\n")
                size += 1
            h = hashlib.sha256()
            with open(src, "rb") as fh:
                while chunk := fh.read(CHUNK):
                    out.write(chunk)
                    merged.update(chunk)
                    h.update(chunk)
                    size += len(chunk)
                    tail = chunk[-1:]
            per_source.append(h.hexdigest())
    return size, merged.hexdigest(), per_source


@router.post("/merge")
async def merge_cases(request: Request, background_tasks: BackgroundTasks, body: dict = Body(...)):
    """Concatenate several already-ingested line-log cases into one new case
    and run the normal pipeline over the whole thing.

    A log export tool splitting 29 hours of FortiGate traffic into 15
    hourly files meant every rule, risk score and narrative only ever saw one
    hour: sources whose policy-gap violations recurred all day reached no
    per-file threshold, and only a human cross-reading 15 AI reports noticed.
    Merging the raw files and re-running the existing single-case machinery
    buys full-window correlation without a second, cross-case query layer.
    """
    case_ids = body.get("case_ids") or []
    if not isinstance(case_ids, list) or len(case_ids) < 2:
        raise HTTPException(400, "case_ids must be a list of at least 2 case ids")
    if len(set(case_ids)) != len(case_ids):
        # Concatenating a file with itself would double every one of its rows
        # and invent correlations that never happened.
        raise HTTPException(400, "case_ids contains the same case more than once")

    sources, unknown = [], []
    for cid in case_ids:
        manifest = storage.load_manifest(cid)
        (sources if manifest else unknown).append(manifest or cid)
    if unknown:
        raise HTTPException(404, f"Case not found: {', '.join(unknown)}")

    # One customer's evidence is never combined with another's - the merged
    # case lives in exactly one customer's store (storage.py). This used to
    # merge across customers and file the result under the first one.
    owners = {m.get("company_id") for m in sources}
    if len(owners) != 1 or None in owners:
        raise HTTPException(409, "Cases of different customers cannot be merged")
    company_id = owners.pop()
    if body.get("company_id") not in (None, company_id):
        raise HTTPException(409, "company_id must be the customer the cases belong to")

    # Only line logs for now. A CSV would contribute a header row per file
    # (and two log sources' exports need not even share a column set), and JSON
    # is either lines or one array - neither concatenates blindly.
    wrong_kind = [m["case_id"] for m in sources if m.get("file_kind") != "log"]
    if wrong_kind:
        raise HTTPException(
            400,
            "Only file_kind='log' cases can be merged; these are not: "
            + ", ".join(wrong_kind),
        )

    # The raw upload is the audit trail, and it is also the only copy of the
    # bytes - a case whose raw file went missing cannot contribute.
    gone = [m["case_id"] for m in sources
            if not storage.raw_path(m["case_id"], "log").exists()]
    if gone:
        raise HTTPException(409, f"Raw file missing for: {', '.join(gone)}")

    # Chronological, not upload order: the merged file must read as one
    # timeline. Manifests do not carry ts_first, so it comes from the case's
    # own DuckDB; a case that never processed (or parsed no timestamp at all)
    # falls back to upload order and is reported rather than rejected.
    ordered, fallback = [], []
    for m in sources:
        ts_first = m.get("ts_first") or db.ts_range(m["case_id"])[0]
        if not ts_first:
            fallback.append(m["case_id"])
        key = (0, ts_first) if ts_first else (1, m.get("uploaded_at") or "")
        ordered.append((key, ts_first, m))
    ordered.sort(key=lambda entry: entry[0])

    company = storage.load_company(company_id)
    if company is None:
        raise HTTPException(404, "Company not found")
    company_name = company["name"]
    # Sources from one project stay in it; mixed ones give a case in none.
    project_ids = {m.get("project_id") for m in sources}
    project = storage.load_project(company_id, project_ids.pop()) if len(project_ids) == 1 else None

    names = [m.get("original_filename") or m["case_id"] for _, _, m in ordered]
    manifest = storage.create_case(
        original_filename=f"merged({len(ordered)}): " + "+".join(names),
        file_kind="log",
        size_bytes=0,
        note=body.get("note") or f"Merged {len(ordered)} cases in chronological order",
        company_id=company_id,
        company_name=company_name,
        project=project,
        merged_from=[
            {"case_id": m["case_id"], "original_filename": m.get("original_filename"),
             "ts_first": ts_first}
            for _, ts_first, m in ordered
        ],
    )
    case_id = manifest["case_id"]
    dest = storage.raw_path(case_id, "log")

    # Byte-level copy in chunks: syslog lines are self-delimited and carry no
    # cross-file state, so nothing has to be parsed here, and ~1GB sources
    # must not be read into memory. config.MAX_UPLOAD_BYTES deliberately does
    # not apply - it guards the streaming HTTP endpoint against one oversized
    # POST body, and these bytes are already on disk and already ingested.
    # Off the event loop for the same reason the pipeline is: this is minutes
    # of blocking disk IO (13GB for the FortiGate set), and running it inline
    # would stall every other request for the duration.
    size, sha256, source_digests = await asyncio.to_thread(
        _concat_raw, [storage.raw_path(m["case_id"], "log") for _, _, m in ordered], dest
    )

    # A merge is derived evidence: it is only as good as its sources, so each
    # is checked against the digest recorded when it was acquired, and the
    # derivation - which files, at which digests - is the new case's first
    # custody entry.
    altered = [m["case_id"] for (_, _, m), got in zip(ordered, source_digests)
               if (m.get("evidence") or {}).get("sha256") not in (None, got)]
    if altered:
        dest.unlink(missing_ok=True)
        storage.manifest_path(case_id).unlink(missing_ok=True)
        raise HTTPException(
            409, "Evidence integrity check failed - the preserved file no longer matches "
                 f"its acquisition digest for: {', '.join(altered)}")
    actor = request.state.user["email"]
    custody.record(
        case_id, "derived", actor, sha256=sha256, bytes=size, method="concatenation",
        sources=[{"case_id": m["case_id"], "sha256": got,
                  "verified": bool((m.get("evidence") or {}).get("sha256"))}
                 for (_, _, m), got in zip(ordered, source_digests)],
    )
    for (_, _, m), got in zip(ordered, source_digests):
        custody.record(m["case_id"], "used_in_merge", actor, sha256=got, merged_into=case_id)

    fields = {"size_bytes": size, "evidence": custody.evidence(sha256, size, actor)}
    if fallback:
        fields["merge_order_fallback"] = fallback
    storage.update_case(case_id, **fields)
    manifest.update(fields)

    background_tasks.add_task(_run_pipeline, case_id, dest, "log")
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


def _findings_view(case_id: str, manifest: dict) -> list[dict]:
    """Collapsed findings with everything an analyst - or an export - sees
    on them: Admiralty confidence, review decision, lifecycle status."""
    findings = db.collapsed_findings(case_id)
    # Admiralty grading (confidence.py): source reliability needs the
    # manifest's mapping and evidence plus the custody log; cross-source
    # confirmation needs the zip members' row ranges.
    confidence.annotate(
        manifest, custody.entries(case_id), findings,
        db.entity_members(case_id, manifest.get("members") or []),
    )
    state = review.current(case_id)
    flow = lifecycle.state(case_id)
    for f in findings:
        r = state.get(f["key"])
        f["review"] = r or {"status": review.UNREVIEWED, "actor": "",
                            "reason_code": "", "note": "", "ts": None}
        # Only high/critical findings enter the workflow (lifecycle.py); the
        # rest stay visible here without a status.
        if lifecycle.tracked(f):
            lc = flow.get(f["key"]) or {"status": lifecycle.OPEN, "assignee": None, "history": []}
            f["lifecycle"] = {"tracked": True, **lc, "csf": lifecycle.CSF[lc["status"]]}
        else:
            f["lifecycle"] = {"tracked": False}
    return findings


@router.get("/{case_id}/findings")
async def get_case_findings(case_id: str):
    """Findings collapsed to the unit an analyst actually reviews, each with
    a computed confidence and its current review status."""
    manifest = storage.load_manifest(case_id)
    if manifest is None:
        raise HTTPException(404, "Case not found")

    findings = _findings_view(case_id, manifest)
    counts = review.summary(case_id, [f["key"] for f in findings])
    return {
        "case_id": case_id,
        "findings": findings,
        "count": len(findings),
        "review_summary": counts,
        "lifecycle_summary": lifecycle.summary(findings, _created_at(case_id, manifest)),
        "classifications": lifecycle.CLASSIFICATIONS,
        "assignees": [{"email": u["email"], "name": u.get("name") or u["email"]}
                      for u in sorted(auth.load_users().values(), key=lambda u: u["email"])],
        # FR-5.6: the export gate reads exactly this - nothing may be left
        # Unreviewed when a final report is produced.
        "ready_for_report": counts.get(review.UNREVIEWED, 0) == 0 and bool(findings),
        "reason_codes": review.REASON_CODES,
        # Whether the decision history behind these statuses is untampered.
        "review_chain": review.verify(case_id),
    }


def _created_at(case_id: str, manifest: dict) -> str | None:
    """When the case's findings were created - the first time the rule
    engine finished on it (custody `processed`), else the upload time. MTTC
    is measured from here (lifecycle.py); re-processing does not reset it."""
    for e in custody.entries(case_id):
        if e.get("action") == "processed":
            return e.get("ts")
    return manifest.get("uploaded_at")


@router.post("/{case_id}/lifecycle")
async def change_lifecycle(case_id: str, request: Request, body: dict = Body(...)):
    """One status change or assignment on a tracked finding (lifecycle.py).
    The actor is the signed-in account; the rules are enforced here, not
    only by the UI."""
    manifest = storage.load_manifest(case_id)
    if manifest is None:
        raise HTTPException(404, "Case not found")
    key = (body.get("finding_key") or "").strip()
    finding = next((f for f in db.collapsed_findings(case_id) if f["key"] == key), None)
    if finding is None:
        raise HTTPException(404, "Finding not found in this case")
    if not lifecycle.tracked(finding):
        raise HTTPException(400, "This finding is below the workflow threshold (high) and has no lifecycle")
    review_status = (review.current(case_id).get(key) or {}).get("status", review.UNREVIEWED)
    try:
        entry = lifecycle.apply(
            case_id, finding, lifecycle.state(case_id).get(key), body.get("action") or "",
            request.state.user["email"], body, review_status, set(auth.load_users()),
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


# A queued map-reduce job that stopped being updated for this long is not
# running any more - the container was restarted mid-job, and nothing else
# would ever clear its "running" marker. Every call in the job writes progress,
# and no single call can take anywhere near this long.
JOB_STALE_SECONDS = 15 * 60


def _job_running(job: dict | None) -> bool:
    if not job or job.get("status") != "running":
        return False
    try:
        updated = datetime.fromisoformat(job.get("updated_at") or "")
    except ValueError:
        return True
    age = (datetime.now(timezone.utc) - updated).total_seconds()
    return age < JOB_STALE_SECONDS


def _job_view(job: dict) -> dict:
    """The polling payload. Keys the frontend already renders (summary,
    attack_chain, timeline, recommendations, graph) are present and empty so
    an in-progress response cannot make the existing UI throw; `summary`
    carries the progress text rather than a narrative."""
    done, total = job.get("chunks_done") or 0, job.get("chunks_total") or 0
    return {
        "case_id": job.get("case_id"),
        "analysis_status": job.get("status"),
        "analysis_job": job,
        "summary": job.get("error") or (
            f"Analysis in progress: {job.get('step') or 'queued'} phase, "
            f"{done} of {total + 1} model calls done. This case is too large "
            f"for a single call, so it is narrated in batches (about a minute "
            f"per call); poll GET /api/cases/{job.get('case_id')}/analysis."
        ),
        "attack_chain": [],
        "recommendations": [],
        "timeline": [],
        "graph": None,
    }


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
        result["analysis_status"] = "running" if _job_running(job) else "ready"
        if _job_running(job):
            result["analysis_job"] = job
        return result

    if _job_running(job):
        return JSONResponse(_job_view(job), status_code=202)
    if job and job.get("status") == "failed":
        return _job_view(job)

    raise HTTPException(404, "No analysis yet for this case - POST /analyze first")


def _sql_context(case_id: str, events: list[dict]) -> tuple[dict, list[dict], dict]:
    """Everything the narrative is built around that is NOT the model's job.

    The attack graph is derived from findings in SQL, not asked of the model -
    exact, complete, and it leaves the whole output budget for the narrative.
    Source profiles tell a habitual user apart from an intruder, and the risk
    ranking answers "where do I look first". All three stay complete for the
    whole case even when the narrative itself has to be batched.
    """
    graph = db.build_graph(case_id)
    ips = list(dict.fromkeys(e["srcip"] for e in events if e.get("srcip")))
    profiles = db.source_profiles(case_id, ips)
    risk = db.risk_scores(case_id)
    return graph, profiles, risk


async def _run_map_reduce_job(case_id: str, plan: dict) -> None:
    """Background worker: N map calls + 1 reduce, paced against the OTPM
    budget. Mirrors _run_pipeline - the client polls instead of waiting."""

    def progress(step: str, index: int, total: int) -> None:
        storage.update_analysis_job(
            case_id, step=step,
            chunks_done=index - 1 if step == "map" else total,
        )

    try:
        # Ranked candidates first, then a pool that spans the rules that
        # fired: the plain top-N of a huge case is one rule repeated N times,
        # which makes every batch say the same thing.
        candidates = db.top_distinct_findings(
            case_id, plan["pool_size"] * analysis.POOL_CANDIDATE_FACTOR
        )
        pool = analysis.diversify_pool(candidates, plan["pool_size"])
        distinct_total = db.distinct_finding_count(case_id)
        _, flagged = db.counts(case_id)
        graph, profiles, risk = _sql_context(case_id, pool)

        result = await analysis.run_map_reduce_analysis(
            case_id, pool, distinct_total, flagged, graph=graph,
            profiles=profiles, risk=risk, plan=plan,
            profiles_for=lambda ips: db.source_profiles(case_id, ips),
            on_progress=progress,
            auto_retry_max_wait=analysis.BACKGROUND_RETRY_MAX_WAIT,
            veris=_veris_line(case_id),
            escalations=db.escalation_paths(case_id),
        )
    except Exception as exc:  # noqa: BLE001 - the job owns its own failure
        storage.update_analysis_job(
            case_id, status="failed", error=f"{type(exc).__name__}: {exc}"[:500],
            finished_at=datetime.now(timezone.utc).isoformat(),
        )
        return

    storage.save_analysis(case_id, result)
    storage.update_analysis_job(
        case_id, status="done", chunks_done=plan["chunks"], step="done",
        finished_at=datetime.now(timezone.utc).isoformat(),
        groq_calls=result.get("_meta", {}).get("groq_calls"),
    )


@router.post("/{case_id}/analyze")
async def analyze_case(case_id: str, background_tasks: BackgroundTasks, force: bool = False):
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
    if manifest.get("status") != "ready":
        raise HTTPException(409, f"Case is not ready yet (status: {manifest.get('status')})")

    # A job already in flight wins over any new request, force or not: a
    # second one would race the first for the same per-minute token budget and
    # both would crawl.
    job = storage.load_analysis_job(case_id)
    if _job_running(job):
        return JSONResponse(dict(_job_view(job), already_running=True), status_code=202)

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
        background_tasks.add_task(_run_map_reduce_job, case_id, plan)
        return JSONResponse(_job_view(job), status_code=202)

    # Fast path, unchanged: one SQL query collapses repeats and returns only
    # the most severe distinct findings, and one call writes the narrative.
    events = db.top_distinct_findings(case_id, config.MAX_EVENTS_FOR_ANALYSIS)
    _, flagged = db.counts(case_id)
    graph, profiles, risk = _sql_context(case_id, events)

    try:
        result = await analysis.run_analysis(
            case_id, events, distinct_total, flagged, graph=graph,
            profiles=profiles, risk=risk, veris=_veris_line(case_id),
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
