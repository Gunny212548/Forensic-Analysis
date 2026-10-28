"""The narrative's job state and its background map-reduce worker.

Split out of routers/cases.py (ADR-004). The routes still own the HTTP
answers (202 / 404 / 429 ...); this module owns what a job looks like and how
a big case is narrated in batches. The job is a coroutine on the event loop
with its own sidecar file and stale rule - it is not in services/jobs.py.
"""

from datetime import datetime, timezone

from . import analysis, case_views, db, storage


# A queued map-reduce job that stopped being updated for this long is not
# running any more - the container was restarted mid-job, and nothing else
# would ever clear its "running" marker. Every call in the job writes progress,
# and no single call can take anywhere near this long.
JOB_STALE_SECONDS = 15 * 60


def job_running(job: dict | None) -> bool:
    if not job or job.get("status") != "running":
        return False
    try:
        updated = datetime.fromisoformat(job.get("updated_at") or "")
    except ValueError:
        return True
    age = (datetime.now(timezone.utc) - updated).total_seconds()
    return age < JOB_STALE_SECONDS


def job_view(job: dict) -> dict:
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


def sql_context(case_id: str, events: list[dict]) -> tuple[dict, list[dict], dict]:
    """Everything the narrative is built around that is NOT the model's job.

    The attack graph is derived from findings in SQL, not asked of the model -
    exact, complete, and it leaves the whole output budget for the narrative.
    Source profiles tell a habitual user apart from an intruder, and the risk
    ranking answers "where do I look first". All three stay complete for the
    whole case even when the narrative itself has to be batched.
    """
    # The graph and the ranking are those of the confirmed groups only, as on
    # the Attack path step (the user, 2026-10-28).
    confirmed, _ = case_views.decided(case_id)
    graph = db.build_graph(case_id, keys=confirmed)
    ips = list(dict.fromkeys(e["srcip"] for e in events if e.get("srcip")))
    profiles = db.source_profiles(case_id, ips)
    risk = db.risk_scores(case_id, keys=confirmed)
    return graph, profiles, risk


async def run_map_reduce_job(case_id: str, plan: dict) -> None:
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
        graph, profiles, risk = sql_context(case_id, pool)

        result = await analysis.run_map_reduce_analysis(
            case_id, pool, distinct_total, flagged, graph=graph,
            profiles=profiles, risk=risk, plan=plan,
            profiles_for=lambda ips: db.source_profiles(case_id, ips),
            on_progress=progress,
            auto_retry_max_wait=analysis.BACKGROUND_RETRY_MAX_WAIT,
            veris=case_views.veris_line(case_id),
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
