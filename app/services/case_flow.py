"""A case as six steps, and where it stands on each (specs/case_flow_design.md).

The order is NIST SP 800-86's forensic process - Collection, Examination,
Analysis, Reporting - with the CSF 2.0 Respond outcomes between Analysis and
Reporting, because SP 800-86 does not cover containment; SP 800-61 Rev. 3 lets
an organisation use the life-cycle model that suits it (p. 6). The AI step is
optional and nothing waits for it.

Every state here is computed from records the case already has - manifest,
custody log, review log, finding registry, analysis cache - so the browser
never derives one. Nothing in this module writes.

Each step names the standards it follows. `source` is the document's name as
docs/standards/SOURCES.md lists it; tests/check_case_flow.py fails when a step
has no source marked read there (the user's rule: every step cites a standard,
and only a standard that was read is relied on).
"""

from . import analysis_jobs, case_views, custody, lifecycle, review, storage

DONE, ACTIVE, BLOCKED, NOT_STARTED, OPTIONAL = "done", "active", "blocked", "not_started", "optional"

STEPS = [
    {"id": "ingest", "title": "Ingest", "standards": [
        {"source": "NIST SP 800-86", "ref": "Collection phase"},
        {"source": "NIST CSWP 29", "ref": "CSF 2.0 RS.AN-07"},
        {"source": "RFC 3227", "ref": "chain of custody"},
        {"source": "FIPS 180-4", "ref": "SHA-256"},
    ]},
    {"id": "triage", "title": "Triage", "standards": [
        {"source": "NIST SP 800-86", "ref": "Examination phase"},
        {"source": "NIST CSWP 29", "ref": "CSF 2.0 DE.AE-02, DE.AE-08, RS.MA-02, RS.MA-03"},
        {"source": "Sigma rules specification", "ref": "2.1.0 level"},
        {"source": "FIRST CSIRT Services Framework", "ref": "2.1, 5.2 Event analysis"},
    ]},
    {"id": "investigate", "title": "Investigate", "standards": [
        {"source": "NIST SP 800-86", "ref": "Analysis phase"},
        {"source": "NIST CSWP 29", "ref": "CSF 2.0 RS.AN-03, RS.AN-06, RS.AN-08, DE.AE-03"},
        {"source": "FIRST CSIRT Services Framework", "ref": "2.1, 5.2 related events and risk scores"},
        {"source": "MITRE ATT&CK", "ref": "techniques and tactics"},
    ]},
    {"id": "respond", "title": "Respond", "standards": [
        {"source": "NIST SP 800-61 Rev. 3", "ref": "CSF 2.0 Respond"},
        {"source": "NIST CSWP 29", "ref": "CSF 2.0 RS.MI-01, RS.MI-02"},
    ]},
    {"id": "analyse", "title": "Analyse", "standards": [
        {"source": "NIST AI 100-1", "ref": "AI RMF 1.0 GOVERN, MANAGE"},
        {"source": "NIST AI 600-1", "ref": "Confabulation, Human-AI Configuration"},
        {"source": "VERIS", "ref": "1.4 classification"},
    ]},
    {"id": "report", "title": "Report", "standards": [
        {"source": "NIST SP 800-86", "ref": "Reporting phase"},
        {"source": "NIST CSWP 29", "ref": "CSF 2.0 RS.CO-02, RS.CO-03"},
        {"source": "OASIS STIX 2.1", "ref": "bundle export"},
        {"source": "MITRE ATT&CK Navigator", "ref": "layer format 4.5"},
    ]},
]
STEP_IDS = [s["id"] for s in STEPS]


def _plural(n: int, word: str) -> str:
    return f"{n} {word}{'' if n == 1 else 's'}"


def build(case_id: str, manifest: dict) -> dict:
    steps = {s["id"]: {**s, "state": NOT_STARTED, "remaining": None, "total": None, "reason": ""}
             for s in STEPS}
    _ingest(case_id, manifest, steps["ingest"])

    if case_views.holds_findings(manifest):
        findings = case_views.findings_view(case_id, manifest)
        unreviewed = [f for f in findings if f["review"]["status"] == review.UNREVIEWED]
        tracked = [f for f in findings if f["lifecycle"]["tracked"]]
        _triage(findings, unreviewed, steps["triage"])
        _investigate(tracked, steps["investigate"])
        _respond(tracked, steps["respond"])
        _analyse(case_id, steps["analyse"])
        _report(findings, unreviewed, steps["report"])
    else:
        steps["analyse"].update(state=OPTIONAL, reason="Available once the case is processed")

    ordered = [steps[i] for i in STEP_IDS]
    recommended = next((s["id"] for s in ordered if s["state"] in (ACTIVE, BLOCKED, NOT_STARTED)),
                       "report")
    return {"case_id": case_id, "steps": ordered, "recommended": recommended}


def _ingest(case_id: str, manifest: dict, step: dict) -> None:
    status = manifest.get("status")
    if status == "ready":
        problem = custody.problem(case_id)
        if problem:
            step.update(state=BLOCKED, reason=f"Evidence cannot be relied on: {problem}")
        elif not manifest.get("evidence"):
            step.update(state=DONE, reason="Processed; no acquisition digest was recorded for this file")
        else:
            step.update(state=DONE, reason=f"{manifest.get('total_rows', 0):,} events read, digest verified")
    elif status == "failed":
        step.update(state=BLOCKED, reason=manifest.get("error") or "Processing failed")
    else:
        pct = (manifest.get("progress") or {}).get("pct")
        step.update(state=ACTIVE, reason=f"Processing ({pct}%)" if pct is not None else f"Status: {status}")


def _triage(findings: list[dict], unreviewed: list[dict], step: dict) -> None:
    high = sum(1 for f in unreviewed if f["lifecycle"]["tracked"])
    step.update(total=len(findings), remaining=len(unreviewed))
    if not findings:
        step.update(state=DONE, reason="No findings to review")
    elif not unreviewed:
        step.update(state=DONE, reason=f"All {_plural(len(findings), 'finding')} reviewed")
    else:
        step.update(state=ACTIVE, reason=f"{len(unreviewed)} of {_plural(len(findings), 'finding')} "
                                         f"not reviewed ({high} high or critical)")


def _investigate(tracked: list[dict], step: dict) -> None:
    # A rejected finding needs no investigation; it waits in Respond until closed.
    live = [f for f in tracked if f["review"]["status"] != review.REJECTED]
    waiting = [f for f in live if f["lifecycle"]["status"] == lifecycle.OPEN]
    step.update(total=len(live), remaining=len(waiting))
    if not tracked:
        step.update(state=DONE, reason="No high or critical findings")
    elif not waiting:
        step.update(state=DONE, reason="Every high or critical finding is assigned and past Open")
    elif all(f["review"]["status"] == review.UNREVIEWED for f in waiting) and len(waiting) == len(live):
        step.update(state=BLOCKED, reason=f"{_plural(len(waiting), 'high or critical finding')} "
                                          "not triaged yet")
    else:
        step.update(state=ACTIVE, reason=f"{len(waiting)} of {len(live)} still Open")


def _respond(tracked: list[dict], step: dict) -> None:
    pending = [f for f in tracked if f["lifecycle"]["status"] != lifecycle.RESOLVED]
    step.update(total=len(tracked), remaining=len(pending))
    if not tracked:
        step.update(state=DONE, reason="No high or critical findings")
    elif not pending:
        step.update(state=DONE, reason=f"All {_plural(len(tracked), 'finding')} resolved")
    else:
        rejected = sum(1 for f in pending if f["review"]["status"] == review.REJECTED)
        note = f", {rejected} rejected but not closed" if rejected else ""
        started = any(f["lifecycle"]["status"] != lifecycle.OPEN for f in tracked)
        step.update(state=ACTIVE if started or rejected else NOT_STARTED,
                    reason=f"{len(pending)} of {len(tracked)} not resolved{note}")


def _analyse(case_id: str, step: dict) -> None:
    job = storage.load_analysis_job(case_id)
    if analysis_jobs.job_running(job):
        step.update(state=ACTIVE, reason="AI analysis running")
    elif storage.analysis_path(case_id).exists():
        step.update(state=DONE, reason="AI narrative available")
    elif job and job.get("status") == "failed":
        step.update(state=OPTIONAL, reason=f"Last run failed: {job.get('error') or 'unknown cause'}")
    else:
        step.update(state=OPTIONAL, reason="Not run - optional, no other step waits for it")


def _report(findings: list[dict], unreviewed: list[dict], step: dict) -> None:
    step.update(total=len(findings), remaining=len(unreviewed))
    if not findings:
        step.update(state=ACTIVE, reason="No findings - nothing to report beyond the exports")
    elif unreviewed:
        step.update(state=BLOCKED, reason=f"Gate closed: {len(unreviewed)} "
                                          f"{'finding' if len(unreviewed) == 1 else 'findings'} not reviewed")
    else:
        step.update(state=ACTIVE, reason="Gate open - exports available; the final report is not built yet")
