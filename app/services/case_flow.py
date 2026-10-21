"""A case as six steps, and where it stands on each (specs/case_flow_design.md).

The steps are revision 3's forensic flow - Ingest, Timeline, Attack events,
Attack timeline, Attack path, Report - in the order of NIST SP 800-86's
process: Collection, Examination, Analysis, Reporting. Respond (containment,
Contained / Resolved, MTTC) is not one of them since the user removed it on
2026-10-20; the separate AI step went with revision 2 - the AI narrative is
part of the Report. Story 1 (specs/story1_case_flow_steps.md) built the steps
from what exists; a step not built in full says which story builds it.

Every state here is computed from records the case already has - manifest,
custody log, review log - so the browser never derives one. Nothing in this
module writes.

Each step names the standards it follows. `source` is the document's name as
docs/standards/SOURCES.md lists it; tests/check_case_flow.py fails when a step
has no source marked read there (the user's rule: every step cites a standard,
and only a standard that was read is relied on).
"""

from . import case_views, custody, review

DONE, ACTIVE, BLOCKED, NOT_STARTED, OPTIONAL = "done", "active", "blocked", "not_started", "optional"

STEPS = [
    {"id": "ingest", "title": "Ingest", "standards": [
        {"source": "NIST SP 800-86", "ref": "Collection phase, 3.1"},
        {"source": "RFC 3227", "ref": "4.1 chain of custody"},
        {"source": "RFC 3227", "ref": "2, 3.2 time zone and clock drift"},
        {"source": "ACPO Good Practice Guide", "ref": "principle 3, 5.5 tasking, 5.10.3 provenance"},
        {"source": "NIST SP 800-92", "ref": "fn 24 out-of-sync sources"},
        {"source": "Sigma rules specification", "ref": "logsource taxonomy appendix 2.1.0"},
        {"source": "NIST CSWP 29", "ref": "CSF 2.0 RS.AN-07"},
        {"source": "FIPS 180-4", "ref": "SHA-256"},
    ]},
    {"id": "timeline", "title": "Timeline", "standards": [
        {"source": "NIST SP 800-86", "ref": "Examination phase, 3.2"},
        {"source": "NIST SP 800-92", "ref": "3.2 log normalization"},
        {"source": "NIST IR 8354", "ref": "4.7.1 time-line tools"},
    ]},
    {"id": "attack-events", "title": "Attack events", "standards": [
        {"source": "NIST SP 800-86", "ref": "6.4.2 validate data based on interpretation"},
        {"source": "FIRST CSIRT Services Framework", "ref": "2.1, 5.2 Event analysis"},
        {"source": "NIST CSWP 29", "ref": "CSF 2.0 RS.MA-02"},
        {"source": "NIST AI 600-1", "ref": "Human-AI Configuration"},
    ]},
    {"id": "attack-timeline", "title": "Attack timeline", "standards": [
        {"source": "NIST SP 800-86", "ref": "Analysis phase, 6.4.3"},
        {"source": "NIST IR 8354", "ref": "4.7 analysis of results"},
    ]},
    {"id": "attack-path", "title": "Attack path", "standards": [
        {"source": "NIST SP 800-86", "ref": "3.3 people, places, items and events"},
        {"source": "MITRE ATT&CK", "ref": "techniques and tactics"},
        {"source": "NIST IR 8354", "ref": "4.7.1 link analysis"},
    ]},
    {"id": "report", "title": "Report", "standards": [
        {"source": "NIST SP 800-86", "ref": "Reporting phase, 3.4"},
        {"source": "ACPO Good Practice Guide", "ref": "6.3-6.5 reporting"},
        {"source": "NIST AI 600-1", "ref": "Confabulation"},
        {"source": "OASIS STIX 2.1", "ref": "bundle export"},
        {"source": "MITRE ATT&CK Navigator", "ref": "layer format 4.5"},
    ]},
]
STEP_IDS = [s["id"] for s in STEPS]
# Revision 1's step ids (triage, investigate, respond, analyse) still open:
# App.jsx redirects them to the step that holds their content now.

CONFIRMED = (review.ACCEPTED, review.MODIFIED)


def _plural(n: int, word: str) -> str:
    return f"{n} {word}{'' if n == 1 else 's'}"


def build(case_id: str, manifest: dict) -> dict:
    steps = {s["id"]: {**s, "state": NOT_STARTED, "remaining": None, "total": None, "reason": "",
                       "warnings": []}
             for s in STEPS}
    _ingest(case_id, manifest, steps["ingest"])

    if manifest.get("status") == "ready":
        steps["timeline"].update(state=DONE, reason=f"{manifest.get('total_rows', 0):,} events in time "
                                                    "order - one evidence item until story 4")
    if case_views.holds_findings(manifest):
        findings = case_views.findings_view(case_id, manifest)
        unreviewed = [f for f in findings if f["review"]["status"] == review.UNREVIEWED]
        confirmed = [f for f in findings if f["review"]["status"] in CONFIRMED]
        _attack_events(findings, unreviewed, steps["attack-events"])
        _attack_timeline(findings, unreviewed, confirmed, steps["attack-timeline"])
        _attack_path(findings, unreviewed, confirmed, steps["attack-path"])
        _report(findings, unreviewed, steps["report"])

    ordered = [steps[i] for i in STEP_IDS]
    recommended = next((s["id"] for s in ordered if s["state"] in (ACTIVE, BLOCKED, NOT_STARTED)),
                       "report")
    return {"case_id": case_id, "steps": ordered, "recommended": recommended}


def identified(manifest: dict) -> list[dict]:
    """What each file of the case was identified as (identify.py) - one entry,
    or one per zip member. Cases processed before IAI-92 have none."""
    maps = [m.get("mapping") or {} for m in manifest.get("members") or []] or [manifest.get("mapping") or {}]
    return [m["logsource"] for m in maps if m.get("logsource")]


def logsource_label(found: dict) -> str:
    sigma = " / ".join(f"{k}: {v}" for k, v in found.get("sigma", {}).items())
    custom = f"custom product: {found['custom']}" if found.get("custom") else ""
    return " · ".join(x for x in (sigma, custom) if x) or "-"


def _ingest(case_id: str, manifest: dict, step: dict) -> None:
    status = manifest.get("status")
    found = identified(manifest)
    read = [f for f in found if f["status"] == "supported"]
    if status == "ready" and found and not read:
        # Kept as evidence, not analysed (Q8): say what it is, or that it is nothing known.
        f = found[0]
        what = (f"Identified as {f['name']} ({logsource_label(f)}) - no reader for it yet"
                if f["status"] == "no_reader" else "Not a log format this tool can identify")
        step.update(state=BLOCKED, reason=f"{what}; the file is kept as evidence and was not analysed")
    elif status == "ready":
        problem = custody.problem(case_id)
        names = ", ".join(dict.fromkeys(f["name"] for f in read))
        skipped = len(found) - len(read)
        prefix = (f"{names} - " if names else "") + (f"{skipped} file(s) not analysed - " if skipped else "")
        if problem:
            step.update(state=BLOCKED, reason=f"Evidence cannot be relied on: {problem}")
        elif not manifest.get("evidence"):
            step.update(state=DONE, reason=f"{prefix}processed; no acquisition digest was recorded for this file")
        else:
            step.update(state=DONE, reason=f"{prefix}{manifest.get('total_rows', 0):,} events read, digest verified")
    elif status == "failed":
        step.update(state=BLOCKED, reason=manifest.get("error") or "Processing failed")
    else:
        pct = (manifest.get("progress") or {}).get("pct")
        step.update(state=ACTIVE, reason=f"Processing ({pct}%)" if pct is not None else f"Status: {status}")
    # Question, provenance, declared time, duplicates (story 3): listed under
    # the step, never a block (D8, D9).
    step["warnings"] = case_views.ingest_warnings(manifest)


def _attack_events(findings: list[dict], unreviewed: list[dict], step: dict) -> None:
    """The rules suggest, the analyst decides - one decision per finding group
    (D7). Done when no suggestion is left undecided (revision 2's gate)."""
    step.update(total=len(findings), remaining=len(unreviewed))
    if not findings:
        step.update(state=DONE, reason="No rule suggested an attack event")
    elif not unreviewed:
        step.update(state=DONE, reason=f"All {_plural(len(findings), 'suggestion')} decided")
    else:
        step.update(state=ACTIVE, reason=f"{len(unreviewed)} of {_plural(len(findings), 'suggestion')} "
                                         "not decided yet")


def _attack_timeline(findings: list[dict], unreviewed: list[dict], confirmed: list[dict],
                     step: dict) -> None:
    step.update(total=len(confirmed))
    if confirmed:
        state = ACTIVE if unreviewed else DONE
        step.update(state=state, reason=f"{_plural(len(confirmed), 'confirmed group')} in time order - "
                                        "gaps and hypotheses come in story 6")
    elif findings and unreviewed:
        step.update(state=NOT_STARTED, reason="Nothing confirmed yet - decide the attack events first")
    else:
        step.update(state=DONE, reason="No attack event was confirmed")


def _attack_path(findings: list[dict], unreviewed: list[dict], confirmed: list[dict],
                 step: dict) -> None:
    """The path is what the confirmed events show, so the step is done only
    once every suggestion is decided - a graph being drawable is not the
    analyst's work being finished. Until story 7 the graph itself still draws
    every suggestion, which the reason says."""
    note = " - the graph below still draws every suggestion until story 7"
    step.update(total=len(confirmed))
    if not findings:
        step.update(state=DONE, reason="No finding - nothing to draw")
    elif unreviewed and not confirmed:
        step.update(state=NOT_STARTED, reason=f"Waits for confirmed attack events{note}")
    elif unreviewed:
        step.update(state=ACTIVE, reason=f"{_plural(len(confirmed), 'confirmed group')}, "
                                         f"{len(unreviewed)} not decided yet{note}")
    elif confirmed:
        step.update(state=DONE, reason=f"Every suggestion decided; {_plural(len(confirmed), 'confirmed group')}"
                                       f"{note}")
    else:
        step.update(state=DONE, reason="No attack event was confirmed - there is no path to draw")


def _report(findings: list[dict], unreviewed: list[dict], step: dict) -> None:
    step.update(total=len(findings), remaining=len(unreviewed))
    if not findings:
        step.update(state=ACTIVE, reason="No findings - nothing to report beyond the exports")
    elif unreviewed:
        step.update(state=BLOCKED, reason=f"Gate closed: {len(unreviewed)} "
                                          f"{'suggestion' if len(unreviewed) == 1 else 'suggestions'} not decided")
    else:
        step.update(state=ACTIVE, reason="Gate open - exports and the AI narrative available; the written "
                                         "report is not built yet")
