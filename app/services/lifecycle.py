"""Finding lifecycle, aligned with NIST SP 800-61 Rev. 3 (CSF 2.0 outcomes).

  Open           new; the system created it, nobody owns it yet.
                 RS.MA-02 "incident reports are triaged and validated" - waiting.
  Investigating  someone owns it and is working out what happened.
                 RS.AN-03 "analysis is performed to establish what has taken
                 place during an incident and the root cause".
  Contained      the activity was stopped; the actions taken are recorded.
                 RS.MI-01 "incidents are contained".
  Resolved       closed, with a classification and a written summary.
                 RS.MI-02 "incidents are eradicated" for a true positive; for
                 a benign or false positive, the RS.MA-02 validation outcome.

Rules (the requirements, FR-4.1/4.5/4.7/4.8, as recorded in CLAUDE.md):
- Leaving Open needs an assignee. Any account may be one - roles are not
  defined yet (IAI-14).
- Resolving needs an assignee, an analyst review decision on the finding
  (review.py: accept / modify / reject), a classification and a summary.
- A **true positive** must pass through Contained, with the containment
  actions written down. A benign true positive or a false positive may close
  straight from Investigating, and is excluded from MTTC - forcing it
  through Contained would record a containment that never happened.
- MTTC = finding creation -> Contained, over true positives only.
- A Resolved finding can be reopened (back to Investigating) with a note;
  nothing is ever edited, every change is a new entry.

**Which findings enter the workflow** (IAI-42): those at Sigma level high
or critical - the spec's "should trigger an internal alert and requires a
prompt review". Medium and below stay visible at case level ("reviewed
manually on a more frequent basis"). Measured 2026-10-12: the Palo Alto case
goes from 1,516 reviewable groups to 3, the monsoon zip from 1,561 to 12;
the old ">=2 rule families" alternative admitted all 34 groups of the Entra
case (every spray source carries R1000 + R2005), so it is not used - the
Admiralty credibility (confidence.py) now carries corroboration instead.

Every change is one entry in the case's review log, which is hash-chained
(hashchain.py) - one audit trail for review decisions and status changes.
"""

from datetime import datetime

from . import review
from .severity import WEIGHT

OPEN, INVESTIGATING, CONTAINED, RESOLVED = "Open", "Investigating", "Contained", "Resolved"
STATES = (OPEN, INVESTIGATING, CONTAINED, RESOLVED)

CLASSIFICATIONS = {
    "true_positive": "True positive",
    "benign_true_positive": "Benign true positive",
    "false_positive": "False positive",
}

CSF = {
    OPEN: "RS.MA-02 (triage and validation)",
    INVESTIGATING: "RS.AN-03 (incident analysis)",
    CONTAINED: "RS.MI-01 (incidents are contained)",
    RESOLVED: "RS.MI-02 (incidents are eradicated) / RS.MA-02 outcome",
}

ADMIT_LEVEL = WEIGHT["high"]


def tracked(finding: dict) -> bool:
    """Whether a collapsed finding enters the workflow."""
    return (finding.get("lvl") or 0) >= ADMIT_LEVEL


def _parse(ts: str | None):
    try:
        return datetime.fromisoformat(ts) if ts else None
    except ValueError:
        return None


def state(case_id: str) -> dict[str, dict]:
    """Replay the lifecycle entries of the review log per finding key."""
    out: dict[str, dict] = {}
    for e in review.log(case_id):
        if e.get("kind") != "lifecycle":
            continue
        s = out.setdefault(e["finding_key"], {"status": OPEN, "assignee": None, "history": []})
        if e.get("assignee"):
            s["assignee"] = e["assignee"]
        to = e.get("to")
        if to:
            s["status"] = to
            if to == CONTAINED:
                s["contained_at"] = e["ts"]
                s["containment_actions"] = e.get("containment_actions")
            if to == RESOLVED:
                s["resolved_at"] = e["ts"]
                s["classification"] = e.get("classification")
                s["summary"] = e.get("summary")
            if to == INVESTIGATING and e.get("action") == "reopen":
                for k in ("resolved_at", "classification", "summary"):
                    s.pop(k, None)
        s["history"].append({k: e.get(k) for k in
                             ("ts", "action", "from", "to", "actor", "assignee", "note")})
    return out


def apply(case_id: str, finding: dict, current: dict | None, action: str, actor: str,
          body: dict, review_status: str, valid_assignees: set[str]) -> dict:
    """Validate one requested change against the rules above and append it.
    Raises ValueError with the reason a change is refused."""
    s = current or {"status": OPEN, "assignee": None}
    status = s["status"]
    assignee = (body.get("assignee") or "").strip().lower() or s.get("assignee")
    note = (body.get("note") or "").strip()[:2000]
    entry = {"kind": "lifecycle", "finding_key": finding["key"], "action": action,
             "actor": actor, "from": status}

    if body.get("assignee"):
        if assignee not in valid_assignees:
            raise ValueError(f"'{assignee}' is not an account in this system")
        entry["assignee"] = assignee

    if action == "assign":
        if status == RESOLVED:
            raise ValueError("a resolved finding cannot be reassigned - reopen it first")
        if not body.get("assignee"):
            raise ValueError("assign needs an assignee")
        entry["to"] = None
    elif action == "investigate":
        if status != OPEN:
            raise ValueError(f"only an Open finding can start investigation (this one is {status})")
        if not assignee:
            raise ValueError("an Open finding needs an assignee before investigation starts")
        entry["to"] = INVESTIGATING
    elif action == "contain":
        if status != INVESTIGATING:
            raise ValueError(f"only an Investigating finding can be contained (this one is {status})")
        actions = (body.get("containment_actions") or "").strip()
        if not actions:
            raise ValueError("record the containment actions taken")
        entry["to"] = CONTAINED
        entry["containment_actions"] = actions[:4000]
    elif action == "resolve":
        if status not in (INVESTIGATING, CONTAINED):
            raise ValueError(f"only an Investigating or Contained finding can be resolved (this one is {status})")
        if not assignee:
            raise ValueError("a finding needs an assignee to be resolved")
        if review_status == review.UNREVIEWED:
            raise ValueError("review the finding (accept, modify or reject) before resolving it")
        cls = body.get("classification")
        if cls not in CLASSIFICATIONS:
            raise ValueError(f"choose a classification: {', '.join(CLASSIFICATIONS)}")
        if cls == "true_positive" and status != CONTAINED:
            raise ValueError("a true positive must be contained first, with the actions recorded")
        summary = (body.get("summary") or "").strip()
        if not summary:
            raise ValueError("write a summary of what happened and what was done")
        entry.update(to=RESOLVED, classification=cls, summary=summary[:4000])
    elif action == "reopen":
        if status != RESOLVED:
            raise ValueError("only a Resolved finding can be reopened")
        if not note:
            raise ValueError("say why the finding is being reopened")
        entry["to"] = INVESTIGATING
    else:
        raise ValueError(f"unknown action '{action}'")

    if note:
        entry["note"] = note
    return review.append(case_id, entry)


def summary(findings: list[dict], created_at: str | None) -> dict:
    """Counts per status over tracked findings, and MTTC (creation ->
    Contained) over true positives that were contained."""
    counts = {k: 0 for k in STATES}
    durations = []
    created = _parse(created_at)
    for f in findings:
        lc = f.get("lifecycle")
        if not lc or not lc.get("tracked"):
            continue
        counts[lc["status"]] += 1
        contained = _parse(lc.get("contained_at"))
        if lc.get("classification") == "true_positive" and created and contained:
            durations.append((contained - created).total_seconds())
    return {
        "counts": counts,
        "tracked": sum(counts.values()),
        "mttc_seconds": (sum(durations) / len(durations)) if durations else None,
        "mttc_n": len(durations),
        "created_at": created_at,
    }
