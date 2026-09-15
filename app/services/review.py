"""Analyst review state, stored as an append-only log.

Four requirements land on the same structure, so they share one: review
status per finding, the history of who changed what (FR-2.5), a structured
reason for every rejection (FR-4.6), and an audit trail of case status
changes (FR-7.6). Each is one line appended to `review/{case_id}.jsonl`;
the current state is the replay of that file.

Kept OUTSIDE the case's DuckDB on purpose: re-processing a case drops and
rebuilds that file (`db.drop`), which would silently erase every review
decision an analyst had made.

The unit of review is the *collapsed* finding - one entry per
(rule, source, account) - not the raw row. A single firewall case produced
25,579 finding rows that collapse to 6 groups; asking an analyst to review
rows one at a time is a requirement that cannot be met in practice, while
six decisions take a couple of minutes.
"""

import json
from datetime import datetime, timezone
from pathlib import Path

from .. import config

# Review Status values from the requirements (FR-3 definitions table).
UNREVIEWED = "Unreviewed"
ACCEPTED = "Accepted"
MODIFIED = "Modified"
REJECTED = "Rejected"

# action -> resulting review status
ACTIONS = {
    "accept": ACCEPTED,
    "modify": MODIFIED,
    "reject": REJECTED,
    "unreview": UNREVIEWED,  # undo, so a mis-click is not permanent
}

# FR-4.6: a rejection must carry a structured reason, not free text alone.
REASON_CODES = {
    "insufficient_evidence": "หลักฐานไม่พอ",
    "misinterpretation": "ตีความผิด",
    "better_technique": "มี technique ที่ตรงกว่า",
    "other": "อื่น ๆ",
}


def review_dir() -> Path:
    return Path(config.DATA_DIR) / "review"


def review_path(case_id: str) -> Path:
    return review_dir() / f"{case_id}.jsonl"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def append(case_id: str, entry: dict) -> dict:
    """Append one immutable record. Never rewrites earlier lines."""
    entry = {"ts": _now(), **entry}
    review_dir().mkdir(parents=True, exist_ok=True)
    with open(review_path(case_id), "a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, ensure_ascii=False, default=str) + "\n")
    return entry


def log(case_id: str) -> list[dict]:
    path = review_path(case_id)
    if not path.exists():
        return []
    entries = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                continue  # a truncated tail must not hide the rest of the history
    return entries


def current(case_id: str) -> dict[str, dict]:
    """Replay the log into the current review state per finding."""
    state: dict[str, dict] = {}
    for entry in log(case_id):
        key = entry.get("finding_key")
        action = entry.get("action")
        if not key or action not in ACTIONS:
            continue  # case-status records and anything unknown are not findings
        state[key] = {
            "status": ACTIONS[action],
            "actor": entry.get("actor") or "",
            "reason_code": entry.get("reason_code") or "",
            "note": entry.get("note") or "",
            "ts": entry.get("ts"),
        }
    return state


def record_review(case_id: str, finding_key: str, action: str, actor: str,
                  reason_code: str = "", note: str = "") -> dict:
    if action not in ACTIONS:
        raise ValueError(f"unknown action '{action}' (expected one of {sorted(ACTIONS)})")
    if action == "reject" and reason_code not in REASON_CODES:
        raise ValueError(
            "rejecting a finding requires a reason_code, one of "
            f"{sorted(REASON_CODES)}"
        )
    return append(case_id, {
        "kind": "review",
        "finding_key": finding_key,
        "action": action,
        "status": ACTIONS[action],
        "actor": actor or "unknown",
        "reason_code": reason_code,
        "note": note[:1000],
    })


def summary(case_id: str, keys: list[str]) -> dict[str, int]:
    """Counts per review status over the findings that currently exist.

    Driven by `keys` rather than by the log, so a decision left over from a
    previous run of the rules doesn't count towards a finding that no longer
    exists - which matters because the export gate (FR-5.6) reads this.
    """
    state = current(case_id)
    counts = {UNREVIEWED: 0, ACCEPTED: 0, MODIFIED: 0, REJECTED: 0}
    for key in keys:
        status = state.get(key, {}).get("status", UNREVIEWED)
        counts[status] = counts.get(status, 0) + 1
    return counts
