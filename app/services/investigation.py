"""The question an investigation answers, its window and known leads (story 3, I1-I2).

ACPO 5.5: "investigators must supply specific requirements"; SP 800-86 sec. 3.3:
analysis answers "the questions that were the impetus" for the collection; and
the Diamond Model (sec. 8.2) puts it first - "The first step of analysis is to
define the question to be addressed". D8: required before the report is
approved, asked at Ingest, editable at any time.

An investigation is a project (D6, Q33): the question is stored on the project
and every change goes to the project's own hash-chained log
(`projects/<pj-id>.log.jsonl`). A case uploaded without a project is a
one-item investigation, so its question lives on its manifest and its changes
on its custody log. `get` / `save` hide which of the two it is.
"""

import threading
from datetime import datetime

from . import custody, hashchain, storage

FIELDS = ("question", "window_from", "window_to", "addresses", "accounts", "hosts")
LEAD_FIELDS = ("addresses", "accounts", "hosts")
MAX_QUESTION = 2000
MAX_LEADS = 100
MAX_LEAD = 256

# One question is read, changed and written back; two saves at once must not
# drop either change (the app runs one process - gotcha #48).
_lock = threading.Lock()


def _clean(fields: dict) -> dict:
    """Validated values; empty clears. Raises ValueError."""
    out = {}
    for name, value in fields.items():
        if name not in FIELDS:
            raise ValueError(f"unknown field '{name}' - fields are {', '.join(FIELDS)}")
        if name in LEAD_FIELDS:
            values = value if isinstance(value, list) else str(value or "").replace(",", "\n").splitlines()
            leads = list(dict.fromkeys(str(v).strip() for v in values if str(v).strip()))
            if len(leads) > MAX_LEADS:
                raise ValueError(f"{name}: more than {MAX_LEADS} entries")
            if any(len(v) > MAX_LEAD for v in leads):
                raise ValueError(f"{name}: an entry is longer than {MAX_LEAD} characters")
            out[name] = leads or None
        elif name == "question":
            text = str(value or "").strip()
            if len(text) > MAX_QUESTION:
                raise ValueError(f"question is longer than {MAX_QUESTION} characters")
            out[name] = text or None
        else:
            text = str(value or "").strip()
            if text:
                try:
                    datetime.fromisoformat(text)
                except ValueError:
                    raise ValueError(f"{name} must be an ISO 8601 time, e.g. 2026-02-14T00:00") from None
            out[name] = text or None
    if out.get("window_from") and out.get("window_to"):
        try:
            backwards = datetime.fromisoformat(out["window_from"]) > datetime.fromisoformat(out["window_to"])
        except TypeError:  # one with an offset, one without
            raise ValueError("give both window times with an offset, or both without") from None
        if backwards:
            raise ValueError("window_from is after window_to")
    return out


def _where(manifest: dict) -> tuple[str, dict | None]:
    """("project", project) or ("case", None)."""
    pj = manifest.get("project_id")
    if pj:
        project = storage.load_project(manifest["company_id"], pj)
        if project is not None:
            return "project", project
    return "case", None


def get(manifest: dict) -> dict:
    """{"scope": project | case, "question": {...}, "updated_by", "updated_at"}."""
    scope, project = _where(manifest)
    holder = project if scope == "project" else manifest
    q = holder.get("question") or {}
    return {"scope": scope, "project_name": (project or {}).get("name"),
            "question": {k: q.get(k) for k in FIELDS},
            "updated_by": q.get("updated_by"), "updated_at": q.get("updated_at")}


def save(case_id: str, fields: dict, actor: str) -> dict:
    """Change the question of the investigation this case belongs to. Only the
    fields given change; the log line carries old and new values."""
    clean = _clean(fields)
    with _lock:
        return _save(case_id, clean, actor)


def _save(case_id: str, clean: dict, actor: str) -> dict:
    manifest = storage.load_manifest(case_id)
    scope, project = _where(manifest)
    current = dict(((project if scope == "project" else manifest).get("question")) or {})
    changes = {k: [current.get(k), v] for k, v in clean.items() if current.get(k) != v}
    if not changes:
        return get(manifest)
    current.update(clean)
    if scope == "project":
        entry = hashchain.append(storage.project_log_path(project["company_id"], project["project_id"]),
                                 {"action": "question", "actor": actor, "case_id": case_id,
                                  "changes": changes})
        current.update(updated_by=actor, updated_at=entry["ts"])
        project["question"] = {k: v for k, v in current.items() if v is not None}
        storage.save_project(project)
    else:
        entry = custody.record(case_id, "question", actor, changes=changes)
        current.update(updated_by=actor, updated_at=entry["ts"])
        storage.update_case(case_id, question={k: v for k, v in current.items() if v is not None})
    return get(storage.load_manifest(case_id))


def answered(manifest: dict) -> bool:
    return bool(get(manifest)["question"].get("question"))
