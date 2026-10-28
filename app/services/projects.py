"""A project is one investigation of one customer (specs/projects.md, the user's
Q110-Q113 of 2026-10-28): the unit an engagement is opened, worked and closed in.

P1: a project is Open or Closed. It closes only when every suggestion in its cases
is decided - the report gate a case already has (gotcha #73), so "Closed" means
nothing is left to answer - and only when every case of it is processed. It may be
reopened at any time. Each change is a line in the project's own hash-chained log
(`projects/<pj-id>.log.jsonl`, beside its question's history). A Closed project takes
no new case (Q111). Manager and admin (Q113, `customer:manage`).
"""

from . import case_views, hashchain, overview, storage
from .severity import level_of


class Refused(Exception):
    """The change cannot be made now; the message says why."""


def cases_of(company_id: str, project_id: str | None) -> list[dict]:
    """The project's cases - with None, the customer's cases in no project."""
    return [m for m in storage.list_manifests(company_id) if m.get("project_id") == project_id]


def _facts(manifests: list[dict]) -> dict:
    """What the project's cases hold: cases, processed, suggestions and those not
    decided, the worst not decided, and the cases that are not processed."""
    out = {"cases": len(manifests), "ready": 0, "reviewable": 0, "unreviewed": 0,
           "open_max_lvl": None, "not_ready": []}
    for m in manifests:
        if m.get("status") == "ready":
            out["ready"] += 1
        else:
            out["not_ready"].append({"case_id": m["case_id"], "file": m.get("original_filename"),
                                     "status": m.get("status")})
        if not case_views.holds_findings(m):
            continue
        f = overview._case_facts(m["case_id"])
        out["reviewable"] += f["findings"]
        out["unreviewed"] += f["unreviewed"]
        lvl = f["open_max_lvl"]
        if lvl is not None and (out["open_max_lvl"] is None or lvl > out["open_max_lvl"]):
            out["open_max_lvl"] = lvl
    return out


def summary(company_id: str) -> list[dict]:
    """The customer's projects with what each holds, Open first, then the newest."""
    rows = []
    for p in storage.list_projects(company_id):
        f = _facts(cases_of(company_id, p["project_id"]))
        rows.append({**{k: p.get(k) for k in ("project_id", "company_id", "name", "created_at", "created_by",
                                               "closed_at", "closed_by")},
                     "status": storage.project_status(p),
                     "cases": f["cases"], "ready": f["ready"], "reviewable": f["reviewable"],
                     "unreviewed": f["unreviewed"], "highest": level_of(f["open_max_lvl"]),
                     "can_close": _close_blocker(f) is None, "close_blocker": _close_blocker(f)})
    rows.sort(key=lambda r: r.get("created_at") or "", reverse=True)
    rows.sort(key=lambda r: r["status"] != storage.PROJECT_OPEN)
    return rows


def _close_blocker(f: dict) -> str | None:
    """Why the project cannot close now, or None (Q110)."""
    if f["not_ready"]:
        n = len(f["not_ready"])
        return f"{n} {'case is' if n == 1 else 'cases are'} not processed ({f['not_ready'][0]['file']}, " \
               f"{f['not_ready'][0]['status']}) - wait, re-process or delete {'it' if n == 1 else 'them'}"
    if f["unreviewed"]:
        n = f["unreviewed"]
        return f"{n} {'suggestion is' if n == 1 else 'suggestions are'} not decided"
    return None


def _change(company_id: str, project_id: str, actor: str, to: str) -> dict:
    with storage.PROJECT_LOCK:
        project = storage.load_project(company_id, project_id)
        if project is None:
            raise LookupError(project_id)
        if storage.project_status(project) == to:
            raise Refused(f"the project is already {to}")
        if to == storage.PROJECT_CLOSED:
            blocker = _close_blocker(_facts(cases_of(company_id, project_id)))
            if blocker:
                raise Refused(f"the project cannot close: {blocker}")
        entry = hashchain.append(storage.project_log_path(company_id, project_id),
                                 {"action": "closed" if to == storage.PROJECT_CLOSED else "reopened",
                                  "actor": actor})
        project["status"] = to
        if to == storage.PROJECT_CLOSED:
            project.update(closed_at=entry["ts"], closed_by=actor)
        else:
            project.pop("closed_at", None)
            project.pop("closed_by", None)
        storage.save_project(project)
        return project


def close(company_id: str, project_id: str, actor: str) -> dict:
    return _change(company_id, project_id, actor, storage.PROJECT_CLOSED)


def reopen(company_id: str, project_id: str, actor: str) -> dict:
    return _change(company_id, project_id, actor, storage.PROJECT_OPEN)


def history(company_id: str, project_id: str) -> list[dict]:
    """The project's status changes, oldest first."""
    path = storage.project_log_path(company_id, project_id)
    if not path.exists():
        return []
    return [e for e in hashchain.entries(path) if e.get("action") in ("closed", "reopened")]

