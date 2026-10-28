"""A project is one investigation of one customer (specs/projects.md, the user's
Q110-Q113 of 2026-10-28): the unit an engagement is opened, worked and closed in.

P1: a project is Open or Closed. It closes only when every suggestion in its cases
is decided - the report gate a case already has (gotcha #73), so "Closed" means
nothing is left to answer - and only when every case of it is processed. It may be
reopened at any time. Each change is a line in the project's own hash-chained log
(`projects/<pj-id>.log.jsonl`, beside its question's history). A Closed project takes
no new case (Q111). Manager and admin (Q113, `customer:manage`).

P3: a project is renamed (its name is copied onto each case's manifest, so both
change), a case is moved to another project of the same customer - never across
customers (gotcha #40), never into or out of a Closed project, never while it is
processed - and a project is deleted with every case in it, as a customer is
(specs/customer_delete.md); deletion is `customer:delete`.

P4: the picture of the whole investigation, read-only, built from the analyst's
decisions in each case: the attack timeline of every confirmed group of every case,
and the attack graph and risk ranking of its cases joined - a host or an account is
the same node in every case of one customer (one network).
"""

from . import case_delete, case_views, custody, db, hashchain, overview, review, rule_meta, storage
from .severity import level_of

CONFIRMED = (review.ACCEPTED, review.MODIFIED)
GRAPH_EDGES = 24  # the project graph's budget: the most severe edges of all its cases

MAX_NAME = 200


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
    """The project's status changes, renames and moves, oldest first."""
    path = storage.project_log_path(company_id, project_id)
    if not path.exists():
        return []
    return [e for e in hashchain.entries(path)
            if e.get("action") in ("closed", "reopened", "renamed", "case_moved_in", "case_moved_out")]


def _open_project(company_id: str, project_id: str, what: str) -> dict:
    project = storage.load_project(company_id, project_id)
    if project is None:
        raise LookupError(project_id)
    if storage.project_status(project) == storage.PROJECT_CLOSED:
        raise Refused(f"project \"{project['name']}\" is closed - reopen it to {what}")
    return project


def rename(company_id: str, project_id: str, name: str, actor: str) -> dict:
    """A new name for the project, on it and on every case of it. Refused when another
    project of the customer already has that name (names are how upload finds one)."""
    name = (name or "").strip()
    if not name:
        raise ValueError("a project needs a name")
    if len(name) > MAX_NAME:
        raise ValueError(f"a project name is at most {MAX_NAME} characters")
    with storage.PROJECT_LOCK:
        project = storage.load_project(company_id, project_id)
        if project is None:
            raise LookupError(project_id)
        same = storage.find_project_by_name(company_id, name)
        if same is not None and same["project_id"] != project_id:
            raise Refused(f"the customer already has a project named \"{same['name']}\"")
        if project["name"] == name:
            return project
        hashchain.append(storage.project_log_path(company_id, project_id),
                         {"action": "renamed", "actor": actor, "from": project["name"], "to": name})
        project["name"] = name
        storage.save_project(project)
        for m in cases_of(company_id, project_id):
            storage.update_case(m["case_id"], project_name=name)
        return project


def move_case(case_id: str, project_id: str, actor: str) -> dict:
    """Move a case into another project of its customer. Recorded on the case's chain of
    custody and in both projects' logs. Returns the case's manifest."""
    manifest = storage.load_manifest(case_id)
    if manifest is None:
        raise LookupError(case_id)
    company_id = manifest["company_id"]
    if manifest.get("status") in case_delete.BUSY:
        raise Refused(f"the case is {manifest.get('status')} - wait until it is done")
    with storage.PROJECT_LOCK:
        target = _open_project(company_id, project_id, "move a case into it")
        source_id = manifest.get("project_id")
        if source_id == project_id:
            raise Refused(f"the case is already in \"{target['name']}\"")
        source = storage.load_project(company_id, source_id) if source_id else None
        if source is not None and storage.project_status(source) == storage.PROJECT_CLOSED:
            raise Refused(f"project \"{source['name']}\" is closed - reopen it to move a case out of it")
        moved = {"from_project": source_id, "to_project": project_id}
        custody.record(case_id, "moved", actor, **moved,
                       from_name=(source or {}).get("name"), to_name=target["name"])
        if source is not None:
            hashchain.append(storage.project_log_path(company_id, source_id),
                             {"action": "case_moved_out", "actor": actor, "case_id": case_id, **moved})
        hashchain.append(storage.project_log_path(company_id, project_id),
                         {"action": "case_moved_in", "actor": actor, "case_id": case_id, **moved})
        storage.update_case(case_id, project_id=project_id, project_name=target["name"])
    return storage.load_manifest(case_id)


def preview_delete(company_id: str, project_id: str) -> dict:
    """What deleting the project would remove, and the cases that block it now."""
    project = storage.load_project(company_id, project_id)
    if project is None:
        raise LookupError(project_id)
    manifests = cases_of(company_id, project_id)
    f = _facts(manifests)
    return {"project_id": project_id, "name": project["name"], "status": storage.project_status(project),
            "cases": len(manifests), "suggestions": f["reviewable"],
            "decisions": f["reviewable"] - f["unreviewed"], "busy": case_delete.busy(manifests)}


def delete(company_id: str, project_id: str, actor: str) -> dict:
    """Delete the project with every case in it. Each case goes as a deleted case does
    (case_delete.py, a line each in the customer's deleted/log.jsonl), then the project
    and its log, recorded on one more line there that carries the project's log."""
    pre = preview_delete(company_id, project_id)
    if pre["busy"]:
        raise Refused("wait until these cases are done: "
                      + "; ".join(f"{b['file'] or b['case_id']} ({b['reason']})" for b in pre["busy"]))
    with storage.PROJECT_LOCK:
        project = storage.load_project(company_id, project_id)
        if project is None:
            raise LookupError(project_id)
        cases = [case_delete.delete(m["case_id"], actor)["case_id"] for m in cases_of(company_id, project_id)]
        log = storage.project_log_path(company_id, project_id)
        project_log = hashchain.entries(log) if log.exists() else []
        deleted_log = case_delete.log_path(company_id)
        deleted_log.parent.mkdir(parents=True, exist_ok=True)  # a project with no case made none
        record = hashchain.append(deleted_log, {
            "action": "project_deleted", "actor": actor, "company_id": company_id,
            "project_id": project_id, "project_name": project["name"],
            "created_at": project.get("created_at"), "status": storage.project_status(project),
            "question": project.get("question"), "cases": cases, "project_log": project_log,
        })
        storage.project_path(company_id, project_id).unlink(missing_ok=True)
        log.unlink(missing_ok=True)
        return record



def _analysed(company_id: str, project_id: str) -> list[dict]:
    """The project's cases whose findings can be read, oldest upload first."""
    project = storage.load_project(company_id, project_id)
    if project is None:
        raise LookupError(project_id)
    cases = [m for m in cases_of(company_id, project_id) if case_views.holds_findings(m)]
    return sorted(cases, key=lambda m: m.get("uploaded_at") or "")


def timeline(company_id: str, project_id: str) -> dict:
    """Every confirmed group (accepted or modified) of every case of the project, in the
    order its first event happened, each naming its case - the case page's Attack
    timeline, project-wide - and how many suggestions are still not decided."""
    rows, undecided, cases = [], 0, []
    for m in _analysed(company_id, project_id):
        found = case_views.findings_view(m["case_id"], m, assign_ids=False)
        undecided += sum(1 for f in found if f["review"]["status"] == review.UNREVIEWED)
        mine = [{**f, "case_id": m["case_id"], "case_file": m.get("original_filename")}
                for f in found if f["review"]["status"] in CONFIRMED]
        cases.append({"case_id": m["case_id"], "file": m.get("original_filename"), "confirmed": len(mine)})
        rows += mine
    # ts_first is zone-stamped text, so it sorts as written; a group with no time goes last.
    rows.sort(key=lambda f: (f.get("ts_first") or "\uffff", f["case_id"], f["key"]))
    return {"findings": rows, "undecided": undecided, "cases": cases,
            "tactic_order": [{"id": t, "ta": ta, "name": n} for t, ta, n in rule_meta.TACTIC_ORDER]}


def graph(company_id: str, project_id: str) -> dict:
    """The attack graph and the risk ranking of the project's cases joined. An edge
    between the same two entities in several cases is one edge naming each case; a
    risk score is summed over the cases, as the Overview sums it per customer. Drawn
    from the confirmed groups only, and empty while any case of the project has a
    suggestion not decided - as on the case's Attack path step (the user, 2026-10-28)."""
    edges: dict[tuple, dict] = {}
    risk: dict[str, dict] = {}
    cases = _analysed(company_id, project_id)
    decisions = {m["case_id"]: case_views.decided(m["case_id"]) for m in cases}
    undecided = sum(n for _, n in decisions.values())
    confirmed = sum(len(keys) for keys, _ in decisions.values())
    if undecided:
        return {"graph": {"nodes": [], "edges": []}, "risk": {}, "undecided": undecided, "confirmed": confirmed}
    for m in cases:
        keys = decisions[m["case_id"]][0]
        # By id: two cases may carry the same file name (two exports both "log.csv").
        case = {"case_id": m["case_id"], "file": m.get("original_filename")}
        for e in db.build_graph(m["case_id"], keys=keys)["edges"]:
            k = (e["from"], e["to"])
            have = edges.get(k)
            if have is None or e["lvl"] > have["lvl"]:
                merged = {**e, "cases": (have or {}).get("cases", []),
                          "count": e["count"] + ((have or {}).get("count") or 0),
                          "rules": sorted(set(e["rules"]) | set((have or {}).get("rules", [])))}
                edges[k] = merged
            else:
                have["count"] += e["count"]
                have["rules"] = sorted(set(have["rules"]) | set(e["rules"]))
            if case not in edges[k]["cases"]:
                edges[k]["cases"].append(case)
        for role, items in db.risk_scores(m["case_id"], keys=keys).items():
            for i in items:
                r = risk.setdefault(role, {}).setdefault(i["entity"], {
                    "entity": i["entity"], "score": 0, "findings": 0, "max_lvl": 0, "rules": set(), "cases": 0})
                r["score"] += i["score"] or 0
                r["findings"] += i["findings"] or 0
                r["max_lvl"] = max(r["max_lvl"], i["max_lvl"] or 0)
                r["rules"] |= set(i["rules"] or [])
                r["cases"] += 1
    kept = sorted(edges.values(), key=lambda e: (-e["lvl"], -e["count"], e["from"], e["to"]))[:GRAPH_EDGES]
    for e in kept:
        if len(e["cases"]) > 1:
            e["label"] = f"{e['label']} - in {len(e['cases'])} cases"
    names: list[str] = []
    for e in kept:
        for n in (e["from"], e["to"]):
            if n not in names:
                names.append(n)
    nodes = [{"id": n, "label": n, "type": "ip" if db._IP_LIKE.match(n) else "entity"} for n in names]
    ranked = {role: sorted(({**r, "rules": sorted(r["rules"])} for r in by.values()),
                           key=lambda r: (-r["score"], r["entity"]))[:8]
              for role, by in risk.items()}
    return {"graph": {"nodes": nodes, "edges": kept}, "risk": ranked, "undecided": 0, "confirmed": confirmed}
