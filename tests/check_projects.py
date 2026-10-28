"""Projects as investigations (specs/projects.md): P1 status and a required project.

    python tests/check_projects.py [repo dir] [--scratch DIR]

A throwaway DATA_DIR and AUTH_DIR, the real app through FastAPI's TestClient. Cases
are made in storage with a few findings written straight into their DuckDB, so no
pipeline or model runs.
"""
import argparse
import io
import os
import shutil
import sys
import tempfile
from pathlib import Path

ap = argparse.ArgumentParser()
ap.add_argument("repo", nargs="?", default=str(Path(__file__).resolve().parents[1]))
ap.add_argument("--scratch", default=None)
args = ap.parse_args()
scratch = Path(args.scratch or tempfile.mkdtemp(prefix="projects-"))
shutil.rmtree(scratch, ignore_errors=True)
(scratch / "data").mkdir(parents=True)
(scratch / "auth").mkdir(parents=True)
os.environ["DATA_DIR"] = str(scratch / "data")
os.environ["AUTH_DIR"] = str(scratch / "auth")
os.environ.setdefault("TRIAGE_ENABLED", "0")
sys.path.insert(0, args.repo)

from fastapi.testclient import TestClient  # noqa: E402

from app.services import auth, authz, db, hashchain, projects, storage  # noqa: E402

failures = 0


def check(name: str, ok: bool) -> None:
    global failures
    print(("  ok   " if ok else "  FAIL ") + name)
    failures += 0 if ok else 1


PW = "correct horse battery"
for email, role in (("manager@x.test", authz.MANAGER), ("analyst@x.test", authz.ANALYST)):
    auth.create_account("check", email, role, role, PW)

from app.main import app  # noqa: E402


def client(email: str) -> TestClient:
    c = TestClient(app)
    assert c.post("/api/auth/login", json={"email": email, "password": PW}).status_code == 200
    return c


manager, analyst = client("manager@x.test"), client("analyst@x.test")
co = storage.create_company("Acme")
CO = co["company_id"]


def upload(c: TestClient, **form):
    return c.post("/api/upload", data=form,
                  files={"file": ("t.log", io.BytesIO(b"Oct 1 00:00:00 h sshd[1]: x\n"), "text/plain")})


def case_with_findings(project: dict | None, keys: list[tuple[str, str, str]]) -> str:
    """A ready case of Acme whose findings collapse to `keys` (rid, srcip, user)."""
    cid = storage.create_case("f.log", "log", 1, company_id=CO, project=project)["case_id"]
    con = db.init(cid)
    for i, (rid, src, user) in enumerate(keys):
        con.execute("INSERT INTO raw_events (row_id, srcip, username) VALUES (?, ?, ?)", [i, src, user])
        con.execute("INSERT INTO findings (row_id, rid, lvl, descr, mitre) VALUES (?, ?, 3, 'x', ['T1041'])",
                    [i, rid])
    con.close()
    storage.raw_path(cid, "log").write_text("Oct 1 00:00:00 h sshd[1]: x\n", encoding="utf-8")
    storage.update_case(cid, status="ready")
    return cid


print("P1: every new case is in a project")
before = {c["company_id"] for c in storage.list_companies()}
r = upload(manager, company_name="Brand new Co")
check(f"an upload naming no project is refused (400, {r.status_code})", r.status_code == 400)
check("and no customer was created on the way", {c["company_id"] for c in storage.list_companies()} == before)
r = upload(manager, company_id=CO, project_name="Q3 breach")
check("an upload into a new project files the case in it",
      r.status_code == 200 and r.json().get("project_name") == "Q3 breach")
q3 = storage.find_project_by_name(CO, "Q3 breach")
check("a new project is Open", q3 is not None and storage.project_status(q3) == storage.PROJECT_OPEN)
check("a project from before statuses is Open", storage.project_status({"name": "old"}) == storage.PROJECT_OPEN)

print("P1: closing only when every suggestion is decided (Q110)")
pj = storage.create_project(CO, "Ransomware 2026", "check")
PJ = pj["project_id"]
c1 = case_with_findings(pj, [("R3001", "10.0.0.5", "eve"), ("R2002", "10.0.0.6", "")])
rows = {p["project_id"]: p for p in manager.get(f"/api/companies/{CO}/projects").json()}
check("the list says what the project holds and that it cannot close yet",
      rows[PJ]["cases"] == 1 and rows[PJ]["unreviewed"] == 2 and rows[PJ]["can_close"] is False
      and "2 suggestions are not decided" in rows[PJ]["close_blocker"])
check("an analyst may not close a project (403)",
      analyst.post(f"/api/companies/{CO}/projects/{PJ}/close").status_code == 403)
r = manager.post(f"/api/companies/{CO}/projects/{PJ}/close")
check(f"closing with suggestions not decided is refused (409, {r.status_code})", r.status_code == 409)
busy = storage.create_case("b.log", "log", 1, company_id=CO, project=pj)["case_id"]
storage.raw_path(busy, "log").write_text("Oct 1 00:00:01 h sshd[1]: y\n", encoding="utf-8")
storage.update_case(busy, status="processing")
for key in [f["key"] for f in db.collapsed_findings(c1)]:
    manager.post(f"/api/cases/{c1}/review", json={"finding_key": key, "action": "accept"})
r = manager.post(f"/api/companies/{CO}/projects/{PJ}/close")
check(f"a case still processing blocks it too (409, {r.status_code})",
      r.status_code == 409 and "not processed" in r.json()["detail"])
storage.update_case(busy, status="ready")
r = manager.post(f"/api/companies/{CO}/projects/{PJ}/close")
check("every suggestion decided and every case processed: a manager closes it",
      r.status_code == 200 and r.json()["status"] == "closed" and r.json()["closed_by"] == "manager@x.test")
check("closing twice is refused (409)", manager.post(f"/api/companies/{CO}/projects/{PJ}/close").status_code == 409)

print("P1: a closed project takes no new evidence (Q111)")
r = upload(manager, company_id=CO, project_id=PJ)
check(f"an upload into it by id is refused (409, {r.status_code})", r.status_code == 409 and "closed" in r.json()["detail"])
r = upload(manager, company_id=CO, project_name="ransomware 2026")
check(f"and by name (409, {r.status_code})", r.status_code == 409)
check("no case was made", len(projects.cases_of(CO, PJ)) == 2)
r = manager.post("/api/cases/merge", json={"case_ids": [c1, busy]})
check(f"nor merged into it (409, {r.status_code})", r.status_code == 409 and "closed" in r.json()["detail"])

print("P1: reopening")
check("an analyst may not reopen (403)", analyst.post(f"/api/companies/{CO}/projects/{PJ}/reopen").status_code == 403)
r = manager.post(f"/api/companies/{CO}/projects/{PJ}/reopen")
check("a manager reopens it", r.status_code == 200 and r.json()["status"] == "open" and "closed_at" not in r.json())
check("and it takes evidence again", upload(manager, company_id=CO, project_id=PJ).status_code == 200)
log = storage.project_log_path(CO, PJ)
check("every change is in the project's hash-chained log",
      [e["action"] for e in projects.history(CO, PJ)] == ["closed", "reopened"]
      and hashchain.verify(log).get("intact"))
check("an unknown action or project is 404",
      manager.post(f"/api/companies/{CO}/projects/{PJ}/archive").status_code == 404
      and manager.post(f"/api/companies/{CO}/projects/pj-000000000000/close").status_code == 404)

print("P1: the project list")
manager.post(f"/api/companies/{CO}/projects/{q3['project_id']}/close")
listed = manager.get(f"/api/companies/{CO}/projects").json()
check("Open first, then Closed", [p["status"] for p in listed] == sorted((p["status"] for p in listed),
                                                                           key=lambda s: s != "open"))
other = storage.create_project(CO, "Phishing", "check")
c2 = case_with_findings(other, [("R3001", "10.0.0.9", "bob")])
r = manager.post("/api/cases/merge", json={"case_ids": [c1, c2]})
check(f"cases of different projects are not merged (409, {r.status_code})",
      r.status_code == 409 and "different projects" in r.json()["detail"])

print("P2: a dashboard per project")
from app.services import jobs  # noqa: E402

jobs.wait_idle(120)  # the uploads above are processed, so every count below is settled
whole = manager.get("/api/overview", params={"company_id": CO}).json()
one = manager.get("/api/overview", params={"company_id": CO, "project_id": PJ}).json()
mine = projects.cases_of(CO, PJ)
check("scoped to a project, the Overview counts that project's cases only",
      one["project_id"] == PJ and one["totals"]["cases"] == len(mine) < whole["totals"]["cases"])
check("its suggestions are the project's",
      one["totals"]["reviewable"] == next(p for p in projects.summary(CO) if p["project_id"] == PJ)["reviewable"])
check("the customer's own Overview lists every project, Open first, and none when one is chosen",
      {p["project_id"] for p in whole["by_project"]} == {p["project_id"] for p in storage.list_projects(CO)}
      and one["by_project"] == [] and {p["project_id"] for p in one["project_options"]} >= {PJ})
check("a project of no customer, or of another, is 404",
      manager.get("/api/overview", params={"project_id": PJ}).status_code == 404
      and manager.get("/api/overview", params={"company_id": storage.create_company("Other")["company_id"],
                                               "project_id": PJ}).status_code == 404)
fall = manager.get("/api/findings", params={"company_id": CO}).json()
fpj = manager.get("/api/findings", params={"company_id": CO, "project_id": PJ}).json()
check("Findings filtered by project lists only that project's cases",
      all(r["case_id"] in {m["case_id"] for m in mine} for r in fpj["rows"])
      and fpj["scope_total"] <= fall["scope_total"])
check("and a project without its customer is 404",
      manager.get("/api/findings", params={"project_id": PJ}).status_code == 404)

print("P3: rename")
from app.services import case_delete, custody  # noqa: E402

check("an analyst may not rename (403)",
      analyst.put(f"/api/companies/{CO}/projects/{PJ}", json={"name": "x"}).status_code == 403)
check("a name another project has is refused (409), an empty one is 400",
      manager.put(f"/api/companies/{CO}/projects/{PJ}", json={"name": "phishing"}).status_code == 409
      and manager.put(f"/api/companies/{CO}/projects/{PJ}", json={"name": "  "}).status_code == 400)
r = manager.put(f"/api/companies/{CO}/projects/{PJ}", json={"name": "Ransomware 2026 (Lockbit)"})
check("a manager renames it", r.status_code == 200 and r.json()["name"] == "Ransomware 2026 (Lockbit)")
check("and every case of it carries the new name",
      {m["project_name"] for m in projects.cases_of(CO, PJ)} == {"Ransomware 2026 (Lockbit)"})
check("the rename is in the project's log", projects.history(CO, PJ)[-1]["action"] == "renamed")

print("P3: moving a case")
OTHER = other["project_id"]
legacy = case_with_findings(None, [("R3001", "10.0.0.7", "kim")])  # a case from before (Q112)
check("an analyst may not move a case (403)",
      analyst.post(f"/api/companies/{CO}/projects/{OTHER}/cases", json={"case_id": legacy}).status_code == 403)
r = manager.post(f"/api/companies/{CO}/projects/{OTHER}/cases", json={"case_id": legacy})
check("a case in no project is moved into one",
      r.status_code == 200 and r.json()["project_id"] == OTHER and r.json()["project_name"] == "Phishing")
check("the move is on the case's chain of custody and in the project's log",
      custody.entries(legacy)[-1]["action"] == "moved" and projects.history(CO, OTHER)[-1]["action"] == "case_moved_in")
r = manager.post(f"/api/companies/{CO}/projects/{PJ}/cases", json={"case_id": legacy})
check("and on to another project", r.status_code == 200 and r.json()["project_id"] == PJ
      and projects.history(CO, OTHER)[-1]["action"] == "case_moved_out")
foreign_co = storage.create_company("Foreign")
foreign = storage.create_case("x.log", "log", 1, company_id=foreign_co["company_id"],
                              project=storage.create_project(foreign_co["company_id"], "F", "check"))["case_id"]
check("another customer's case is not moved in (404)",
      manager.post(f"/api/companies/{CO}/projects/{PJ}/cases", json={"case_id": foreign}).status_code == 404)
for key in [f["key"] for f in db.collapsed_findings(c2)]:
    manager.post(f"/api/cases/{c2}/review", json={"finding_key": key, "action": "accept"})
check("(Phishing closes once its case is decided)",
      manager.post(f"/api/companies/{CO}/projects/{OTHER}/close").status_code == 200)
r = manager.post(f"/api/companies/{CO}/projects/{OTHER}/cases", json={"case_id": legacy})
check(f"a case is not moved into a closed project (409, {r.status_code})", r.status_code == 409)
r = manager.post(f"/api/companies/{CO}/projects/{PJ}/cases", json={"case_id": c2})
check(f"nor out of one (409, {r.status_code})", r.status_code == 409 and "closed" in r.json()["detail"])
manager.post(f"/api/companies/{CO}/projects/{OTHER}/reopen")
storage.update_case(c2, status="processing")
check("nor while it is processed (409)",
      manager.post(f"/api/companies/{CO}/projects/{PJ}/cases", json={"case_id": c2}).status_code == 409)
storage.update_case(c2, status="ready")

print("P3: deleting a project")
doomed = storage.create_project(CO, "Doomed", "check")
DP = doomed["project_id"]
d1 = case_with_findings(doomed, [("R3001", "10.0.0.8", "zed")])
keep_cases = {m["case_id"] for m in storage.list_manifests(CO)} - {d1}
check("an analyst may not see or delete (403)",
      analyst.get(f"/api/companies/{CO}/projects/{DP}/deletion").status_code == 403
      and analyst.delete(f"/api/companies/{CO}/projects/{DP}").status_code == 403)
pre = manager.get(f"/api/companies/{CO}/projects/{DP}/deletion").json()
check(f"the preview counts what goes {pre}", pre["cases"] == 1 and pre["suggestions"] == 1 and pre["busy"] == [])
storage.update_case(d1, status="processing")
check("refused while a case of it is processed (409), nothing goes",
      manager.delete(f"/api/companies/{CO}/projects/{DP}").status_code == 409
      and storage.load_manifest(d1) is not None and storage.load_project(CO, DP) is not None)
storage.update_case(d1, status="ready")
r = manager.delete(f"/api/companies/{CO}/projects/{DP}")
check("a manager deletes it", r.status_code == 200 and r.json()["deleted"] == DP)
check("the project and its case are gone, every other case stays",
      storage.load_project(CO, DP) is None and storage.load_manifest(d1) is None
      and keep_cases <= {m["case_id"] for m in storage.list_manifests(CO)})
rec = case_delete.records(CO)
check("the customer's deletion record has the case, then the project carrying its log",
      [e["action"] for e in rec[-2:]] == ["case_deleted", "project_deleted"]
      and rec[-1]["cases"] == [d1] and rec[-1]["project_name"] == "Doomed"
      and hashchain.verify(case_delete.log_path(CO)).get("intact"))
empty = storage.create_project(CO, "Empty", "check")
check("an empty project is deleted too",
      manager.delete(f"/api/companies/{CO}/projects/{empty['project_id']}").status_code == 200)

print("P4: the whole investigation")
inv = storage.create_project(CO, "Intrusion", "check")
IV = inv["project_id"]


def timed_case(rows: list[tuple[str, str, str, str, list[str]]]) -> str:
    """A ready case of the Intrusion project: rows of (ts, rid, srcip, dstip, mitre)."""
    cid = storage.create_case("t.log", "log", 1, company_id=CO, project=inv)["case_id"]
    con = db.init(cid)
    for i, (ts, rid, src, dst, mitre) in enumerate(rows):
        con.execute("INSERT INTO raw_events (row_id, ts, srcip, dstip) VALUES (?, ?, ?, ?)", [i, ts, src, dst])
        con.execute("INSERT INTO findings (row_id, rid, lvl, descr, mitre) VALUES (?, ?, 5, 'x', ?)", [i, rid, mitre])
    con.close()
    storage.update_case(cid, status="ready")
    return cid


firewall = timed_case([("2026-05-02 10:00:00", "R2002", "203.0.113.9", "10.0.0.20", ["T1046"])])
hosts = timed_case([("2026-05-01 09:00:00", "R3001", "203.0.113.9", "10.0.0.20", ["T1041"]),
                    ("2026-05-03 11:00:00", "R2007", "10.0.0.20", "198.51.100.4", ["T1071"])])
for cid in (firewall, hosts):
    for f in db.collapsed_findings(cid):
        if f["rid"] != "R2007":  # left undecided
            manager.post(f"/api/cases/{cid}/review", json={"finding_key": f["key"], "action": "accept"})
tl = analyst.get(f"/api/companies/{CO}/projects/{IV}/timeline").json()
check("the project timeline holds the confirmed groups of both cases, and every role reads it",
      {f["case_id"] for f in tl["findings"]} == {firewall, hosts} and len(tl["findings"]) == 2)
check("in the order their first event happened, across cases",
      [f["case_id"] for f in tl["findings"]] == [hosts, firewall]
      and [f["ts_first"][:10] for f in tl["findings"]] == ["2026-05-01", "2026-05-02"])
check("a group not decided is left out and counted", tl["undecided"] == 1)
check("each names its file, and the stages are ATT&CK's",
      all(f["case_file"] for f in tl["findings"]) and tl["tactic_order"][0]["id"] == "reconnaissance")
gr = analyst.get(f"/api/companies/{CO}/projects/{IV}/graph").json()
shared = [e for e in gr["graph"]["edges"] if (e["from"], e["to"]) == ("203.0.113.9", "10.0.0.20")]
check("the same two hosts in two cases are one edge naming both cases",
      len(shared) == 1 and len(shared[0]["cases"]) == 2 and set(shared[0]["rules"]) == {"R2002", "R3001"})
check("a host is one node however many cases it is in",
      [n["id"] for n in gr["graph"]["nodes"]].count("203.0.113.9") == 1)
src = {r["entity"]: r for r in gr["risk"].get("sources", [])}
check("its risk is summed over the cases", src.get("203.0.113.9", {}).get("cases") == 2)
check("an unknown project is 404",
      manager.get(f"/api/companies/{CO}/projects/pj-000000000000/timeline").status_code == 404
      and manager.get(f"/api/companies/{CO}/projects/pj-000000000000/graph").status_code == 404)
whole = manager.get("/api/overview", params={"company_id": CO}).json()
row = next(p for p in whole["by_project"] if p["project_id"] == IV)
one = manager.get("/api/overview", params={"company_id": CO, "project_id": IV}).json()
check("a project's row carries its own areas and evidence, as its Overview counts them",
      row["areas"] == {a["id"]: sum(a["total"].values()) for a in one["areas"] if sum(a["total"].values())}
      and [(c["product"], c["days"]) for c in row["coverage"]]
      == [(c["product"], c["days"]) for c in one["coverage"] if "days" in c])

jobs.wait_idle(120)  # the uploads above queued real processing; let it finish before exit
print("\nPROJECTS OK" if not failures else f"\n{failures} FAILED")
sys.exit(1 if failures else 0)
