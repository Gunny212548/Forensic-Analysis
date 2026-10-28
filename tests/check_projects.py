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

from app.services import jobs  # noqa: E402

jobs.wait_idle(120)  # the uploads above queued real processing; let it finish before exit
print("\nPROJECTS OK" if not failures else f"\n{failures} FAILED")
sys.exit(1 if failures else 0)
