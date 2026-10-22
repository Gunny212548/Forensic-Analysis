"""Roles and permissions (IAI-14, specs/IAI-14_rbac.md): the matrix, the
lifecycle rules, and every route answering 403 / 200 by role over HTTP.

    python tests/check_authz.py [repo dir] [--scratch DIR]

A throwaway DATA_DIR and AUTH_DIR, the real app through FastAPI's TestClient.
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
scratch = Path(args.scratch or tempfile.mkdtemp(prefix="authz-"))
shutil.rmtree(scratch, ignore_errors=True)
(scratch / "data").mkdir(parents=True)
(scratch / "auth").mkdir(parents=True)
os.environ["DATA_DIR"] = str(scratch / "data")
os.environ["AUTH_DIR"] = str(scratch / "auth")
sys.path.insert(0, args.repo)

from fastapi.testclient import TestClient  # noqa: E402

from app.services import auth, authz, hashchain, storage  # noqa: E402

failures = 0


def check(name: str, ok: bool) -> None:
    global failures
    print(("  ok   " if ok else "  FAIL ") + name)
    failures += 0 if ok else 1


print("the matrix (specs/IAI-14_rbac.md)")
A, M, N = authz.ADMIN, authz.MANAGER, authz.ANALYST
TABLE = {
    authz.READ: {A, M, N}, authz.UPLOAD: {A, M, N}, authz.CUSTOMERS: {A, M}, authz.QUESTION: {A, M},
    authz.PROVENANCE: {A, M, N}, authz.VERIFY: {A, M, N}, authz.REPROCESS: {A, M, N},
    authz.MERGE: {A, M}, authz.ANALYZE: {A, M, N}, authz.REVIEW: {A, M, N}, authz.ASSIGN: {A, M},
    authz.WORK: {A, M}, authz.CLOSE: {A, M}, authz.REOPEN: {A, M}, authz.ACCOUNTS: {A},
    authz.LIFECYCLE: {A, M, N},
}
wrong = [(action, role) for action, roles in TABLE.items() for role in authz.ROLES
         if authz.can({"role": role}, action) != (role in roles)]
check(f"every action x role as the table says {wrong}", not wrong)
check("deny by default: an unknown role, or none, may do nothing",
      not any(authz.can({"role": r}, a) for r in ("viewer", "", None, "Admin") for a in TABLE))
check("admin may do everything any other role may (the user, 2026-10-22)",
      all(set(authz.PERMISSIONS[r]) <= set(authz.PERMISSIONS[A]) for r in authz.ROLES))
try:
    authz.require({"email": "a@x", "role": N}, authz.CLOSE)
    check("a refusal names who and what is needed", False)
except authz.Forbidden as exc:
    check("a refusal names who and what is needed", "a@x" in str(exc) and "manager" in str(exc))

print("lifecycle: an analyst works their own findings; a manager closes (Q57)")
me = {"email": "ana@x", "role": N}


def allowed(user, action, current, body=None):
    try:
        authz.require_lifecycle(user, action, current, body or {})
        return True
    except authz.Forbidden:
        return False


cases = [
    ("take an unassigned finding", me, "assign", None, {"assignee": "ana@x"}, True),
    ("assign it to someone else", me, "assign", None, {"assignee": "bob@x"}, False),
    ("take one assigned to someone else", me, "assign", {"assignee": "bob@x"}, {"assignee": "ana@x"}, False),
    ("investigate their own", me, "investigate", {"assignee": "ana@x"}, {}, True),
    ("investigate an unassigned one, taking it", me, "investigate", None, {"assignee": "ana@x"}, True),
    ("investigate someone else's", me, "investigate", {"assignee": "bob@x"}, {}, False),
    ("contain their own", me, "contain", {"assignee": "ana@x"}, {}, True),
    ("resolve their own", me, "resolve", {"assignee": "ana@x"}, {}, False),
    ("reopen", me, "reopen", {"assignee": "ana@x"}, {}, False),
]
for name, user, action, current, body, want in cases:
    check(f"analyst may {'' if want else 'not '}{name}", allowed(user, action, current, body) == want)
mgr = {"email": "mgr@x", "role": M}
check("a manager may assign, work, resolve and reopen any",
      all(allowed(mgr, a, {"assignee": "bob@x"}, {"assignee": "bob@x"})
          for a in ("assign", "investigate", "contain", "resolve", "reopen")))
check("an admin may make any lifecycle change, as a manager",
      all(allowed({"email": "adm@x", "role": A}, a, {"assignee": "bob@x"}, {"assignee": "bob@x"})
          for a in ("assign", "investigate", "contain", "resolve", "reopen")))

print("over HTTP")
PW = "correct horse battery"
for email, role in (("admin@x.test", A), ("manager@x.test", M), ("analyst@x.test", N)):
    auth.create_account("check", email, role, role, PW)
users = auth.load_users()
users["norole@x.test"] = {"email": "norole@x.test", "name": "", "role": "viewer",
                          "password": auth.hash_password(PW)}
auth.save_users(users)
co = storage.create_company("Existing customer")

from app.main import app  # noqa: E402


def client(email: str) -> TestClient:
    c = TestClient(app)
    r = c.post("/api/auth/login", json={"email": email, "password": PW})
    assert r.status_code == 200, (email, r.status_code, r.text)
    return c


admin, manager, analyst, norole = (client(e) for e in
                                   ("admin@x.test", "manager@x.test", "analyst@x.test", "norole@x.test"))
me_ = analyst.get("/api/auth/me").json()
check("/me carries the role and its permissions",
      me_["role"] == "analyst" and authz.CLOSE not in me_["permissions"] and authz.REVIEW in me_["permissions"])
check("every role reads; an account with no role reads nothing but who it is",
      all(c.get("/api/cases").status_code == 200 for c in (admin, manager, analyst))
      and norole.get("/api/cases").status_code == 403 and norole.get("/api/auth/me").status_code == 200)
check("a new customer: admin and manager 200, analyst 403",
      [c.post("/api/companies", json={"name": "New Co"}).status_code for c in (analyst, admin, manager)]
      == [403, 200, 200])


def upload(c: TestClient, **form) -> int:
    return c.post("/api/upload", data=form,
                  files={"file": ("t.log", io.BytesIO(b"Oct 1 00:00:00 h sshd[1]: x\n"), "text/plain")}).status_code


check("upload: an account with no role refused before the body is read",
      upload(norole, company_id=co["company_id"]) == 403)
check("upload: an admin may", upload(admin, company_id=co["company_id"]) == 200)
check("upload: an analyst into an existing customer", upload(analyst, company_id=co["company_id"]) == 200)
check("upload: an analyst may not create a customer or a project on the way",
      upload(analyst, company_name="Brand new") == 403
      and upload(analyst, company_id=co["company_id"], project_name="New project") == 403)
check("upload: a manager may", upload(manager, company_name="Brand new") == 200)
check("an existing customer named on upload is not a new one",
      upload(analyst, company_name="existing customer") == 200)

print("every case route asks (403 for a role without the action, anything else for one with it)")
# Never processed: the routes that pass authz stop at 409 / 400 / 404, so no
# pipeline or model call runs.
cid = storage.create_case("t.log", "log", 1, company_id=co["company_id"])["case_id"]
ROUTES = [  # (method, path, body, action)
    ("post", f"/api/cases/{cid}/verify", None, authz.VERIFY),
    ("put", f"/api/cases/{cid}/question", {}, authz.QUESTION),
    ("put", f"/api/cases/{cid}/provenance", {}, authz.PROVENANCE),
    ("post", f"/api/cases/{cid}/reprocess", {}, authz.REPROCESS),
    ("post", "/api/cases/merge", {}, authz.MERGE),
    ("post", f"/api/cases/{cid}/lifecycle", {"finding_key": "none"}, authz.LIFECYCLE),
    ("post", f"/api/cases/{cid}/review", {"finding_key": "none"}, authz.REVIEW),
    ("post", f"/api/cases/{cid}/analyze", None, authz.ANALYZE),
]
sessions = {A: admin, M: manager, N: analyst, "viewer": norole}
wrong = []
for method, path, body, action in ROUTES:
    for role, c in sessions.items():
        code = getattr(c, method)(path, **({"json": body} if body is not None else {})).status_code
        if (code == 403) == authz.can({"role": role}, action):
            wrong.append((path.rsplit("/", 1)[-1], role, code))
check(f"each route answers 403 exactly where the matrix says no {wrong}", not wrong)

print("accounts (the Users page)")
check("only an admin lists accounts", [c.get("/api/users").status_code for c in (analyst, manager, admin)]
      == [403, 403, 200])
r = admin.post("/api/users", json={"email": "new@x.test", "name": "New", "role": "analyst", "password": PW})
check("an admin creates an account", r.status_code == 200 and r.json()["role"] == "analyst")
check("a short password or an unknown role is refused",
      admin.post("/api/users", json={"email": "s@x.test", "role": "analyst", "password": "short"}).status_code == 400
      and admin.post("/api/users", json={"email": "s@x.test", "role": "root", "password": PW}).status_code == 400)
newbie = client("new@x.test")
check("the new analyst works", newbie.get("/api/cases").status_code == 200)
check("a change of the wrong type is refused, not coerced",
      admin.patch("/api/users/new@x.test", json={"disabled": "false"}).status_code == 400
      and admin.patch("/api/users/new@x.test", json={"name": 5}).status_code == 400
      and newbie.get("/api/cases").status_code == 200)
check("an admin changes a role", admin.patch("/api/users/new@x.test", json={"role": "manager"}).json()["role"]
      == "manager")
check("disabling an account ends its session and its sign-in",
      admin.patch("/api/users/new@x.test", json={"disabled": True}).status_code == 200
      and newbie.get("/api/cases").status_code == 401
      and TestClient(app).post("/api/auth/login", json={"email": "new@x.test", "password": PW}).status_code == 401)
check("an admin may not demote or disable themself",
      admin.patch("/api/users/admin@x.test", json={"role": "analyst"}).status_code == 400
      and admin.patch("/api/users/admin@x.test", json={"disabled": True}).status_code == 400)
admin2 = TestClient(app)
auth.create_account("check", "admin2@x.test", "Second", A, PW)
admin2.post("/api/auth/login", json={"email": "admin2@x.test", "password": PW})
check("another admin may; the last enabled admin stays one",
      admin2.patch("/api/users/admin@x.test", json={"disabled": True}).status_code == 200
      and admin.get("/api/cases").status_code == 401
      and admin2.patch("/api/users/admin2@x.test", json={"role": "manager"}).status_code == 400)
admin2.patch("/api/users/admin@x.test", json={"disabled": False})
admin = client("admin@x.test")
mgr_session = client("manager@x.test")
check("a password reset ends the account's sessions",
      admin.post("/api/users/manager@x.test/password", json={"password": PW + "!"}).status_code == 200
      and mgr_session.get("/api/cases").status_code == 401)
check("an admin removes an account, not themself",
      admin.delete("/api/users/new@x.test").status_code == 200
      and admin.delete("/api/users/admin@x.test").status_code == 400)
audit = admin.get("/api/users/audit").json()
events = [e["event"] for e in audit["entries"]]
check(f"every change is in the hash-chained account log, newest first ({len(events)} lines)",
      audit["chain"].get("intact") and events[0] == "account_removed" and "password_reset" in events
      and not any("password" in str(e.get("changes", "")) or "hash" in e.get("changes", {})
                  for e in audit["entries"]))
check("the log holds no password", PW not in auth.accounts_audit_path().read_text(encoding="utf-8"))
check("the chain verifies on disk", hashchain.verify(auth.accounts_audit_path()).get("intact"))

print("\nAUTHZ OK" if not failures else f"\n{failures} FAILED")
sys.exit(1 if failures else 0)
