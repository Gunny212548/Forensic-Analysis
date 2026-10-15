"""Each customer's cases must live in that customer's store and nowhere else.

    python tests/check_customer_isolation.py <scratch dir> [--repo DIR]

Builds a throwaway store in <scratch dir>, adds two customers through the
API, uploads gen_usecase's files for each (the SAME bytes for both - the
case that tempts a shared store), and checks:

- adding a customer creates its store (customers/<id>/ with every subdir);
- every file of a case - manifest, DuckDB, raw evidence, custody log,
  review log, analysis - is under its own customer's store, and nothing of
  either customer is anywhere else in DATA_DIR;
- the case list and the Overview, scoped to one customer, show only that
  customer's cases; unscoped they show both;
- merging cases of two customers is refused (409), and within one customer
  it is allowed and lands in that customer's store;
- a project lives in its customer's store, is reused by name, and another
  customer's project id is refused (409) without making a case; a merge
  keeps a project only when every source is in it;
- a case id that is not a case id, or a customer that does not exist, is
  refused instead of turning into a path.

stdlib + the app's own dependencies (fastapi TestClient); no network.
"""

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
EMAIL, PASSWORD = "isolation@test.local", "isolation-throwaway-password"
FAILED: list[str] = []


def check(ok: bool, what: str) -> None:
    print(f"  {'ok  ' if ok else 'FAIL'} {what}")
    if not ok:
        FAILED.append(what)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("scratch")
    ap.add_argument("--repo", default=str(REPO))
    args = ap.parse_args()
    scratch, repo = Path(args.scratch), Path(args.repo)
    store, uc = scratch / "store", scratch / "usecase"
    store.mkdir(parents=True, exist_ok=True)
    subprocess.run([sys.executable, str(Path(__file__).with_name("gen_usecase.py")), str(uc)],
                   check=True, capture_output=True)
    os.environ["DATA_DIR"] = str(store)
    subprocess.run([sys.executable, str(repo / "tools" / "create_user.py"), "add", EMAIL,
                    "--name", "Isolation", "--role", "analyst", "--password-stdin"],
                   input=PASSWORD + "\n", text=True, capture_output=True, check=True)
    sys.path.insert(0, str(repo))
    from fastapi.testclient import TestClient

    from app.main import app

    c = TestClient(app)
    with c:
        c.post("/api/auth/login", json={"email": EMAIL, "password": PASSWORD})

        print("customers")
        a = c.post("/api/companies", json={"name": "Customer A"}).json()
        b = c.post("/api/companies", json={"name": "Customer B"}).json()
        for co in (a, b):
            root = store / "customers" / co["company_id"]
            check(all((root / sub).is_dir() for sub in
                      ("cases", "db", "raw", "analysis", "review", "custody"))
                  and (root / "customer.json").is_file(),
                  f"adding {co['name']} created its store")

        print("uploads (the same bytes for both customers)")
        cases = {a["company_id"]: [], b["company_id"]: []}
        for co in (a, b):
            for name in ("nightfall-auth.log", "nightfall-firewall.csv"):
                with open(uc / name, "rb") as fh:
                    m = c.post("/api/upload", files={"file": (name, fh)},
                               data={"company_id": co["company_id"]}).json()
                # TestClient runs the background task before returning.
                cases[co["company_id"]].append(m["case_id"])
        for co_id, ids in cases.items():
            for cid in ids:
                m = c.get(f"/api/cases/{cid}").json()
                check(m.get("status") == "ready" and m.get("company_id") == co_id,
                      f"{cid} processed for its customer")

        # A review decision, so the review log exists to be located too.
        first = cases[a["company_id"]][0]
        key = c.get(f"/api/cases/{first}/findings").json()["findings"][0]["key"]
        r = c.post(f"/api/cases/{first}/review", json={"finding_key": key, "action": "accept"})
        check(r.status_code == 200, f"review decision recorded ({r.status_code})")

        print("where the files are")
        everything = [p for p in store.rglob("*") if p.is_file()]
        for co_id, ids in cases.items():
            own = store / "customers" / co_id
            for cid in ids:
                files = [p for p in everything if cid in p.name]
                inside = all(own in p.parents for p in files)
                kinds = {p.parent.name for p in files}
                check(inside and {"cases", "db", "raw", "custody"} <= kinds,
                      f"{cid}: {len(files)} files, all in its own store ({sorted(kinds)})")
        check(not any(p.name in ("users.json", "session_secret") for p in everything),
              "no login account file inside DATA_DIR (they live in AUTH_DIR)")
        shared = [p for p in everything if "customers" not in p.parts
                  and any(cid in p.name for ids in cases.values() for cid in ids)]
        check(not shared, f"no case file outside the customer stores ({len(shared)} found)")

        print("scoped views")
        for co_id, ids in cases.items():
            listed = [m["case_id"] for m in c.get(f"/api/cases?company_id={co_id}").json()]
            check(sorted(listed) == sorted(ids), f"case list for {co_id} shows only its cases")
            ov = c.get(f"/api/overview?company_id={co_id}").json()
            check(sorted(x["case_id"] for x in ov["cases"]) == sorted(ids)
                  and ov["company_id"] == co_id and ov["totals"]["customers"] == 1,
                  f"overview for {co_id} shows only its cases")
        allv = c.get("/api/overview").json()
        check(len(allv["cases"]) == 4 and len(allv["customer_options"]) == 2,
              "unscoped overview shows both customers")
        check(c.get("/api/overview?company_id=co-000000000000").status_code == 404,
              "overview of an unknown customer is 404")

        print("merge")
        auth_a = cases[a["company_id"]][0]
        auth_b = cases[b["company_id"]][0]
        r = c.post("/api/cases/merge", json={"case_ids": [auth_a, auth_b]})
        check(r.status_code == 409, f"merge across customers refused ({r.status_code})")
        # Within one customer: two log cases of A (upload the auth log again).
        with open(uc / "nightfall-auth.log", "rb") as fh:
            again = c.post("/api/upload", files={"file": ("again.log", fh)},
                           data={"company_id": a["company_id"]}).json()["case_id"]
        r = c.post("/api/cases/merge", json={"case_ids": [auth_a, again]})
        merged = r.json().get("case_id") if r.status_code == 200 else None
        check(merged is not None
              and (store / "customers" / a["company_id"] / "cases" / f"{merged}.json").is_file(),
              f"merge within one customer lands in its store ({r.status_code})")

        print("projects")

        def upload_a(data: dict) -> "object":
            with open(uc / "nightfall-auth.log", "rb") as fh:
                return c.post("/api/upload", files={"file": ("p.log", fh)}, data=data)

        p1 = upload_a({"company_id": a["company_id"], "project_name": "Investigation 1"}).json()
        pid = p1.get("project_id")
        check(bool(pid) and p1.get("project_name") == "Investigation 1"
              and (store / "customers" / a["company_id"] / "projects" / f"{pid}.json").is_file(),
              "a new project is created in its customer's store and the case is filed in it")
        p2 = upload_a({"company_id": a["company_id"], "project_name": "investigation 1 "}).json()
        check(p2.get("project_id") == pid, "a project name is reused, not forked")
        listed = c.get(f"/api/companies/{a['company_id']}/projects").json()
        check([p["project_id"] for p in listed] == [pid], "the customer's project list has it")
        check(c.get(f"/api/companies/{b['company_id']}/projects").json() == [],
              "the other customer has no projects")
        before = len(c.get(f"/api/cases?company_id={b['company_id']}").json())
        with open(uc / "nightfall-auth.log", "rb") as fh:
            r = c.post("/api/upload", files={"file": ("x.log", fh)},
                       data={"company_id": b["company_id"], "project_id": pid})
        after = len(c.get(f"/api/cases?company_id={b['company_id']}").json())
        check(r.status_code == 409 and after == before,
              f"another customer's project is refused and no case is made ({r.status_code})")
        r = upload_a({"company_id": a["company_id"], "project_id": "../../users"})
        check(r.status_code == 409, f"a path-shaped project id is not a project ({r.status_code})")
        r = c.post("/api/cases/merge", json={"case_ids": [p1["case_id"], p2["case_id"]]})
        m = c.get(f"/api/cases/{r.json().get('case_id')}").json() if r.status_code == 200 else {}
        check(m.get("project_id") == pid, f"a merge of one project's cases stays in it ({r.status_code})")
        r = c.post("/api/cases/merge", json={"case_ids": [p1["case_id"], auth_a]})
        m = c.get(f"/api/cases/{r.json().get('case_id')}").json() if r.status_code == 200 else {}
        check(r.status_code == 200 and not m.get("project_id"),
              f"a merge across projects is in no project ({r.status_code})")

        print("refusals")
        check(c.get("/api/cases/..%2F..%2Fusers").status_code in (404, 422),
              "a path-shaped case id is not a case")
        check(c.get("/api/cases?company_id=../../users").status_code == 404,
              "a path-shaped customer id is not a customer")

    print(f"\n{'CUSTOMER ISOLATION OK' if not FAILED else f'{len(FAILED)} FAILED'}")
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
