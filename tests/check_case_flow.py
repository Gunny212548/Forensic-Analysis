"""The case flow (IAI-89, specs/case_flow_design.md R1-R4), end to end through the API.

    python tests/check_case_flow.py <scratch dir> [--repo DIR]

Builds a throwaway store, uploads gen_usecase's planted attack (both files in
one zip, and the firewall alone) and walks a case through its six steps:

- the steps and their order, and that every step cites a standard that was
  read - one listed under "Read" in docs/standards/SOURCES.md (R4);
- states computed from the case's own records: Ingest done, Triage waiting on
  the unreviewed findings, Report's gate closed until they are reviewed;
- the recommended step moves on as the analyst works: review everything ->
  Investigate, start investigation on every high/critical finding -> Respond,
  resolve them -> Report;
- a rejected high/critical finding needs no investigation but is still waiting
  in Respond until it is closed;
- an evidence problem blocks Ingest;
- the attack graph and risk ranking are served without the AI (/graph).

stdlib + the app's own dependencies (fastapi TestClient); no network, no model.
"""

import argparse
import os
import subprocess
import sys
import zipfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
FAILED: list[str] = []
EMAIL, PW = "analyst@flow.local", "flow-throwaway-pw-1"
ORDER = ["ingest", "triage", "investigate", "respond", "analyse", "report"]


def check(ok: bool, what: str) -> None:
    print(f"  {'ok  ' if ok else 'FAIL'} {what}")
    if not ok:
        FAILED.append(what)


def read_sources(repo: Path) -> list[str]:
    """The first cell of every row in SOURCES.md's "## Read" table."""
    text = (repo / "docs" / "standards" / "SOURCES.md").read_text(encoding="utf-8")
    section = text.split("## Read", 1)[1].split("\n## ", 1)[0].split("\n### ", 1)[0]
    rows = [ln for ln in section.splitlines() if ln.startswith("| ") and not ln.startswith("| Document")]
    return [r.split("|")[1].strip() for r in rows if not set(r.replace("|", "").strip()) <= {"-"}]


def unit_standards(repo: Path) -> None:
    sys.path.insert(0, str(repo))
    from app.services import case_flow

    print("steps and their standards")
    check([s["id"] for s in case_flow.STEPS] == ORDER, "six steps, in the order of the design")
    read = read_sources(repo)
    check(len(read) >= 8, f"SOURCES.md lists the documents that were read ({len(read)})")
    for s in case_flow.STEPS:
        cited = [st["source"] for st in s["standards"]]
        backed = [c for c in cited if any(c in doc for doc in read)]
        check(bool(backed), f"{s['id']}: cites a standard that was read ({', '.join(backed) or 'none'})")


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
    with zipfile.ZipFile(uc / "nightfall.zip", "w") as z:
        z.write(uc / "nightfall-auth.log", "nightfall-auth.log")
        z.write(uc / "nightfall-firewall.csv", "nightfall-firewall.csv")
    os.environ["DATA_DIR"] = str(store)
    subprocess.run([sys.executable, str(repo / "tools" / "create_user.py"), "add", EMAIL,
                    "--name", "analyst", "--role", "analyst", "--password-stdin"],
                   input=PW + "\n", text=True, capture_output=True, check=True)
    unit_standards(repo)

    from fastapi.testclient import TestClient

    from app.main import app
    from app.services import custody, jobs

    c = TestClient(app)
    with c:
        c.post("/api/auth/login", json={"email": EMAIL, "password": PW})

        def upload(path: Path) -> dict:
            with open(path, "rb") as fh:
                return c.post("/api/upload", files={"file": (path.name, fh)},
                              data={"company_name": "Flow Co"}).json()

        Z = upload(uc / "nightfall.zip")["case_id"]
        F = upload(uc / "nightfall-firewall.csv")["case_id"]
        jobs.wait_idle(180)

        def flow(cid: str) -> dict:
            r = c.get(f"/api/cases/{cid}/flow")
            return r.json() if r.status_code == 200 else {"status": r.status_code}

        def step(fl: dict, sid: str) -> dict:
            return next(s for s in fl["steps"] if s["id"] == sid)

        def findings(cid: str) -> list[dict]:
            return c.get(f"/api/cases/{cid}/findings").json()["findings"]

        def lc(cid: str, f_: dict, action: str, **body) -> int:
            return c.post(f"/api/cases/{cid}/lifecycle",
                          json={"finding_key": f_["key"], "action": action, **body}).status_code

        print("a fresh case")
        fl = flow(Z)
        check([s["id"] for s in fl.get("steps", [])] == ORDER, "/flow returns the six steps in order")
        check(all(s["standards"] for s in fl["steps"]), "each step carries its standards")
        check(step(fl, "ingest")["state"] == "done", f"Ingest is done ({step(fl, 'ingest')['reason']})")
        fs = findings(Z)
        tracked = [f for f in fs if f["lifecycle"]["tracked"]]
        tri = step(fl, "triage")
        check(tri["state"] == "active" and tri["remaining"] == len(fs) == tri["total"],
              f"Triage waits on every finding ({tri['remaining']} of {tri['total']})")
        check(fl["recommended"] == "triage", "the recommended step is Triage")
        check(step(fl, "analyse")["state"] == "optional", "Analyse is optional and not run")
        check(step(fl, "report")["state"] == "blocked", f"Report is blocked: {step(fl, 'report')['reason']}")
        check(bool(tracked), f"the case has high/critical findings ({len(tracked)})")
        check(step(fl, "investigate")["state"] == "blocked",
              "Investigate is blocked while no high/critical finding is triaged")

        print("triage done")
        for f_ in fs:
            c.post(f"/api/cases/{Z}/review", json={"finding_key": f_["key"], "action": "accept"})
        fl = flow(Z)
        check(step(fl, "triage")["state"] == "done", "Triage is done when nothing is unreviewed")
        check(step(fl, "report")["state"] == "active", "the report gate opens")
        check(fl["recommended"] == "investigate", "the recommended step moves to Investigate")

        print("investigate, then respond")
        for f_ in tracked:
            lc(Z, f_, "assign", assignee=EMAIL)
            lc(Z, f_, "investigate")
        fl = flow(Z)
        check(step(fl, "investigate")["state"] == "done", "Investigate is done when none is still Open")
        check(fl["recommended"] == "respond" and step(fl, "respond")["remaining"] == len(tracked),
              f"Respond is next, with {len(tracked)} to resolve")
        codes = [lc(Z, f_, "resolve", classification="false_positive", summary="planted test data")
                 for f_ in tracked]
        check(all(code == 200 for code in codes), "every finding resolves")
        fl = flow(Z)
        check(step(fl, "respond")["state"] == "done", "Respond is done when all are Resolved")
        check(fl["recommended"] == "report", "the recommended step is Report")

        print("a rejected high/critical finding")
        ft = [f for f in findings(F) if f["lifecycle"]["tracked"]]
        if ft:
            c.post(f"/api/cases/{F}/review",
                   json={"finding_key": ft[0]["key"], "action": "reject", "reason_code": "misinterpretation"})
            fl = flow(F)
            inv, rsp = step(fl, "investigate"), step(fl, "respond")
            check(inv["total"] == len(ft) - 1, "it needs no investigation")
            check(rsp["remaining"] == len(ft) and "rejected but not closed" in rsp["reason"],
                  f"it still waits in Respond until closed ({rsp['reason']})")
        else:
            check(False, "the firewall case has a high/critical finding")

        print("evidence problem")
        custody.record(F, "integrity_failed", EMAIL, sha256="0" * 64, expected="1" * 64, purpose="test")
        ing = step(flow(F), "ingest")
        check(ing["state"] == "blocked" and "digest" in ing["reason"], f"Ingest is blocked: {ing['reason']}")

        print("graph without the AI")
        g = c.get(f"/api/cases/{Z}/graph")
        body = g.json() if g.status_code == 200 else {}
        check(g.status_code == 200 and body.get("graph", {}).get("edges"), "/graph returns the attack graph")
        check(bool(body.get("risk")), "...and the risk ranking")
        check(c.get("/api/cases/nope/flow").status_code == 404, "/flow of an unknown case is 404")
        check(c.get("/api/cases/nope/graph").status_code == 404, "/graph of an unknown case is 404")

    print()
    if FAILED:
        print(f"{len(FAILED)} FAILED")
        return 1
    print("CASE FLOW OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
