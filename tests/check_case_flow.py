"""The case flow (IAI-89, then story 1 - specs/story1_case_flow_steps.md), end to
end through the API.

    python tests/check_case_flow.py <scratch dir> [--repo DIR]

Builds a throwaway store, uploads gen_usecase's planted attack (both files in
one zip, and the firewall alone) and walks a case through its six steps -
Ingest, Timeline, Attack events, Attack timeline, Attack path, Report:

- the steps and their order, and that every step cites a standard that was
  read - one listed under "Read" in docs/standards/SOURCES.md (R4);
- no Respond step: no status workflow and no assignee in the flow (revisions 2
  and 3 of the case flow design);
- states computed from the case's own records: Ingest and Timeline done,
  Attack events waiting on the undecided suggestions, Attack timeline waiting
  for a confirmed one, Report's gate closed until all are decided;
- confirming every suggestion completes Attack events, fills the Attack
  timeline and opens the Report; rejecting them all leaves an empty timeline
  that says so;
- the Timeline step's events come in event-time order;
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
ORDER = ["ingest", "timeline", "attack-events", "attack-timeline", "attack-path", "report"]


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

        print("a fresh case")
        fl = flow(Z)
        check([s["id"] for s in fl.get("steps", [])] == ORDER, "/flow returns the six steps in order")
        check(not any(s["id"] in ("respond", "triage", "investigate", "analyse") for s in fl["steps"]),
              "no Respond, Triage, Investigate or Analyse step")
        check(all(s["standards"] for s in fl["steps"]), "each step carries its standards")
        check(step(fl, "ingest")["state"] == "done", f"Ingest is done ({step(fl, 'ingest')['reason']})")
        check(step(fl, "timeline")["state"] == "done", "Timeline is a view and never blocks")
        fs = findings(Z)
        ae = step(fl, "attack-events")
        check(bool(fs) and ae["state"] == "active" and ae["remaining"] == len(fs) == ae["total"],
              f"Attack events waits on every suggestion ({ae['remaining']} of {ae['total']})")
        check(fl["recommended"] == "attack-events", "the recommended step is Attack events")
        check(step(fl, "attack-timeline")["state"] == "not_started",
              "Attack timeline waits for a confirmed event")
        check(step(fl, "report")["state"] == "blocked", f"Report is blocked: {step(fl, 'report')['reason']}")

        print("every suggestion confirmed")
        for f_ in fs:
            c.post(f"/api/cases/{Z}/review", json={"finding_key": f_["key"], "action": "accept"})
        fl = flow(Z)
        check(step(fl, "attack-events")["state"] == "done", "Attack events is done when nothing is undecided")
        at = step(fl, "attack-timeline")
        check(at["state"] == "done" and at["total"] == len(fs),
              f"Attack timeline holds the {len(fs)} confirmed groups ({at['reason']})")
        check(step(fl, "report")["state"] == "active", "the report gate opens")
        check(fl["recommended"] == "report", "the recommended step is Report")

        print("every suggestion rejected")
        ff = findings(F)
        for f_ in ff:
            c.post(f"/api/cases/{F}/review",
                   json={"finding_key": f_["key"], "action": "reject", "reason_code": "misinterpretation"})
        fl = flow(F)
        at = step(fl, "attack-timeline")
        check(step(fl, "attack-events")["state"] == "done" and at["total"] == 0
              and "No attack event was confirmed" in at["reason"],
              f"nothing confirmed, and the attack timeline says so ({at['reason']})")

        print("the timeline is in event-time order")
        r = c.get(f"/api/cases/{Z}/events", params={"only_flagged": "false", "order": "time", "limit": 1000})
        times = [e["ts"] for e in r.json()["events"]]
        parsed = [t for t in times if t]
        check(r.status_code == 200 and parsed == sorted(parsed) and times[:len(parsed)] == parsed,
              f"{len(times)} events, ordered by time, unparsed last")
        check(c.get(f"/api/cases/{Z}/events", params={"order": "bogus"}).status_code == 422,
              "an unknown order is refused")

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
