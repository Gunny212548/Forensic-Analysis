"""Ingest finished (story 3, specs/story3_ingest.md), end to end through the API.

    python tests/check_ingest.py <scratch dir> [--repo DIR]

Builds a throwaway store with two customers and drives the real app through
fastapi's TestClient:

- the question of an investigation: on the project for a case in one (shared by
  every case of it), on the case itself without one; each change a hash-chained
  line with old and new values; bad input refused (I1, I2);
- provenance per evidence item: saved, each change a custody line, the custody
  chain still intact; a bad zone, an unknown field, an unknown item refused (I3);
- declared time (I5-I7): a declared +00:00 moves only the events whose source
  text states no offset, by +7 h; a clock offset moves every event; clearing
  both gives back the first run's times exactly; `timezone-declared` replaces
  `timezone-unconfirmed`; nothing applies until a re-process;
- re-process (I8): refused while processing; review decisions survive it;
- the reproducibility record (I9): on every `processed` line, the same on two
  runs of the same code;
- duplicates (I10): named within a customer, never across customers;
- the Ingest step's warnings (I11), and the MCP get_case serving the same.

stdlib + the app's own dependencies; no network, no model.
"""

import argparse
import os
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
FAILED: list[str] = []
EMAIL, PW = "analyst@ingest.local", "ingest-throwaway-pw-1"

# Three events whose source text states no zone, two that state Z (UTC).
MIXED = (
    "2026-02-14T09:00:00 sshd[1]: Failed password for root from 10.9.9.9 port 1 ssh2\n"
    "2026-02-14T09:00:01 sshd[2]: Failed password for root from 10.9.9.9 port 2 ssh2\n"
    "2026-02-14T09:00:02 sshd[3]: Failed password for root from 10.9.9.9 port 3 ssh2\n"
    "2026-02-14T09:00:03Z sshd[4]: Failed password for root from 10.9.9.9 port 4 ssh2\n"
    "2026-02-14T09:00:04Z sshd[5]: Failed password for root from 10.9.9.9 port 5 ssh2\n"
)


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
    (scratch / "mixed.log").write_text(MIXED, encoding="utf-8")
    os.environ["DATA_DIR"] = str(store)
    subprocess.run([sys.executable, str(repo / "tools" / "create_user.py"), "add", EMAIL,
                    "--name", "analyst", "--role", "analyst", "--password-stdin"],
                   input=PW + "\n", text=True, capture_output=True, check=True)
    sys.path.insert(0, str(repo))

    from fastapi.testclient import TestClient

    from app import mcp_server
    from app.main import app
    from app.services import custody, hashchain, jobs, storage

    c = TestClient(app)
    with c:
        c.post("/api/auth/login", json={"email": EMAIL, "password": PW})

        def upload(path: Path, customer: str, project: str = "") -> dict:
            with open(path, "rb") as fh:
                return c.post("/api/upload", files={"file": (path.name, fh)},
                              data={"company_name": customer, "project_name": project}).json()

        def times(cid: str) -> dict[str, str]:
            rows = c.get(f"/api/cases/{cid}/events", params={"limit": 100, "offset": 0,
                                                              "only_flagged": False}).json()["events"]
            return {r["ts_raw"]: r["ts"] for r in rows}

        def ingest(cid: str) -> dict:
            return c.get(f"/api/cases/{cid}/ingest").json()

        def reprocess(cid: str, reason: str) -> int:
            code = c.post(f"/api/cases/{cid}/reprocess", json={"reason": reason}).status_code
            jobs.wait_idle(120)
            return code

        def actions(cid: str) -> list[str]:
            return [e["action"] for e in custody.entries(cid)]

        M = upload(scratch / "mixed.log", "Ingest Co", "Night shift")["case_id"]
        A = upload(uc / "nightfall-auth.log", "Ingest Co", "Night shift")["case_id"]
        L = upload(uc / "nightfall-firewall.csv", "Ingest Co")["case_id"]  # no project
        jobs.wait_idle(180)
        first = times(M)
        mm = storage.load_manifest(M)

        print("first run")
        check(mm["status"] == "ready", f"the mixed file is processed ({mm['status']})")
        ta = (mm.get("time_applied") or [{}])[0]
        check((ta.get("rows_with_offset"), ta.get("rows_without_offset")) == (2, 3),
              f"3 events state no zone, 2 do ({ta})")
        check(first.get("2026-02-14T09:00:00", "").startswith("2026-02-14 09:00:00"),
              f"no zone stated: taken as GMT+7 ({first.get('2026-02-14T09:00:00')})")
        check(first.get("2026-02-14T09:00:03Z", "").startswith("2026-02-14 16:00:03"),
              f"Z converted to GMT+7 ({first.get('2026-02-14T09:00:03Z')})")
        method1 = ingest(M)["method"] or {}
        check(len(method1.get("app_code_sha256", "")) == 64 and len(method1.get("rules_sha256", "")) == 64,
              "the processed line carries code and rule-set digests")
        check(method1.get("duckdb") and method1.get("profiles"), f"and DuckDB version and profiles ({method1.get('profiles')})")
        w = ingest(M)["warnings"]
        check(any("No question" in x for x in w), "warning: no question recorded")
        check(any("3 events state no time zone" in x for x in w), "warning: 3 events assumed GMT+7")
        check(any("provenance not recorded" in x for x in w), "warning: provenance not recorded")
        fl = c.get(f"/api/cases/{M}/flow").json()
        ing = next(s for s in fl["steps"] if s["id"] == "ingest")
        check(ing["state"] == "done" and ing["warnings"] == w, "the flow's Ingest step is done and carries the warnings")

        print("question")
        r = c.put(f"/api/cases/{M}/question", json={"question": "Did 10.9.9.9 get in?",
                                                    "addresses": "10.9.9.9, 10.10.1.5",
                                                    "window_from": "2026-02-14T00:00"})
        q = r.json()
        check(r.status_code == 200 and q["scope"] == "project", f"a case in a project: the project's question ({r.status_code})")
        check(q["question"]["addresses"] == ["10.9.9.9", "10.10.1.5"], "leads split and kept in order")
        check(q["updated_by"] == EMAIL, "who changed it is the signed-in account")
        check(ingest(A)["investigation"]["question"]["question"] == "Did 10.9.9.9 get in?",
              "another case of the same project shows the same question")
        project = storage.load_project(mm["company_id"], mm["project_id"])
        log = storage.project_log_path(project["company_id"], project["project_id"])
        v = hashchain.verify(log)
        check(v["intact"] and v["entries"] == 1, f"one hash-chained line in the project log ({v})")
        c.put(f"/api/cases/{A}/question", json={"question": "Did 10.9.9.9 get in, and how?"})
        entry = hashchain.entries(log)[-1]
        check(entry["changes"]["question"] == ["Did 10.9.9.9 get in?", "Did 10.9.9.9 get in, and how?"],
              "the line holds the old and the new value")
        check(c.put(f"/api/cases/{M}/question", json={"window_from": "2026-02-15T00:00",
                                                      "window_to": "2026-02-14T00:00"}).status_code == 400,
              "a window that ends before it starts is refused")
        check(c.put(f"/api/cases/{M}/question", json={"verdict": "x"}).status_code == 400,
              "an unknown field is refused")
        check(c.put(f"/api/cases/{M}/question", json={"window_from": "yesterday"}).status_code == 400,
              "a window time that is not ISO 8601 is refused")
        r = c.put(f"/api/cases/{L}/question", json={"question": "What did the firewall see?"})
        check(r.status_code == 200 and r.json()["scope"] == "case", "a case without a project: its own question")
        check("question" in actions(L), "and the change is a custody line of that case")
        check(not any("No question" in x for x in ingest(M)["warnings"]), "the no-question warning is gone")

        print("provenance")
        bad = [({"source_timezone": "+7"}, 400, "a zone that is not +HH:MM"),
               ({"source_timezone": "Asia/Bangkok"}, 400, "a named zone (Q35)"),
               ({"clock_offset_seconds": "a minute"}, 400, "a clock offset that is not seconds"),
               ({"clock_offset_seconds": 10**7}, 400, "a clock offset over a week"),
               ({"colour": "red"}, 400, "an unknown field")]
        for body, code, what in bad:
            check(c.put(f"/api/cases/{M}/provenance", json=body).status_code == code, f"refused: {what}")
        check(c.put(f"/api/cases/{M}/provenance", params={"item": "other.log"},
                    json={"source_system": "x"}).status_code == 404, "refused: an item that is not in the case")
        r = c.put(f"/api/cases/{M}/provenance", json={
            "source_system": "jump host js-01", "export_method": "scp of /var/log/auth.log, no filter",
            "exported_by": "IT admin", "exported_at": "2026-02-16 10:00", "source_timezone": "+00:00"})
        p = r.json()
        check(r.status_code == 200 and p["reprocess_needed"], "saved; a declared zone needs a re-process")
        check(times(M) == first, "nothing moves before the re-process")
        last = custody.entries(M)[-1]
        check(last["action"] == "provenance" and last["changes"]["source_timezone"] == [None, "+00:00"],
              "a custody line with the old and new value")
        check(custody.verify_chain(M)[0], "the custody chain still verifies")
        check(any("not been applied" in x for x in ingest(M)["warnings"]), "warning: re-process to apply")

        print("re-process with a declared zone")
        storage.update_case(M, status="processing")
        check(c.post(f"/api/cases/{M}/reprocess", json={}).status_code == 409, "refused while processing")
        storage.update_case(M, status="ready")
        check(reprocess(M, "source zone declared") == 200, "re-process accepted")
        second = times(M)
        check(second["2026-02-14T09:00:00"].startswith("2026-02-14 16:00:00"),
              f"no zone stated -> read as UTC -> +7 h ({second['2026-02-14T09:00:00']})")
        check(second["2026-02-14T09:00:03Z"] == first["2026-02-14T09:00:03Z"], "a stated Z is not moved")
        iv = ingest(M)
        check(not iv["reprocess_needed"], "nothing left to apply")
        check(iv["items"][0]["time_applied"]["rows_shifted"] == 3, "3 events shifted, recorded")
        check(not any("state no time zone" in x for x in iv["warnings"]), "the assumed-GMT+7 warning is gone")
        check("reprocess_requested" in actions(M), "the re-process request is a custody line")
        flags = [f for fd in c.get(f"/api/cases/{A}/findings").json()["findings"] for f in fd.get("flags", [])]
        check("timezone-declared" not in flags, "another case is not affected")

        print("clock offset, then clearing both")
        c.put(f"/api/cases/{M}/provenance", json={"clock_offset_seconds": 60})
        reprocess(M, "clock offset declared")
        third = times(M)
        check(third["2026-02-14T09:00:00"].startswith("2026-02-14 15:59:00"), "zone + clock: 16:00:00 - 60 s")
        check(third["2026-02-14T09:00:03Z"].startswith("2026-02-14 15:59:03"), "the clock moves a stated Z too")
        c.put(f"/api/cases/{M}/provenance", json={"source_timezone": "", "clock_offset_seconds": ""})
        reprocess(M, "settings cleared")
        check(times(M) == first, "cleared: every time is exactly the first run's again")
        method4 = ingest(M)["method"] or {}
        same = {k: method1.get(k) == method4.get(k) for k in ("app_code_sha256", "rules_sha256", "intel_feeds",
                                                              "duckdb", "profiles")}
        check(all(same.values()), f"the reproducibility record is the same on both runs ({same})")
        check(sum(a == "processed" for a in actions(M)) == 4, "four processed lines, one per run")

        print("decisions survive a re-process")
        fds = c.get(f"/api/cases/{A}/findings").json()["findings"]
        key = fds[0]["key"] if fds else None
        check(bool(key), f"the planted auth log raises findings ({len(fds)})")
        if key:
            c.post(f"/api/cases/{A}/review", json={"finding_key": key, "action": "accept", "note": "seen"})
            reprocess(A, "check decisions survive")
            after = {f["key"]: f["review"]["status"] for f in c.get(f"/api/cases/{A}/findings").json()["findings"]}
            check(after.get(key) == "Accepted", f"the decision is still there ({after.get(key)})")

        print("duplicates")
        D = upload(scratch / "mixed.log", "Ingest Co")
        check([d["case_id"] for d in D.get("duplicate_of") or []] == [M], "same customer: the earlier case is named")
        X = upload(scratch / "mixed.log", "Other Co")
        check(not X.get("duplicate_of"), "another customer: nothing named - stores never meet")
        jobs.wait_idle(120)
        check(any(M in x for x in ingest(D["case_id"])["warnings"]), "the duplicate is a warning on its Ingest step")
        check(custody.entries(D["case_id"])[0].get("duplicate_of") == [M], "and on its acquired custody line")

        print("MCP")
        got = mcp_server.tool_get_case({"case_id": M})
        check(got["investigation"]["question"]["question"] == "Did 10.9.9.9 get in, and how?"
              and got["provenance"]["mixed.log"]["source_system"] == "jump host js-01",
              "get_case serves the question and the provenance")

    print()
    print(f"{len(FAILED)} FAILED" if FAILED else "INGEST OK")
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
