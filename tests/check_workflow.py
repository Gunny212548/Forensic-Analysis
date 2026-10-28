"""The finding workflow, end to end through the API (Sprint 3: IAI-42..49, 78, 79).

    python tests/check_workflow.py <scratch dir> [--repo DIR]

Builds a throwaway store, uploads gen_usecase's planted attack (the auth log,
the firewall CSV, and both in one zip) for one customer and the firewall for a
second, and checks what an analyst relies on:

- threshold (IAI-42): only high / critical findings enter the workflow; the
  others stay in the case's findings without a lifecycle;
- entry and traceability (IAI-45): a workflow finding is Open with no assignee,
  has an id FD-YYYY-nnnn that never changes (not even when the case is
  processed again), and its events - with the file each came from, the zip
  member included - can be fetched;
- related findings (IAI-43): pivot hosts chain findings, a shared final target
  does not, an attacked account chains a spray (unit tests of related.chains,
  then the planted attack);
- findings table (IAI-46): columns, the count per severity, filters, paging,
  numbering per customer;
- workflow (IAI-47, 49): every refusal and both paths (a true positive through
  Contained; a false / benign positive straight from Investigating, out of MTTC);
- assignment (IAI-48): only accounts, and it shows in the activity feed;
- badge and Customers (IAI-78, 79): the open count follows status, and a case
  is open while a workflow finding is not Resolved - not while a finding is
  unreviewed.

stdlib + the app's own dependencies (fastapi TestClient); no network.
"""

import argparse
import os
import re
import subprocess
import sys
import zipfile
from pathlib import Path
os.environ.setdefault("TRIAGE_ENABLED", "0")  # rules are measured here, not the AI review (triage.py)

REPO = Path(__file__).resolve().parent.parent
FAILED: list[str] = []
FD = re.compile(r"^FD-\d{4}-\d{4}$")
A_EMAIL, A_PW = "analyst@workflow.local", "workflow-throwaway-pw-1"
B_EMAIL, B_PW = "lead@workflow.local", "workflow-throwaway-pw-2"
AUTH_RULES = {"R2000", "R2005", "R2006", "R2008", "R2009"}


def check(ok: bool, what: str) -> None:
    print(f"  {'ok  ' if ok else 'FAIL'} {what}")
    if not ok:
        FAILED.append(what)


def unit_related() -> None:
    sys.path.insert(0, str(REPO))
    from app.services import db, related

    print("related findings: the grouping rules")

    def row(rid, src, dsts=(), user=None, lvl=4):
        return {"rid": rid, "srcip": src, "username": user, "dstips": list(dsts), "lvl": lvl,
                "level": "high"}

    rows = [
        row("R2002", "1.1.1.1", ["2.2.2.2"]),           # attacker -> victim
        row("R3001", "2.2.2.2", ["3.3.3.3"]),           # victim pivots onward
        row("R3003", "9.9.9.9", ["3.3.3.3"]),           # only shares the final target
        row("R2005", "5.5.5.5", [], user="alice"),      # guessing on an account
        row("R2006", "6.6.6.6", [], user="alice"),
        row("R2005", "7.7.7.7", [], user="bob"),        # another account
    ]
    k = lambda r: related.finding_key(r["rid"], r["srcip"], r["username"])  # noqa: E731
    out = related.chains(rows)
    check(set(x["key"] for x in out[k(rows[0])]["related"]) == {k(rows[1])},
          "a finding is chained to the one that starts at the host it hit (pivot)")
    check(k(rows[1]) in out and k(rows[0]) in [x["key"] for x in out[k(rows[1])]["related"]],
          "the relation is symmetric")
    check(k(rows[2]) not in out, "sharing only the final target does NOT make findings related")
    check(k(rows[2]) not in [x["key"] for x in out[k(rows[1])]["related"]],
          "...and the unrelated one is not listed on the chained ones either")
    check({x["key"] for x in out[k(rows[3])]["related"]} == {k(rows[4])},
          "a spray and the logins on the same account are related by the account")
    check(k(rows[5]) not in out, "a different account is not")
    check(related.finding_key("R1", None, None) == db.finding_key("R1", None, None),
          "related.finding_key spells a key the way db.finding_key does")
    big = [row("R2005", f"10.0.0.{i}", [], user="x") for i in range(30)]
    one = related.chains(big)[related.finding_key("R2005", "10.0.0.0", "x")]
    check(one["related_count"] == 29 and len(one["related"]) == related.LIST_CAP,
          "a long chain lists a capped number and still says how many there are")


def unit_fixes() -> None:
    """The review fixes that need no store: log type of line logs and zips, the
    fingerprint of a growing file, the id year in Bangkok time."""
    sys.path.insert(0, str(REPO))
    import tempfile
    from datetime import datetime, timezone
    from app.services import case_views, filestamp, finding_ids

    print("review fixes: log type, cache fingerprint, id year")
    line = {"file_kind": "log", "mapping": {"line_profiles": [{"name": "OpenSSH sshd"}]}}
    check(case_views.log_type(line) == "OpenSSH sshd", "a line log names the formats it was read by")
    check(case_views.log_type({"file_kind": "csv", "mapping": {"name": "PAN-OS traffic log"}}) == "PAN-OS traffic log",
          "a table names its documented profile")
    check(case_views.log_type({"file_kind": "csv"}) == "csv", "no mapping falls back to the file kind")
    zipm = {"file_kind": "zip", "members": [
        {"row_id_first": 0, "row_id_last": 9, "kind": "csv", "mapping": {"name": "PAN-OS traffic log"}},
        {"row_id_first": 10, "row_id_last": 19, "kind": "log",
         "mapping": {"line_profiles": [{"name": "OpenSSH sshd"}]}}]}
    check(case_views.log_type(zipm, 5) == "PAN-OS traffic log" and case_views.log_type(zipm, 12) == "OpenSSH sshd",
          "a zip answers from the member holding the row")
    check(case_views.log_type(zipm) == "PAN-OS traffic log (+1)", "and without a row, from all its members")

    with tempfile.TemporaryDirectory() as d:
        f = Path(d) / "log.jsonl"
        gone = filestamp.of(f)
        f.write_bytes(b"a\n")
        one = filestamp.of(f)
        f.write_bytes(b"a\nb\n")
        mt = os.stat(f).st_mtime_ns
        f.write_bytes(b"a\nb\nc\n")
        os.utime(f, ns=(mt, mt))
        check(gone != one and one != filestamp.of(f), "a missing file, a file and a longer file differ")
        two = filestamp.of(f)
        f.write_bytes(b"a\nb\nd\nx\n")
        os.utime(f, ns=(mt, mt))
        check(filestamp.of(f) != two, "a longer file differs even when its mtime did not move")

    import app.services.custody as custody_mod
    real = custody_mod.created_at
    try:
        custody_mod.created_at = lambda cid, m=None: "2026-12-31T18:00:00+00:00"
        check(finding_ids._year("c", {}) == "2027", "an upload after midnight in Bangkok takes the new year")
        custody_mod.created_at = lambda cid, m=None: "2026-12-31T16:59:00+00:00"
        check(finding_ids._year("c", {}) == "2026", "and one before it keeps the old")
    finally:
        custody_mod.created_at = real


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
    for email, pw in ((A_EMAIL, A_PW), (B_EMAIL, B_PW)):
        subprocess.run([sys.executable, str(repo / "tools" / "create_user.py"), "add", email,
                        "--name", email.split("@")[0], "--role", "manager", "--password-stdin"],
                       input=pw + "\n", text=True, capture_output=True, check=True)
    sys.path.insert(0, str(repo))
    unit_related()
    unit_fixes()

    from fastapi.testclient import TestClient

    from app.main import app
    from app.services import jobs, lifecycle, storage

    c = TestClient(app)
    with c:
        c.post("/api/auth/login", json={"email": A_EMAIL, "password": A_PW})

        def upload(path: Path, company: str) -> dict:
            with open(path, "rb") as fh:
                return c.post("/api/upload", files={"file": (path.name, fh)},
                              data={"company_name": company, "project_name": company}).json()

        a = upload(uc / "nightfall-auth.log", "Workflow Co")
        f = upload(uc / "nightfall-firewall.csv", "Workflow Co")
        z = upload(uc / "nightfall.zip", "Workflow Co")
        o = upload(uc / "nightfall-firewall.csv", "Other Co")
        jobs.wait_idle(180)
        A, F, Z, O = a["case_id"], f["case_id"], z["case_id"], o["case_id"]
        W, OTHER = a["company_id"], o["company_id"]
        for cid in (A, F, Z, O):
            st = c.get(f"/api/cases/{cid}").json()["status"]
            if st != "ready":
                check(False, f"{cid} processed ({st})")

        def findings(cid: str) -> list[dict]:
            return c.get(f"/api/cases/{cid}/findings").json()["findings"]

        def tracked(cid: str) -> list[dict]:
            return [x for x in findings(cid) if x["lifecycle"]["tracked"]]

        print("threshold and entry (IAI-42, 45)")
        fw = findings(F)
        tf = [x for x in fw if x["lifecycle"]["tracked"]]
        below = [x for x in fw if not x["lifecycle"]["tracked"]]
        check(len(tf) >= 2, f"the planted attack has workflow findings ({len(tf)})")
        check(all(x["lvl"] >= lifecycle.ADMIT_LEVEL for x in tf) and all(x["lvl"] < lifecycle.ADMIT_LEVEL for x in below),
              "exactly the high / critical findings are in the workflow")
        check(len(below) > 0 and all(x["lifecycle"] == {"tracked": False} for x in below),
              "findings below the threshold stay visible, without a lifecycle")
        check(all(x["lifecycle"]["status"] == "Open" and x["lifecycle"]["assignee"] is None for x in tf),
              "a finding enters the workflow Open with no assignee")
        check(all(FD.match(x["fd"] or "") for x in tf) and all(x["fd"] is None for x in below),
              "workflow findings have FD-YYYY-nnnn ids; the others have none")
        every = [x["fd"] for cid in (A, F, Z) for x in tracked(cid)]
        check(len(every) == len(set(every)) and len(every) > 0, f"ids are unique within a customer ({len(every)})")
        other = [x["fd"] for x in tracked(O)]
        check(any(i.endswith("-0001") for i in other), "a second customer is numbered from 0001 on its own")

        print("source events (IAI-45)")
        big = max(tf, key=lambda x: x["cnt"])
        r = c.get(f"/api/cases/{F}/findings/events", params={"key": big["key"], "limit": 1000}).json()
        check(r["total"] == big["cnt"] == len(r["rows"]), f"all {big['cnt']} events behind the finding are returned")
        check(r["rows"][0]["row_id"] == big["sample_row_id"], "the first one is the finding's first event")
        check(all(x["source_file"] == "nightfall-firewall.csv" for x in r["rows"]), "each names its source file")
        check(r["evidence_sha256"] == c.get(f"/api/cases/{F}").json()["evidence"]["sha256"],
              "and the evidence digest of the file")
        if big["cnt"] > 1:
            p = c.get(f"/api/cases/{F}/findings/events", params={"key": big["key"], "limit": 1, "offset": 1}).json()
            check(len(p["rows"]) == 1 and p["rows"][0]["row_id"] == r["rows"][1]["row_id"], "paging returns the next event")
        check(c.get(f"/api/cases/{F}/findings/events", params={"key": "nonsense"}).status_code == 400, "a malformed key is 400")
        check(c.get(f"/api/cases/{F}/findings/events", params={"key": "R9999|1.2.3.4|"}).status_code == 404, "an unknown finding is 404")
        check(c.get("/api/cases/case-20200101-000000-deadbeef/findings/events", params={"key": big["key"]}).status_code == 404,
              "an unknown case is 404")
        ok_zip = True
        for x in tracked(Z):
            rows = c.get(f"/api/cases/{Z}/findings/events", params={"key": x["key"], "limit": 1000}).json()["rows"]
            want = "nightfall-auth.log" if x["rid"] in AUTH_RULES else "nightfall-firewall.csv"
            ok_zip &= bool(rows) and all(y["source_file"] == want for y in rows)
        check(ok_zip, "in a zip every event names the member it came from")

        print("related findings on the planted attack (IAI-43)")
        by_rid = {x["rid"]: x for x in fw}
        scan = by_rid.get("PAN-SCAN-1")  # R2002 on Palo Alto rows since story 4
        check(scan is not None and scan["related_count"] > 0, "the port scan is chained to what 10.10.1.5 did next")
        if scan:
            rel_src = {x["srcip"] for x in scan["related"]}
            check("10.10.1.5" in rel_src and "10.10.1.9" not in rel_src,
                  "through the pivot host - and the benign host is not in the chain")
        rel = {x["key"]: {y["key"] for y in x["related"]} for x in fw if x["related_count"] <= len(x["related"])}
        sym = all(a_ in rel.get(b_, {a_}) for a_, bs in rel.items() for b_ in bs)
        check(sym, "every relation is listed from both sides")
        check(all(x["related_count"] == 0 and x["chain"] is None for x in findings(A)),
              "the auth log alone has no pivot, so no finding is related")

        print("findings table (IAI-46, 78)")
        t = c.get("/api/findings").json()
        cols = {"fd", "key", "case_id", "company_name", "name", "host", "level", "status", "assignee",
                "log_type", "source_file", "detected"}
        check(t["total"] == t["scope_total"] and t["total"] == len(t["rows"]) and t["total"] > 0,
              f"every workflow finding of every customer is listed ({t['total']})")
        check(all(cols <= set(x) for x in t["rows"]), "each row has the columns of the design")
        check(not any(x["log_type"] in ("log", "zip", "unknown") for x in t["rows"]),
              "the log type is a log source, not the file kind: " + ", ".join(sorted({x["log_type"] for x in t["rows"]})))
        # A reader in another process (the MCP server) must not write the id
        # registry: it shows the ids that exist and never calls ensure().
        from app.services import case_views, finding_ids, storage
        real_ensure = finding_ids.ensure

        def no_writes(*a, **k):
            raise AssertionError("a read-only view assigned ids")
        finding_ids.ensure = no_writes
        try:
            ro = case_views.findings_view(A, storage.load_manifest(A), assign_ids=False)
            check(all(x["fd"] for x in ro if x["lifecycle"]["tracked"]),
                  "a read-only view shows the ids already assigned without assigning any")
        except AssertionError as exc:
            check(False, str(exc))
        finally:
            finding_ids.ensure = real_ensure
        check(sum(t["by_severity"].values()) == t["scope_total"], "the header counts per severity add up")
        check(all(t["by_severity"][s] == sum(1 for x in t["rows"] if x["level"] == s) for s in t["by_severity"]),
              "and match the rows")
        check(t["open_count"] == t["scope_total"], "all are open to begin with (the Findings badge)")
        lv = [x["lvl"] for x in t["rows"]]
        check(lv == sorted(lv, reverse=True), "most severe first")
        check({x["company_name"] for x in t["rows"]} == {"Workflow Co", "Other Co"}, "both customers are shown")
        tw = c.get("/api/findings", params={"company_id": W}).json()
        check(tw["scope_total"] == len(every) and {x["company_id"] for x in tw["rows"]} == {W},
              "scoped to one customer, only its findings")
        check(c.get("/api/findings", params={"company_id": OTHER}).json()["scope_total"] == len(other), "and the other's")
        crit = c.get("/api/findings", params={"severity": "critical"}).json()
        check(crit["total"] == t["by_severity"]["critical"] and all(x["level"] == "critical" for x in crit["rows"]),
              "severity filter")
        check(crit["scope_total"] == t["scope_total"], "...which leaves the header counts alone")
        check(c.get("/api/findings", params={"status": "Resolved"}).json()["total"] == 0, "status filter")
        host = t["rows"][0]["host"]
        qq = c.get("/api/findings", params={"q": host}).json()
        check(qq["total"] > 0 and all(host in (x["host"] or "") or host in str(x.values()) for x in qq["rows"]),
              "text search finds a host")
        pg = c.get("/api/findings", params={"limit": 2, "offset": 1}).json()
        check([x["key"] + x["case_id"] for x in pg["rows"]] == [x["key"] + x["case_id"] for x in t["rows"][1:3]],
              "paging")
        check(c.get("/api/findings", params={"status": "Done"}).status_code == 400, "an unknown status is 400")
        check(c.get("/api/findings", params={"severity": "extreme"}).status_code == 400, "an unknown severity is 400")
        check(c.get("/api/findings", params={"company_id": "co-000000000000"}).status_code == 404, "an unknown customer is 404")
        check(c.get("/api/findings", params={"q": "x" * 300}).status_code == 422, "an oversized search is refused")

        print("the status workflow (IAI-47, 48, 49)")
        f1, f2 = tf[0], tf[1]

        def lc(cid, f_, action, **body):
            return c.post(f"/api/cases/{cid}/lifecycle", json={"finding_key": f_["key"], "action": action, **body})

        def state(cid, f_):
            return next(x for x in findings(cid) if x["key"] == f_["key"])["lifecycle"]

        open0 = c.get("/api/findings", params={"company_id": W}).json()["open_count"]
        check(lc(F, f1, "investigate").status_code == 400, "cannot investigate without an assignee")
        check(lc(F, f1, "assign", assignee="nobody@nowhere.local").status_code == 400, "only an account can be assigned")
        below_key = {"key": below[0]["key"]}
        check(lc(F, below_key, "assign", assignee=B_EMAIL).status_code == 400, "a finding below the threshold has no workflow")
        check(lc(F, f1, "resolve", classification="false_positive", summary="x").status_code == 400, "cannot close an Open finding")
        r = lc(F, f1, "assign", assignee=B_EMAIL)
        check(r.status_code == 200 and state(F, f1)["assignee"] == B_EMAIL, "assigned to an account")
        feed = c.get("/api/overview", params={"company_id": W}).json()["recent"]
        check(any(e["kind"] == "lifecycle" and "assigned" in e["text"] and B_EMAIL in e["text"] for e in feed),
              "the assignment is in the activity feed")
        check(lc(F, f1, "investigate").status_code == 200 and state(F, f1)["status"] == "Investigating", "Open -> Investigating")
        check(lc(F, f1, "resolve", classification="benign_true_positive", summary="expected").status_code == 400,
              "cannot close a finding nobody has reviewed")
        c.post(f"/api/cases/{F}/review", json={"finding_key": f1["key"], "action": "accept"})
        check(lc(F, f1, "resolve", classification="false_positive").status_code == 400, "a summary is required")
        check(lc(F, f1, "resolve", classification="maybe", summary="x").status_code == 400, "a known classification is required")
        check(lc(F, f1, "resolve", classification="true_positive", summary="x").status_code == 400,
              "a true positive cannot skip Contained")
        r = lc(F, f1, "resolve", classification="benign_true_positive", summary="admin task, expected")
        s1 = state(F, f1)
        check(r.status_code == 200 and s1["status"] == "Resolved" and s1["classification"] == "benign_true_positive",
              "a benign positive closes straight from Investigating")
        check(all(h.get("ts") for h in s1["history"]) and [h["to"] for h in s1["history"] if h["to"]] == ["Investigating", "Resolved"],
              "every transition is timestamped")
        ls = c.get(f"/api/cases/{F}/findings").json()["lifecycle_summary"]
        check(ls["mttc_n"] == 0 and ls["mttc_seconds"] is None, "...and it is out of MTTC")
        open1 = c.get("/api/findings", params={"company_id": W}).json()["open_count"]
        check(open1 == open0 - 1, f"the open count drops by one ({open0} -> {open1})")

        check(lc(F, f2, "assign", assignee=B_EMAIL).status_code == 200 and lc(F, f2, "investigate").status_code == 200,
              "second finding: assigned and under investigation")
        check(lc(F, f2, "contain").status_code == 400, "containing needs the actions recorded")
        r = lc(F, f2, "contain", containment_actions="blocked 203.0.113.77 at the edge")
        check(r.status_code == 200 and state(F, f2)["status"] == "Contained" and state(F, f2)["contained_at"],
              "Investigating -> Contained, with a timestamp")
        c.post(f"/api/cases/{F}/review", json={"finding_key": f2["key"], "action": "accept"})
        r = lc(F, f2, "resolve", classification="true_positive", summary="exfiltration confirmed and blocked")
        check(r.status_code == 200 and state(F, f2)["status"] == "Resolved", "a true positive closes from Contained")
        ls = c.get(f"/api/cases/{F}/findings").json()["lifecycle_summary"]
        check(ls["mttc_n"] == 1 and ls["mttc_seconds"] is not None and ls["mttc_seconds"] >= 0, "and counts towards MTTC")
        check(c.get("/api/findings", params={"company_id": W}).json()["open_count"] == open1 - 1,
              "closing the second one lowers the open count again")
        check(lc(F, f2, "reopen").status_code == 400, "reopening needs a reason")
        check(lc(F, f2, "reopen", note="new evidence").status_code == 200 and state(F, f2)["status"] == "Investigating",
              "a resolved finding can be reopened with a reason")
        check(c.get("/api/findings", params={"company_id": W}).json()["open_count"] == open1, "and reopening raises it back")

        print("a finding keeps its id and status when the case is processed again")
        ids_before = {x["key"]: x["fd"] for x in tracked(F)}
        st_before = {x["key"]: x["lifecycle"]["status"] for x in tracked(F)}
        storage.update_case(F, status="queued")
        jobs.submit(F, storage.raw_path(F, "csv"), "csv")
        jobs.wait_idle(120)
        check({x["key"]: x["fd"] for x in tracked(F)} == ids_before, "same ids")
        check({x["key"]: x["lifecycle"]["status"] for x in tracked(F)} == st_before, "same statuses")

        print("Customers: open while a suggestion is not decided (the report gate, 2026-10-27)")

        def row(company_id: str) -> dict:
            return next(x for x in c.get("/api/companies/summary").json()["customers"] if x["company_id"] == company_id)

        r0 = row(OTHER)
        all_o = findings(O)
        top_level = max(all_o, key=lambda x: x["lvl"] or 0)["level"]
        check(r0["open"] == 1 and r0["closed"] == 0 and r0["open_severity"] == top_level,
              f"a case with undecided suggestions is open at the worst one ({r0['open_severity']})")
        for x in all_o:
            if x["review"]["status"] == "Unreviewed":
                c.post(f"/api/cases/{O}/review", json={"finding_key": x["key"], "action": "accept"})
        r1 = row(OTHER)
        check(c.get(f"/api/cases/{O}/findings").json()["ready_for_report"], "(every suggestion of the case decided)")
        check(r1["open"] == 0 and r1["closed"] == 1 and r1["open_severity"] is None,
              "closed once every suggestion is decided - whatever the status workflow says")
        keep = min(all_o, key=lambda x: x["lvl"] or 0)
        c.post(f"/api/cases/{O}/review", json={"finding_key": keep["key"], "action": "unreview"})
        r2 = row(OTHER)
        check(r2["open"] == 1 and r2["open_severity"] == keep["level"],
              f"undoing one decision opens it again, at that suggestion's level ({keep['level']})")
        auth_row = row(W)
        check(auth_row["open"] >= 1, "the other customer is untouched")

        print("Overview detection areas")
        from app.services import areas as areas_mod, rules as rules_mod
        check(all(len([a for a in areas_mod.AREAS if rid in a["rids"]]) == 1 for rid in rules_mod.RULE_LABELS),
              "every rule belongs to exactly one area")
        ov = c.get("/api/overview").json()
        ar = ov["areas"]
        check([a["id"] for a in ar] == list(areas_mod.AREA_IDS), "six areas, in order")
        listing = c.get("/api/findings", params={"limit": 500}).json()
        check(sum(a["open"] for a in ar) == ov["totals"]["open_findings"] == listing["open_count"],
              f"the open numbers on the cards add up to the Findings badge ({listing['open_count']})")
        check(all(sum(a["open_by"].values()) == a["open"] for a in ar), "open findings by level add up per card")
        every_case = [x for cid in (A, F, Z, O) for x in findings(cid)]
        check(sum(sum(a["total"].values()) for a in ar) == len(every_case),
              f"Total counts every finding of every case ({len(every_case)})")
        open_new = sum(1 for x in every_case if x["lifecycle"]["tracked"] and x["lifecycle"]["status"] == "Open")
        check(sum(sum(a["new"].values()) for a in ar) == open_new == ov["totals"]["new_findings"],
              f"New counts the findings still Open ({open_new})")
        undecided = sum(1 for x in every_case if x.get("area") and x["review"]["status"] == "Unreviewed")
        check(sum(a["undecided"] for a in ar) == undecided,
              f"Undecided counts what the cases' Attack events have not decided ({undecided})")
        per_case = {cid: findings(cid) for cid in (A, F, Z, O)}
        check(all(a["case_id"] is None if not sum(a["total"].values()) else
                  sum(1 for x in per_case[a["case_id"]] if x.get("area") == a["id"])
                  == max(sum(1 for x in fs if x.get("area") == a["id"]) for fs in per_case.values())
                  for a in ar),
              "a card opens the case holding most of its area's suggestions")
        check(all(len(a["trend"]) == len(ov["trend_days"]) for a in ar) and len(ov["trend_days"]) > 0,
              "every card has one trend value per day on a shared axis")
        dated = sum(1 for x in every_case if x.get("area") and x.get("ts_first"))
        check(sum(sum(a["trend"]) for a in ar) == dated,
              f"the trend counts every finding first seen per day, the whole span ({dated}) - as the case page")
        by_area = c.get("/api/findings", params={"area": "malware-c2"}).json()
        check(by_area["total"] > 0 and all(x["area"] == "malware-c2" for x in by_area["rows"]),
              "a card opens the Findings page on its area")
        check(by_area["total"] == next(a for a in ar if a["id"] == "malware-c2")["open"] + sum(
            1 for x in by_area["rows"] if x["status"] == "Resolved"),
            "and the area's open count matches that list")
        check(c.get("/api/findings", params={"area": "nope"}).status_code == 400, "an unknown area is 400")
        scoped = c.get("/api/overview", params={"company_id": OTHER}).json()
        check(scoped["totals"]["open_findings"] == c.get("/api/findings", params={"company_id": OTHER}).json()["open_count"],
              "scoped to one customer, the cards follow it")

        print("Overview: by customer")
        bc = ov["by_customer"]
        check({r["company_id"] for r in bc} >= {W, OTHER}, "every customer has a row")
        for key in ("cases", "unreviewed", "reviewable", "open_cases"):
            check(sum(r[key] for r in bc) == ov["totals"][key],
                  f"the rows' {key} add up to the page's total ({ov['totals'][key]})")
        for cid in (W, OTHER):
            one = c.get("/api/overview", params={"company_id": cid}).json()
            r = next(x for x in bc if x["company_id"] == cid)
            check(r["unreviewed"] == one["totals"]["unreviewed"] and r["open_cases"] == one["totals"]["open_cases"]
                  and r["areas"] == {a["id"]: sum(a["total"].values()) for a in one["areas"] if sum(a["total"].values())},
                  f"{r['name']}'s row says what its own Overview says")
            check([x["company_id"] for x in one["by_customer"]] == [cid], "scoped, only that customer's row")
        lv = {"critical": 5, "high": 4, "medium": 3, "low": 2, "informational": 1, None: 0}
        check([-lv[r["highest"]] for r in bc] == sorted(-lv[r["highest"]] for r in bc),
              "worst suggestion not decided first")

        print("Overview: evidence coverage, ATT&CK tactics, top rules")
        from app.services import overview as overview_mod, rule_meta as rule_meta_mod
        cov = ov["coverage"]
        check({r["company_id"] for r in cov} >= {W, OTHER}, "every customer has a coverage row")
        read = [r for r in cov if r["product"] is not None]
        check(read and all(r["days"] + r["gap_days"] == r["span_days"] and r["days"] >= 1 for r in read),
              "days with events + days without = the span, per log source")
        for cid in (W, OTHER):
            mans = [storage.load_manifest(x) for x in (A, F, Z, O)]
            want = sum(1 for m in mans if m.get("company_id") == cid
                       for p in m.get("periods") or [] if p.get("product"))
            check(sum(r["files"] for r in read if r["company_id"] == cid) == want,
                  f"coverage counts every file of the customer's periods ({want})")
        row = overview_mod._coverage_row("x", "X", "windows", {
            "files": 2, "cases": {"c"}, "first": "2026-01-01 08:00:00", "last": "2026-01-10 09:00:00",
            "days": {"2026-01-01", "2026-01-02", "2026-01-06", "2026-01-10"}})
        check(row["span_days"] == 10 and row["days"] == 4 and row["gap_days"] == 6
              and row["longest_gap"] == {"from": "2026-01-03", "to": "2026-01-05", "days": 3},
              "gaps: the days with no event between the first and the last, longest first")
        check(overview_mod.attention_reason({"method": "documented"}) is None
              and overview_mod.attention_reason({"method": "no_reader"}) == "no reader - kept, not analysed"
              and overview_mod.attention_reason({"method": "documented", "missing_fields": ["srcip"]})
              == "documented columns missing"
              and overview_mod.attention_reason({"method": "documented", "coverage": {"not_loaded": 3}})
              == "rows not loaded",
              "a file needs attention by the Ingest step's test")
        every = [x for cid in (A, F, Z, O) for x in findings(cid)]
        tac = ov["tactics"]
        check([t["id"] for t in tac] == [t for t, _, _ in rule_meta_mod.TACTIC_ORDER],
              "every ATT&CK tactic, in ATT&CK's order")
        check(all(t["suggestions"] == sum(1 for x in every if t["id"] in (x.get("tactics") or [])) for t in tac),
              "a tactic counts the suggestions whose techniques reach it, as the case page")
        tr = ov["top_rules"]
        check(0 < len(tr) <= 10 and [r["suggestions"] for r in tr] == sorted((r["suggestions"] for r in tr), reverse=True),
              "top rules: at most 10, most suggestions first")
        check(all(r["suggestions"] == sum(1 for x in every if x["rid"] == r["rid"])
                  == r["accepted"] + r["modified"] + r["rejected"] + r["undecided"] for r in tr),
              "a rule's suggestions add up, and its decisions add up to them")
        check(all(r["undecided"] == sum(1 for x in every if x["rid"] == r["rid"]
                                        and x["review"]["status"] == "Unreviewed") for r in tr),
              "not decided as the cases say")

        print("Overview: top affected accounts name their computers and sources")
        from app.services import db as db_mod
        tops = c.get("/api/overview").json()["top_entities"]
        accts = [e for e in tops if e["role"] == "accounts"]
        check(all(e["hosts"] == [] and e["sources"] == [] for e in tops if e["role"] != "accounts"),
              "an address carries no computer or source list")
        for key in ("hosts", "sources"):
            check(all([n for _, n in e[key]] == sorted((n for _, n in e[key]), reverse=True) for e in accts),
                  f"an account's {key} come most flagged events first")
            expect = {}
            for cid in (A, F, Z, O):
                for user, seen in db_mod.account_origins(cid, [e["entity"] for e in accts]).items():
                    for v, n in seen[key]:
                        expect.setdefault(user, {}).setdefault(v, 0)
                        expect[user][v] += n
            check(all(dict(map(tuple, e[key])) == expect.get(e["entity"], {}) for e in accts),
                  f"and add up each case's {key} for that account")
        check(any(e["sources"] for e in accts), "(the usecase's accounts came from a recorded address)")

        print("Overview: attention, KPIs, urgent findings")
        from app.services import custody as custody_mod
        ov = c.get("/api/overview").json()
        t0 = ov["totals"]
        check(t0["last_upload"] is not None and t0["ready"] == 4, "last upload and processed files are reported")
        check(t0["open_cases"] == sum(x["open"] for x in c.get("/api/companies/summary").json()["customers"]),
              "open cases follow the same rule as the Customers page")
        cu = c.get("/api/findings", params={"decision": "Unreviewed", "severity": "critical"}).json()
        check(t0["critical_undecided"] == cu["total"],
              f"critical, not decided = what that Findings filter lists ({cu['total']})")
        check(t0["failed_cases"] == 0 and ov["review_case"] in (A, F, Z, O), "no failed cases; the review backlog names a case")
        check(ov["attention"] == [], "no evidence or audit-log problem yet")
        wf_unrev = sum(1 for cid in (A, F, Z, O) for x in findings(cid)
                       if x["lifecycle"]["tracked"] and x["review"]["status"] == "Unreviewed")
        check(t0["awaiting_review"] == wf_unrev and t0["awaiting_review"] <= t0["unreviewed"],
              f"'awaiting review' counts workflow findings only ({wf_unrev}, of {t0['unreviewed']} unreviewed in all)")
        dec = c.get("/api/findings", params={"decision": "Unreviewed", "limit": 500}).json()
        check(dec["total"] == dec["undecided_count"] == t0["awaiting_review"]
              and all(x["review"] == "Unreviewed" for x in dec["rows"]),
              f"decision=Unreviewed lists what the menu badge counts ({dec['undecided_count']})")
        check(sum(dec["by_decision"].values()) == dec["scope_total"], "decisions add up to the workflow")
        check(c.get("/api/findings", params={"decision": "Maybe"}).status_code == 400, "an unknown decision is refused")
        op = c.get("/api/findings", params={"status": "open"}).json()
        check(op["total"] == op["open_count"] and all(x["status"] != "Resolved" for x in op["rows"]),
              "status=open lists what the badge and the area cards count (not Resolved)")
        check(c.get("/api/findings", params={"status": "nope"}).status_code == 400, "an unknown status is refused")
        ovw = c.get("/api/overview", params={"company_id": W}).json()
        check(ovw["company_id"] == W, "a scoped Overview says which customer its links carry")
        fd = ov["findings_daily"]
        tracked_total = c.get("/api/findings").json()["scope_total"]
        check(len(fd) == 14 and sum(d["critical"] + d["high"] for d in fd) == tracked_total,
              f"findings created per day: 14 days, all {tracked_total} workflow findings counted")
        check(t0["created_last7"] == tracked_total and t0["created_prev7"] == 0, "7 days against the 7 before")
        ur = ov["urgent"]
        check(0 < len(ur) <= 5, "the urgent list: at most 5")
        undecided_keys = {x["key"] for cid in (A, F, Z, O) for x in findings(cid) if x["review"]["status"] == "Unreviewed"}
        check(all(x["key"] in undecided_keys for x in ur), "every one on it still not decided")
        order = [-{"critical": 5, "high": 4}[x["level"]] for x in ur]
        check(order == sorted(order), "critical first")
        check(t0["critical_undecided"] == sum(1 for cid in (A, F, Z, O) for x in tracked(cid)
                                              if x["level"] == "critical" and x["review"]["status"] == "Unreviewed"),
              "critical not decided is counted for the banner")
        check(t0["mttc_seconds"] is None and t0["mttc_target_hours"] == 4.0, "no contained true positive yet: MTTC unknown, target 4 h")
        z1 = tracked(Z)[0]
        lc(Z, z1, "assign", assignee=B_EMAIL)
        lc(Z, z1, "investigate")
        lc(Z, z1, "contain", containment_actions="isolated the host")
        c.post(f"/api/cases/{Z}/review", json={"finding_key": z1["key"], "action": "accept"})
        lc(Z, z1, "resolve", classification="true_positive", summary="confirmed")
        t1 = c.get("/api/overview").json()["totals"]
        check(t1["mttc_n"] == 1 and t1["mttc_seconds"] is not None and t1["mttc_seconds"] >= 0, "a contained true positive gives a mean time to contain")
        cp = custody_mod.custody_path(A)
        good = cp.read_bytes()
        cp.write_bytes(good + b'{"action": "forged"}\n')
        att = c.get("/api/overview").json()["attention"]
        check(any(x["case_id"] == A and "custody" in x["reason"] for x in att), "an altered custody log is reported, with the case")
        cp.write_bytes(good)
        check(c.get("/api/overview").json()["attention"] == [], "and clears when the log is restored")

        print("a case refused for integrity keeps its open findings in view (review #6)")
        before = {x["key"] for x in c.get("/api/findings", params={"company_id": OTHER}).json()["rows"]}
        raw = storage.raw_path(O, "csv")
        raw.write_bytes(raw.read_bytes() + b"\n")  # the evidence changes after acquisition
        jobs.submit(O, raw, "csv")
        jobs.wait_idle(120)
        mo = storage.load_manifest(O)
        check(mo["status"] == "failed" and mo.get("error", "").startswith("IntegrityError"),
              "re-processing altered evidence is refused")
        rows = c.get("/api/findings", params={"company_id": OTHER}).json()["rows"]
        check({x["key"] for x in rows} == before and rows and all(x["evidence_problem"] for x in rows),
              "its workflow findings are still listed, each marked evidence_problem")
        check(c.get(f"/api/cases/{O}/findings/events", params={"key": rows[0]["key"]}).status_code == 200,
              "and their source events still open")
        check(c.get(f"/api/cases/{O}/stix").status_code == 409, "exports stay refused")
        ov2 = c.get("/api/overview").json()
        check(ov2["failed_case"] == O and any(x["case_id"] == O for x in ov2["attention"]),
              "the Overview links the failed case and lists its evidence problem")

    print("FAILED: " + "; ".join(FAILED) if FAILED else "WORKFLOW OK")
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
