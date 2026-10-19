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

REPO = Path(__file__).resolve().parent.parent
FAILED: list[str] = []
FD = re.compile(r"^FD-\d{4}-\d{4}$")
A_EMAIL, A_PW = "analyst@workflow.local", "workflow-throwaway-pw-1"
B_EMAIL, B_PW = "lead@workflow.local", "workflow-throwaway-pw-2"
AUTH_RULES = {"R1000", "R1001", "R1002", "R1003", "R1004", "R2000", "R2005", "R2006"}


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
        row("R3000", "9.9.9.9", ["3.3.3.3"]),           # only shares the final target
        row("R2005", "5.5.5.5", [], user="alice"),      # spray on an account
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
                        "--name", email.split("@")[0], "--role", "analyst", "--password-stdin"],
                       input=pw + "\n", text=True, capture_output=True, check=True)
    sys.path.insert(0, str(repo))
    unit_related()

    from fastapi.testclient import TestClient

    from app.main import app
    from app.services import jobs, lifecycle, storage

    c = TestClient(app)
    with c:
        c.post("/api/auth/login", json={"email": A_EMAIL, "password": A_PW})

        def upload(path: Path, company: str) -> dict:
            with open(path, "rb") as fh:
                return c.post("/api/upload", files={"file": (path.name, fh)},
                              data={"company_name": company}).json()

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
        scan = by_rid.get("R2002")
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

        print("Customers: open while a workflow finding is not Resolved (IAI-79)")

        def row(company_id: str) -> dict:
            return next(x for x in c.get("/api/companies/summary").json()["customers"] if x["company_id"] == company_id)

        r0 = row(OTHER)
        check(r0["open"] == 1 and r0["closed"] == 0 and r0["open_severity"] in ("high", "critical"),
              f"a case with open workflow findings is open ({r0['open']} open, {r0['open_severity']})")
        top = max(x["lvl"] for x in tracked(O))
        for x in tracked(O):
            lc(O, x, "assign", assignee=B_EMAIL)
            lc(O, x, "investigate")
            c.post(f"/api/cases/{O}/review", json={"finding_key": x["key"], "action": "accept"})
            lc(O, x, "resolve", classification="false_positive", summary="test close")
        r1 = row(OTHER)
        unrev = c.get(f"/api/cases/{O}/findings").json()["review_summary"].get("Unreviewed", 0)
        check(r1["open"] == 0 and r1["closed"] == 1 and r1["open_severity"] is None,
              f"closed once every workflow finding is Resolved ({unrev} lower findings are still unreviewed)")
        keep = tracked(O)[0]
        lc(O, keep, "reopen", note="again")
        r2 = row(OTHER)
        check(r2["open"] == 1 and r2["open_severity"] == keep["level"], "reopening makes it open again at that finding's severity")
        check(top >= keep["lvl"], "(sanity: the open severity is the reopened finding's)")
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
        check(all(len(a["trend"]) == len(ov["trend_days"]) for a in ar) and 0 < len(ov["trend_days"]) <= 30,
              "every card has one trend value per day on a shared axis (at most 30 days)")
        check(sum(sum(a["trend"]) for a in ar) <= len(every_case) and sum(sum(a["trend"]) for a in ar) > 0,
              "the trend counts findings first seen per day")
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

        print("Overview: attention, KPIs, urgent findings")
        from app.services import custody as custody_mod
        ov = c.get("/api/overview").json()
        t0 = ov["totals"]
        check(t0["last_upload"] is not None and t0["ready"] == 4, "last upload and processed files are reported")
        check(t0["open_cases"] == sum(x["open"] for x in c.get("/api/companies/summary").json()["customers"]),
              "open cases follow the same rule as the Customers page")
        un = c.get("/api/findings", params={"unassigned": "true", "severity": "critical"}).json()
        check(t0["critical_unassigned"] == un["total"] and all(not x["assignee"] for x in un["rows"]),
              f"critical, unassigned = what that Findings filter lists ({un['total']})")
        check(t0["failed_cases"] == 0 and ov["review_case"] in (A, F, Z, O), "no failed cases; the review backlog names a case")
        check(ov["attention"] == [], "no evidence or audit-log problem yet")
        fd = ov["findings_daily"]
        tracked_total = c.get("/api/findings").json()["scope_total"]
        check(len(fd) == 14 and sum(d["critical"] + d["high"] for d in fd) == tracked_total,
              f"findings created per day: 14 days, all {tracked_total} workflow findings counted")
        check(t0["created_last7"] == tracked_total and t0["created_prev7"] == 0, "7 days against the 7 before")
        ur = ov["urgent"]
        check(0 < len(ur) <= 5 and all(x["status"] != "Resolved" for x in ur), "the urgent list: at most 5, none Resolved")
        order = [(-{"critical": 5, "high": 4}[x["level"]], bool(x["assignee"])) for x in ur]
        check(order == sorted(order), "critical first, unassigned before assigned")
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

    print("FAILED: " + "; ".join(FAILED) if FAILED else "WORKFLOW OK")
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
