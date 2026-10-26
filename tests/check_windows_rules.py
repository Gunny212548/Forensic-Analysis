"""Windows sign-in rules (app/services/rules_windows.py, specs/windows_rules.md story 5a).

    python tests/check_windows_rules.py <scratch> [--repo DIR]

Three parts, no network, no model (TRIAGE_ENABLED=0):
1. One attempt, however many events record it: small event XML files - a host's 4625 and the DC's
   4771 / 4776 for the same attempt count once; two 4625s in the same second are two attempts; a
   4776 is sourced by its workstation name; a computer account is left out of WIN-BRUTE-3.
2. The synthetic Windows quarter (tests/gen_windows_domain.py, seeded) scored against its ground
   truth: each sign-in incident found by the rule the design names, no plain or look-alike event
   flagged, the generic sign-in rules silent on Windows rows, the lines kept on the case, the
   Windows cells of the detection matrix.
3. Real data: attack_data's purplesharp spray (tests/samples) - 50 attempts the DC logged as a
   4625 and a 4776 each, decided a spray by TRW.
Story 5d adds: a refused TGT for an unknown name (4768 0x6) counted, a revoked one (0x12) not; the
CUSUM of WIN-BRUTE-4 (lines.py) on a known series; W3 (low-and-slow), W10 (an RDP session taken
over by a reconnect), W11 (Kerberos user-name enumeration) and W8's ADMIN$ copy on the quarter;
OTRF's reconnect found through the session's own logon id.
specs/finding_entities.md adds: one suggestion per behaviour (the entity a rule names), no
IPv4-mapped address in the timeline column, the account's history among the AI's facts.
"""

import argparse
import csv
import os
import subprocess
import sys
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

FAILED: list[str] = []


def check(ok: bool, what: str) -> None:
    print(f"  {'ok  ' if ok else 'FAIL'} {what}")
    if not ok:
        FAILED.append(what)


def event(eid: int, ts: datetime, host: str, items: dict, sysmon: bool = False) -> str:
    data = "".join(f"<Data Name='{k}'>{v}</Data>" for k, v in items.items())
    t = ts.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f") + "0Z"
    provider = ("<Provider Name='Microsoft-Windows-Sysmon' Guid='{5770385F-C22A-43E0-BF4C-06F5698FFBD9}'/>"
                if sysmon else
                "<Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-A5BA-3E3B0328C30D}'/>")
    channel = "Microsoft-Windows-Sysmon/Operational" if sysmon else "Security"
    return ("<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>" + provider +
            f"<EventID>{eid}</EventID><Version>0</Version><Level>0</Level><Task>12544</Task><Opcode>0</Opcode>"
            f"<Keywords>0x8010000000000000</Keywords><TimeCreated SystemTime='{t}'/><EventRecordID>{eid}</EventRecordID>"
            f"<Correlation/><Execution ProcessID='4' ThreadID='8'/><Channel>{channel}</Channel>"
            f"<Computer>{host}</Computer><Security/></System><EventData>{data}</EventData></Event>")


def fail_4625(ts, host, user, ip, ws="-"):
    return event(4625, ts, host, {"TargetUserName": user, "Status": "0xc000006d", "SubStatus": "0xc000006a",
                                  "LogonType": "3", "WorkstationName": ws, "IpAddress": ip})


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("scratch")
    ap.add_argument("--repo", default=str(Path(__file__).resolve().parent.parent))
    args = ap.parse_args()
    scratch = Path(args.scratch)
    os.environ["DATA_DIR"] = str(scratch / "data")
    os.environ["AUTH_DIR"] = str(scratch / "auth")
    os.environ["TRIAGE_ENABLED"] = "0"
    sys.path.insert(0, args.repo)
    from app.services import db, pipeline, storage

    co = storage.create_company("Windows rules")["company_id"]
    # A feed for the feed-match rules (story 5c): one public address for a connection, and the
    # quarter's internet brute forcer. Documentation ranges (203.0.113.0/24) are refused by intel.py.
    (scratch / "data" / "intel").mkdir(parents=True, exist_ok=True)
    (scratch / "data" / "intel" / "test-feed.txt").write_text("185.220.101.5\n45.155.205.99\n", encoding="utf-8")

    def run(path: Path, kind: str):
        cid = storage.create_case(path.name, kind, path.stat().st_size, company_id=co)["case_id"]
        pipeline.process_case(cid, path, kind)
        return cid, storage.load_manifest(cid), db.connect(cid, read_only=True)

    print("one attempt, however many events record it")
    t0 = datetime(2026, 7, 1, 9, 0, tzinfo=timezone.utc)
    lines = []
    # 6 attempts on jsmith from 10.0.0.5: each a 4625 on FS01 and a 4776 on the DC within 400 ms.
    for i in range(6):
        t = t0 + timedelta(seconds=10 * i)
        lines.append(fail_4625(t, "fs01.corp.local", "jsmith", "10.0.0.5", "WS05"))
        lines.append(event(4776, t + timedelta(milliseconds=400), "dc01.corp.local",
                           {"TargetUserName": "jsmith", "Workstation": "WS05", "Status": "0xc000006a"}))
    # 2 attempts on ann in the same second, the same event id: two attempts.
    lines.append(fail_4625(t0 + timedelta(minutes=5), "fs01.corp.local", "ann", "10.0.0.6"))
    lines.append(fail_4625(t0 + timedelta(minutes=5, milliseconds=300), "fs01.corp.local", "ann", "10.0.0.6"))
    # A 4776 alone: sourced by its workstation name.
    lines.append(event(4776, t0 + timedelta(minutes=7), "dc01.corp.local",
                       {"TargetUserName": "bob", "Workstation": "LAPTOP9", "Status": "0xc0000064"}))
    # A Kerberos failure 3 s after a 4625 for the same account: not the same attempt.
    lines.append(fail_4625(t0 + timedelta(minutes=9), "fs01.corp.local", "carl", "10.0.0.7"))
    lines.append(event(4771, t0 + timedelta(minutes=9, seconds=3), "dc01.corp.local",
                       {"TargetUserName": "carl", "Status": "0x18", "IpAddress": "::ffff:10.0.0.7"}))
    # A computer account failing from 4 addresses in an hour: not WIN-BRUTE-3's.
    for i in range(4):
        lines.append(event(4771, t0 + timedelta(minutes=20 + i), "dc01.corp.local",
                           {"TargetUserName": "PRN01$", "Status": "0x18", "IpAddress": f"::ffff:10.0.9.{i + 1}"}))
    # A refused TGT: 0x6 (no such user) is a failed attempt, 0x12 (account revoked) is not (W-D6).
    lines.append(event(4768, t0 + timedelta(minutes=30), "dc01.corp.local",
                       {"TargetUserName": "nosuchuser", "Status": "0x6", "IpAddress": "::ffff:10.0.0.8"}))
    lines.append(event(4768, t0 + timedelta(minutes=31), "dc01.corp.local",
                       {"TargetUserName": "leaver", "Status": "0x12", "IpAddress": "::ffff:10.0.0.8"}))
    small = scratch / "attempts.xml"
    small.write_text("\n".join(lines) + "\n", encoding="utf-8")
    cid, man, con = run(small, "log")
    check(man["status"] == "ready" and man.get("products") == ["windows"], f"read as Windows ({man.get('error')})")
    con.close()
    # The attempts table is a temp table of the rules' run: build it again on a copy.
    import duckdb
    from app.services import rules_windows
    mem = duckdb.connect()
    mem.execute(f"ATTACH '{db.db_path(cid).as_posix()}' AS c (READ_ONLY)")
    mem.execute("CREATE TEMP VIEW product_events AS SELECT * FROM c.raw_events WHERE product = 'windows'")
    mem.execute("CREATE TEMP VIEW win_events AS SELECT * FROM c.win_events")
    rules_windows._attempts(mem)
    att = {r[0]: r[1:] for r in mem.execute(
        "SELECT account, count(*), list(DISTINCT source), list(DISTINCT source_kind), sum(len(rows)) "
        "FROM win_attempts WHERE outcome = 'fail' GROUP BY account").fetchall()}
    check(att["jsmith"][0] == 6 and att["jsmith"][3] == 12 and att["jsmith"][1] == ["10.0.0.5"],
          f"4625 + 4776 of one attempt count once, sourced by the address ({att['jsmith']})")
    check(att["ann"][0] == 2, f"two 4625s in the same second are two attempts ({att['ann']})")
    check(att["bob"][1] == ["LAPTOP9"] and att["bob"][2] == ["workstation"],
          f"a lone 4776 is sourced by its workstation name ({att['bob']})")
    check(att["carl"][0] == 2, f"a 4771 3 s after the 4625 is another attempt ({att['carl']})")
    check(att["prn01$"][0] == 4 and len(att["prn01$"][1]) == 4, "the computer account's four sources are read")
    check(att.get("nosuchuser", [0])[0] == 1 and "leaver" not in att,
          f"4768 0x6 is a failed attempt, 0x12 a refusal only ({att.get('nosuchuser')}, {att.get('leaver')})")
    mem.close()
    con = db.connect(cid, read_only=True)
    flagged = {r[0]: r[1] for r in con.execute("SELECT rid, count(*) FROM findings GROUP BY rid").fetchall()}
    check("WIN-BRUTE-3" not in flagged, f"a computer account is left out of WIN-BRUTE-3 ({flagged})")
    con.close()

    print("CUSUM (Javed & Paxson §4.1) on known series")
    from app.services import lines as ln
    import random
    rng = random.Random(7)
    normal = [sum(rng.random() < 0.008 for _ in range(100)) for _ in range(400)]
    fit = ln.beta_binomial(normal, 100)
    m = ln.CUSUM_SCALE
    c = round(m * (fit["mean"] + 0.5))
    h, arl = ln.cusum_h(fit["pmf"], c, m)
    check(arl >= ln.CUSUM_ARL and (h == 0 or ln.cusum_arl(fit["pmf"], c, h - 1, m) < ln.CUSUM_ARL),
          f"H is the smallest with an in-control ARL of {ln.CUSUM_ARL} events (H {h / m:g}, ARL {arl:.0f})")
    _, runs = ln.cusum_run(normal, fit["mean"], c, h, m)
    check(not runs, f"no alarm on the normal series itself ({runs})")
    shifted = normal[:200] + [y + (1 if rng.random() < 0.9 else 0) for y in normal[200:300]] + normal[300:]
    _, runs = ln.cusum_run(shifted, fit["mean"], c, h, m)
    check(bool(runs) and 200 <= runs[0][0] < 300,
          f"one more failure per event from event 200 is caught inside the shift ({runs})")
    check(ln.automated([t0 + timedelta(minutes=15 * i, seconds=rng.uniform(0, 20)) for i in range(200)])
          and not ln.automated([t0 + timedelta(seconds=rng.uniform(0, 3 * 86400)) for _ in range(200)]),
          "a 15-minute job is automation by §5's chi-squared test, a person's times are not")

    print("feed matches on a connection and on a sign-in attempt")
    intel_file = scratch / "intel.xml"
    intel_file.write_text("\n".join([
        event(3, t0, "ws05.corp.local", {"ProcessGuid": "{aa}", "Image": r"C:\Users\x\a.exe", "Initiated": "true",
                                         "SourceIp": "10.0.0.5", "DestinationIp": "185.220.101.5",
                                         "DestinationPort": "443"}, sysmon=True),
        event(3, t0, "ws05.corp.local", {"ProcessGuid": "{ab}", "Image": r"C:\Users\x\b.exe", "Initiated": "true",
                                         "SourceIp": "10.0.0.5", "DestinationIp": "93.184.216.34",
                                         "DestinationPort": "443"}, sysmon=True),
        fail_4625(t0 + timedelta(seconds=5), "rds01.corp.local", "administrator", "45.155.205.99"),
    ]) + "\n", encoding="utf-8")
    cid, man, con = run(intel_file, "log")
    got = dict(con.execute("SELECT rid, count(*) FROM findings GROUP BY rid").fetchall())
    check(got.get("WIN-INTEL-1") == 1 and got.get("WIN-INTEL-2") == 1 and "R3003" not in got and "R3004" not in got,
          f"a listed destination is WIN-INTEL-1's, a listed sign-in source WIN-INTEL-2's, not the generic rules' ({got})")
    con.close()

    print("story 5e: a sprayer's own computer account, a beacon the fleet shares")
    lines5e = []
    # WEB01 (10.0.5.10) sprays eight accounts, then its own computer account and one sprayed user sign in.
    for i, name in enumerate(["ann", "bob", "carl", "dave", "eve", "fred", "gina", "hank"]):
        lines5e.append(fail_4625(t0 + timedelta(seconds=5 * i), "dc01.corp.local", name, "10.0.5.10"))
    for k, name in enumerate(["web01$", "eve"]):
        lines5e.append(event(4624, t0 + timedelta(minutes=5 + k), "dc01.corp.local",
                             {"TargetUserName": name, "TargetLogonId": f"0x{k + 0x900:x}", "LogonType": "3",
                              "IpAddress": "10.0.5.10", "AuthenticationPackageName": "Kerberos"}))
    # An agent's timer on 3 of 4 hosts to one address; one host's implant to another.
    for h, (img, dst, every) in enumerate([("agent.exe", "1.2.3.10", 60)] * 3 + [("implant.exe", "5.6.7.8", 120)]):
        for n in range(40):
            lines5e.append(event(3, t0 + timedelta(seconds=every * n + (n % 3)), f"pc{h}.corp.local",
                                 {"ProcessGuid": f"{{{h:02x}}}", "Image": rf"C:\Program Files\x\{img}",
                                  "Initiated": "true", "SourceIp": f"10.0.7.{h + 1}", "DestinationIp": dst,
                                  "DestinationPort": "443"}, sysmon=True))
    f5e = scratch / "story5e.xml"
    f5e.write_text("\n".join(lines5e) + "\n", encoding="utf-8")
    cid, man, con = run(f5e, "log")
    auth = {r[0] for r in con.execute("SELECT entity_user FROM findings WHERE rid = 'WIN-AUTH-1'").fetchall()}
    check(auth == {"eve"}, f"the sprayed user's sign-in is WIN-AUTH-1's, the sprayer's own computer account not ({auth})")
    mal = {r[0] for r in con.execute("SELECT DISTINCT program FROM findings JOIN raw_events USING (row_id) "
                                     "WHERE rid = 'WIN-MAL-1'").fetchall()}
    rec = (man.get("lines") or {}).get("WIN-MAL-1", {})
    check(mal == {"implant.exe"}, f"one host's beacon flagged, the fleet's timer not ({mal})")
    check(rec.get("method") == "fleet-wide" and [x["process"] for x in rec.get("left_out", [])] == ["agent.exe"]
          and rec.get("hosts_with_network_events") == 4,
          f"the fleet's timer is named on the line record ({rec.get('note')})")
    con.close()

    print("the synthetic Windows quarter, against its ground truth")
    out = scratch / "mekong"
    gen = Path(args.repo) / "tests" / "gen_windows_domain.py"
    subprocess.run([sys.executable, str(gen), str(out)], check=True, stdout=subprocess.DEVNULL)
    cid, man, con = run(out / "mekong-windows-2026Q3.zip", "zip")
    check(man["status"] == "ready", f"processed ({man.get('error')})")
    truth = {}
    with open(out / "ground_truth.csv", encoding="utf-8") as fh:
        for r in csv.DictReader(fh):
            truth[(r["host"].upper(), r["channel"], r["record_id"])] = (r["label"], r["incident"])
    found = defaultdict(set)
    wrong = defaultdict(int)
    for rid, host, ch, rec in con.execute(
            "SELECT f.rid, upper(split_part(w.computer, '.', 1)), w.channel, w.record_id "
            "FROM findings f JOIN win_events w USING (row_id)").fetchall():
        label, inc = truth.get((host, ch, str(rec)), ("plain", "-"))
        if label == "attack":
            found[inc].add(rid)
        elif label != "btp":
            wrong[(rid, label)] += 1
    expect = {"W1": {"WIN-BRUTE-2", "WIN-AUTH-1"}, "W2": {"WIN-BRUTE-1"}, "W6": {"WIN-BRUTE-1", "WIN-AUTH-1"},
              "W9": {"WIN-BRUTE-3"},
              # story 5b
              "W5": {"WIN-HOST-1"}, "W7": {"WIN-LAT-1", "WIN-HOST-2"}, "W8": {"WIN-LAT-2", "WIN-LAT-3"},
              # story 5c - W2's source is on the test feed
              "W4": {"WIN-MAL-1"},
              # story 5d
              "W3": {"WIN-BRUTE-4"}, "W10": {"WIN-LAT-1"}, "W11": {"WIN-BRUTE-2"}}
    expect["W8"] = expect["W8"] | {"WIN-LAT-4"}
    expect["W2"] = expect["W2"] | {"WIN-INTEL-2"}
    for inc, rids in expect.items():
        check(rids <= found[inc], f"{inc} found by {sorted(rids)} ({sorted(found[inc])})")
    check(not wrong, f"no plain or look-alike event flagged ({dict(wrong)})")
    w3 = con.execute("SELECT count(DISTINCT row_id) FROM findings WHERE rid = 'WIN-BRUTE-4'").fetchone()[0]
    check(w3 >= 150, f"WIN-BRUTE-4 flags most of W3's 246 failures, measured 156 ({w3})")
    b5 = (man.get("lines") or {}).get("WIN-BRUTE-4", {})
    check(b5.get("method") == "cusum" and b5.get("in_control_arl", 0) >= 3720 and b5.get("epochs", 0) >= 1,
          f"WIN-BRUTE-4's CUSUM kept on the case ({b5.get('note')}, {b5.get('epochs')} epochs)")
    rids = {r[0] for r in con.execute("SELECT DISTINCT rid FROM findings").fetchall()}
    check(not rids & {"R2000", "R2005", "R2006", "R2008", "R2009", "R2007", "R3003", "R3004", "R3005"},
          f"the generic sign-in, beaconing and feed rules are silent on Windows rows ({sorted(rids)})")
    ln = man.get("lines") or {}
    check(ln.get("WIN-BRUTE-1", {}).get("method") == "evidence-line" and ln["WIN-BRUTE-1"]["members"] >= 20,
          f"WIN-BRUTE-1's line measured on the episodes ({ln.get('WIN-BRUTE-1')})")
    check(ln.get("WIN-BRUTE-2", {}).get("method") == "trw", "WIN-BRUTE-2 decided by TRW")
    det = {d["product"]: {a["area"]: a for a in d["areas"]} for d in man.get("detection") or []}
    w = det.get("windows", {})
    check(w.get("scanning-policy", {}).get("status") == "n/a" and w.get("data-apps", {}).get("status") == "n/a",
          "Scanning and Data transfer are n/a on Windows, with a reason")
    check({"WIN-BRUTE-1", "WIN-BRUTE-2", "WIN-BRUTE-3"} <= set(w.get("account-attacks", {}).get("rules", [])),
          "Brute force on Windows runs the WIN rules")
    check(set(w.get("lateral-movement", {}).get("rules", [])) == {"WIN-LAT-1", "WIN-LAT-2", "WIN-LAT-3", "WIN-LAT-4"}
          and set(w.get("host-activity", {}).get("rules", [])) == {"WIN-HOST-1", "WIN-HOST-2"},
          "the two host areas run the 5b rules")
    lat2 = con.execute("SELECT count(DISTINCT descr) FROM findings WHERE rid = 'WIN-LAT-2' "
                       "AND descr LIKE '%Zabbix%'").fetchone()[0]
    check(lat2 == 4, f"the agent rollout to 4 servers is found - a benign true positive for the analyst ({lat2})")
    copied = con.execute("SELECT count(DISTINCT descr) FROM findings WHERE rid = 'WIN-LAT-4' "
                         "AND descr LIKE '%kb5043145%'").fetchone()[0]
    check(copied == 3, f"the patch copied through C$ to 3 servers is found - a benign true positive ({copied})")
    share = con.execute("SELECT count(*) FROM findings WHERE rid = 'WIN-LAT-2' AND descr LIKE '%opened%ADMIN$%'"
                        ).fetchone()[0]
    check(share >= 1, f"WIN-LAT-2 names the ADMIN$ opened in W8's session ({share})")
    # specs/finding_entities.md: a rule names who its finding is about, so one behaviour is one
    # suggestion (E-D1); a DC's ::ffff: address is IPv4 in the timeline (E-D3); the account's
    # history is a fact for the AI (E-D2).
    con.close()
    from app.services import triage
    sugg = db.collapsed_findings(cid)
    per = defaultdict(list)
    for f in sugg:
        per[f["rid"]].append(f)
    check(len(sugg) <= 40, f"the quarter is a few dozen suggestions, not 517 ({len(sugg)})")
    check(len(per["WIN-BRUTE-2"]) == 2 and all(not f["username"] for f in per["WIN-BRUTE-2"]),
          f"one WIN-BRUTE-2 suggestion per sprayer ({[f['key'] for f in per['WIN-BRUTE-2']]})")
    check(len(per["WIN-BRUTE-4"]) == 4 and all(not f["srcip"] for f in per["WIN-BRUTE-4"]),
          f"one WIN-BRUTE-4 suggestion per account guessed ({[f['key'] for f in per['WIN-BRUTE-4']]})")
    check(len(per["WIN-BRUTE-3"]) == 1, f"W9's 30 sources are one WIN-BRUTE-3 suggestion ({len(per['WIN-BRUTE-3'])})")
    w7 = [f for f in per["WIN-LAT-1"] if f["username"] == "adm.backup"]
    check(len(w7) == 1 and w7[0]["srcip"] == "10.20.10.33",
          f"W7's RDP session is one WIN-LAT-1 suggestion with its source ({[f['key'] for f in w7]})")
    con = db.connect(cid, read_only=True)
    mapped = con.execute("SELECT count(*) FROM raw_events WHERE srcip ILIKE '::ffff:%'").fetchone()[0]
    check(mapped == 0, f"no IPv4-mapped address left in the timeline column ({mapped})")
    kept = con.execute("SELECT count(*) FROM win_events WHERE data['IpAddress'] ILIKE '::ffff:%'").fetchone()[0]
    check(kept > 0, f"win_events keeps what Windows wrote ({kept})")
    dump = [f for f in per["WIN-HOST-2"] if f["username"] == "adm.backup"]
    hist = [x for x in triage.facts(con, dump[0])] if dump else []
    check(any("Other findings of account 'adm.backup'" in x and "WIN-AUTH-1" in x and "before this suggestion" in x
              for x in hist), "the dump's facts say adm.backup was guessed and signed in before (account history)")
    seq = con.execute("SELECT w.event_id, count(*) FROM findings f JOIN win_events w USING (row_id) "
                      "WHERE f.rid = 'WIN-LAT-1' GROUP BY 1 ORDER BY 1").fetchall()
    check(dict(seq).get(4624) == 1 and dict(seq).get(4688, 0) >= 6,
          f"WIN-LAT-1 flags the logon and the processes of its session ({seq})")
    con.close()
    from app.services import products
    fw = {d["product"]: {a["area"]: a for a in d["areas"]} for d in products.matrix(
        ["paloalto"], __import__("app.services.rules", fromlist=["RULE_PRODUCT"]).RULE_PRODUCT)}
    check(fw["paloalto"]["lateral-movement"]["status"] == "n/a" and fw["paloalto"]["host-activity"]["status"] == "n/a",
          "a firewall shows the host areas as n/a, with a reason")

    print("real data: attack_data's purplesharp spray")
    sample = Path(args.repo) / "tests" / "samples" / "attack-data" / "windows-security-xml-spray.log"
    cid, man, con = run(sample, "log")
    rows = con.execute("SELECT w.event_id, count(*) FROM findings f JOIN win_events w USING (row_id) "
                       "WHERE f.rid = 'WIN-BRUTE-2' GROUP BY 1 ORDER BY 1").fetchall()
    check(rows == [(4625, 50), (4776, 50)], f"50 attempts, each a 4625 and a 4776, flagged as a spray ({rows})")
    con.close()

    print("real data: OTRF's RDP session and Task Manager LSASS dump")
    sample = Path(args.repo) / "tests" / "samples" / "otrf" / "rdp_interactive_taskmanager_lsass_dump.json"
    cid, man, con = run(sample, "json")
    got = dict(con.execute("SELECT rid, count(*) FROM findings GROUP BY rid").fetchall())
    check(got.get("WIN-LAT-3") == 1, f"the outside client's NTLM logon is WIN-LAT-3's ({got})")
    # Story 5d: the reconnect's 4778 carries the session's own id (0x10ac67), which Task Manager runs
    # under; the 4624 type 7 of the reconnect have new ids. The dump file still has no Sysmon 10.
    lat1 = dict(con.execute("SELECT w.event_id, count(*) FROM findings f JOIN win_events w USING (row_id) "
                            "WHERE f.rid = 'WIN-LAT-1' GROUP BY 1").fetchall())
    check(lat1.get(4778) == 1 and lat1.get(1, 0) >= 1, f"the RDP reconnect and what it ran are WIN-LAT-1's ({lat1})")
    check("WIN-HOST-2" not in got, "the dump without an access event is not found (a blind spot, said so)")
    con.close()

    print("\nWINDOWS RULES OK" if not FAILED else f"\n{len(FAILED)} FAILED")
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
