"""Windows event logs, W1: the core and event XML (app/services/winevent.py,
specs/windows_event_logs.md).

    python tests/check_windows.py <scratch dir> [--repo DIR]

Throwaway store, the real pipeline, no server. Checks:

- identification: event XML is supported with the Sigma logsource of its
  channel; Splunk's text rendering and an .evtx stay no_reader (W3, W2);
- the committed Splunk attack_data captures read to the letter: the Sysmon
  sample and PurpleSharp's NTLM spray (Security XML) - counts per event ID,
  event types, every item kept in win_events under its own name, UTC -> GMT+7;
- the spray fires the existing sign-in rules (R2000, R2009) from 4625 and
  IpAddress, and 4776 is typed but not counted (Q41);
- a synthetic file: an XML declaration and an <Events> wrapper, an event that
  spans lines, a 1102 with UserData, unnamed Data items (param<n>), a damaged
  event counted and kept as text - never dropped;
- the same counts through .gz and inside a .zip.

stdlib + the app's own modules.
"""

import argparse
import gzip
import os
import shutil
import sys
import zipfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SAMPLES = REPO / "tests" / "samples" / "attack-data"
FAILED: list[str] = []

SYNTHETIC = """<?xml version="1.0" encoding="utf-8"?>
<Events>
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4672</EventID><TimeCreated SystemTime='2026-02-14T02:00:00.1234567Z'/><EventRecordID>1</EventRecordID><Channel>Security</Channel><Computer>dc01.example.test</Computer><Security/></System><EventData><Data Name='SubjectUserName'>alice</Data><Data Name='PrivilegeList'>SeDebugPrivilege
			SeBackupPrivilege</Data></EventData></Event>
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Eventlog'/><EventID>1102</EventID><TimeCreated SystemTime='2026-02-14T02:00:01Z'/><EventRecordID>2</EventRecordID><Channel>Security</Channel><Computer>dc01.example.test</Computer><Security UserID='S-1-5-21-1'/></System><UserData><LogFileCleared xmlns='http://manifests.microsoft.com/win/2004/08/windows/eventlog'><SubjectUserSid>S-1-5-21-1</SubjectUserSid><SubjectUserName>mallory</SubjectUserName></LogFileCleared></UserData></Event>
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Legacy Source'/><EventID>9</EventID><TimeCreated SystemTime='2026-02-14T02:00:02Z'/><EventRecordID>3</EventRecordID><Channel>Application</Channel><Computer>ws01.example.test</Computer></System><EventData><Data>first</Data><Data>second</Data></EventData></Event>
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4625</EventID><TimeCreated SystemTime='2026-02-14T02:00:03Z'/><Channel>Security</Channel><Computer>dc01.example.test</Computer></System><EventData><Data Name='TargetUserName'>bob</Data><Data Name='IpAddress'>198.51.100.4
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Sysmon'/><EventID>3</EventID><TimeCreated SystemTime='2026-02-14T02:00:04Z'/><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>ws01.example.test</Computer></System><EventData><Data Name='Image'>C:\\Windows\\System32\\cmd.exe</Data><Data Name='User'>EXAMPLE\\alice</Data><Data Name='SourceIp'>10.0.0.8</Data><Data Name='DestinationIp'>203.0.113.9</Data><Data Name='DestinationPort'>443</Data></EventData></Event>
</Events>
"""


def check(ok: bool, what: str) -> None:
    print(f"  {'ok  ' if ok else 'FAIL'} {what}")
    if not ok:
        FAILED.append(what)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("scratch")
    ap.add_argument("--repo", default=str(REPO))
    args = ap.parse_args()
    scratch = Path(args.scratch)
    shutil.rmtree(scratch, ignore_errors=True)
    (scratch / "store").mkdir(parents=True)
    os.environ["DATA_DIR"] = str(scratch / "store")
    sys.path.insert(0, args.repo)
    from app.services import db, identify, pipeline, storage

    print("identification")
    for name, service in (("windows-sysmon.log", "sysmon"), ("windows-security-xml-spray.log", "security")):
        r = identify.identify(SAMPLES / name, "log")
        check((r["status"], r["sigma"], r.get("read_as")) == ("supported", {"product": "windows", "service": service},
                                                              "winxml"),
              f"{name}: supported, windows/{service} ({r['status']} {r['sigma']})")
    r = identify.identify(SAMPLES / "windows-security.log", "log")
    check(r["status"] == "no_reader", f"Splunk's text rendering stays no_reader until W3 ({r['status']})")
    evtx = scratch / "fake.evtx"
    evtx.write_bytes(b"ElfFile\x00" + b"\x00" * 4088)
    r = identify.identify(evtx, "log")
    check((r["status"], r["name"]) == ("no_reader", "Windows event log (.evtx)"),
          f"an .evtx by its signature: no_reader until W2 ({r['status']})")

    co = storage.create_company("Windows lab")

    def run(src: Path, kind: str = "log", ext: str = "log") -> dict:
        m = storage.create_case(src.name, kind, src.stat().st_size, company_id=co["company_id"],
                                company_name=co["name"])
        raw = storage.raw_path(m["case_id"], ext)
        shutil.copyfile(src, raw)
        pipeline.process_case(m["case_id"], raw, kind)
        return storage.load_manifest(m["case_id"])

    def win(m: dict) -> dict:
        mp = m["members"][0]["mapping"] if m.get("members") else m.get("mapping")
        return (mp or {}).get("windows") or {}

    def query(cid: str, sql: str, params=()):
        con = db.connect(cid, read_only=True)
        try:
            return con.execute(sql, list(params)).fetchall()
        finally:
            con.close()

    print("Security XML - PurpleSharp NTLM spray")
    m = run(SAMPLES / "windows-security-xml-spray.log")
    w = win(m)
    check(m["status"] == "ready" and w.get("events") == 232 and w.get("unreadable") == 0,
          f"232 events, none unreadable ({m['status']}, {w})")
    ids = dict(query(m["case_id"], "SELECT event_id, count(*) FROM win_events GROUP BY 1"))
    check(ids == {4625: 50, 4776: 50, 4648: 50, 4688: 36, 4624: 21, 4634: 21, 4672: 3, 4719: 1},
          f"every event ID counted as in the capture ({ids})")
    check(m.get("rules_matched") == {"R2000": 50, "R2009": 50},
          f"the spray fires R2000 and R2009 from 4625 + IpAddress ({m.get('rules_matched')})")
    acts = dict(query(m["case_id"], "SELECT coalesce(action, '-'), count(*) FROM raw_events GROUP BY 1"))
    check(acts.get("auth_failed") == 50 and acts.get("ntlm_validation") == 50,
          "4625 is a sign-in failure; 4776 typed, not counted as one (Q41)")
    row = query(m["case_id"], "SELECT e.ts, e.ts_raw, e.srcip, e.username, e.hostname, e.app, "
                "w.data['SubStatus'], w.data['LogonType'] FROM raw_events e JOIN win_events w USING (row_id) "
                "WHERE w.event_id = 4625 ORDER BY row_id LIMIT 1")[0]
    check(str(row[0]).startswith("2022-09-09 04:5") and row[1].endswith("Z"), f"UTC -> GMT+7 ({row[0]} from {row[1]})")
    check(row[2] == "10.0.1.15" and row[4].startswith("win-dc-") and row[5] == "Network (3)",
          f"source address, host, logon type named ({row[2]}, {row[4]}, {row[5]})")
    check(row[6] == "0xc000006a" and row[7] == "3", "the event's own items kept under their own names")
    cmd = query(m["case_id"], "SELECT count(*) FROM win_events WHERE event_id = 4688 "
                "AND data['CommandLine'] ILIKE '%powershell%'")[0][0]
    check(cmd > 0, f"a Sigma-style query on CommandLine runs on win_events ({cmd} rows)")
    untyped = [e["event"] for e in db.list_raw(m["case_id"], 300, 0) if e["action"] is None]
    check(untyped and untyped[0] == "Windows event 4634 (Microsoft-Windows-Security-Auditing)",
          f"an event with no type is named, not blank ({untyped[:1]})")

    print("Sysmon XML")
    m = run(SAMPLES / "windows-sysmon.log")
    ids = dict(query(m["case_id"], "SELECT event_id, count(*) FROM win_events GROUP BY 1"))
    check(ids == {10: 36, 1: 2, 4: 1, 16: 1}, f"40 Sysmon events by ID ({ids})")
    p1 = query(m["case_id"], "SELECT e.action, e.program, e.username, w.data['ParentImage'] FROM raw_events e "
               "JOIN win_events w USING (row_id) WHERE w.event_id = 1 ORDER BY row_id LIMIT 1")[0]
    check(p1[0] == "process_created" and p1[1] == "unsecapp.exe" and p1[3].endswith("svchost.exe"),
          f"Sysmon 1: process created, image, parent kept ({p1})")

    print("synthetic: wrapper, multi-line, UserData, unnamed items, damage")
    syn = scratch / "synthetic.xml"
    syn.write_text(SYNTHETIC, encoding="utf-8")
    r = identify.identify(syn, "log")
    check(r["status"] == "supported" and r["sigma"] == {"product": "windows"},
          f"several channels: product windows, no single service ({r['sigma']})")
    m = run(syn)
    w = win(m)
    check(w.get("rows") == 5 and w.get("events") == 4 and w.get("unreadable") == 1,
          f"5 rows: 4 events, 1 damaged kept ({w})")
    native = {r[0]: r[1] for r in query(m["case_id"], "SELECT event_id, data FROM win_events")}
    check("SeBackupPrivilege" in native[4672]["PrivilegeList"], "an item that spans lines is whole")
    check(native[1102].get("SubjectUserName") == "mallory", "1102's UserData items are read")
    check(native[9] == {"param1": "first", "param2": "second"}, "unnamed items get param<n>")
    raw = [e for e in db.list_raw(m["case_id"], 10, 0)]
    check(any(e["raw"].startswith("[unreadable event XML]") and e["ts"] is None for e in raw),
          "the damaged event is a text row, never dropped")
    s3 = next(e for e in raw if e["action"] == "network_connection")
    check((s3["srcip"], s3["dstip"], s3["dstport"], s3["username"]) == ("10.0.0.8", "203.0.113.9", "443", "EXAMPLE\\alice"),
          f"Sysmon 3: source, destination, port, user ({s3['srcip']} -> {s3['dstip']}:{s3['dstport']})")
    check(next(e for e in raw if e["action"] == "special_privileges")["ts"].startswith("2026-02-14 09:00:00.123"),
          "100 ns SystemTime read to the microsecond")

    print("compressed")
    base = sorted(query(m["case_id"], "SELECT event_id, count(*) FROM win_events GROUP BY 1"))
    gz = scratch / "synthetic.xml.gz"
    with gzip.open(gz, "wb") as fh:
        fh.write(syn.read_bytes())
    mg = run(gz, "log", "log.gz")
    check(sorted(query(mg["case_id"], "SELECT event_id, count(*) FROM win_events GROUP BY 1")) == base,
          "the same file through .gz")
    zp = scratch / "events.zip"
    with zipfile.ZipFile(zp, "w") as z:
        z.write(syn, "Security-export.xml")
    mz = run(zp, "zip", "zip")
    check(sorted(query(mz["case_id"], "SELECT event_id, count(*) FROM win_events GROUP BY 1")) == base
          and win(mz).get("unreadable") == 1, "the same file inside a .zip")

    print()
    print(f"{len(FAILED)} FAILED" if FAILED else "WINDOWS OK")
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
