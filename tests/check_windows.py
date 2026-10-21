"""Windows event logs, W1 + W2: the core, event XML and .evtx
(app/services/winevent.py, specs/windows_event_logs.md).

    python tests/check_windows.py <scratch dir> [--repo DIR] [--evtx D:/logtest/windows]

Throwaway store, the real pipeline, no server. Checks:

- identification: event XML is supported with the Sigma logsource of its
  channel; Splunk's text rendering stays no_reader (W3); an .evtx is read (W2);
- the committed Splunk attack_data captures read to the letter: the Sysmon
  sample and PurpleSharp's NTLM spray (Security XML) - counts per event ID,
  event types, every item kept in win_events under its own name, UTC -> GMT+7;
- the spray fires the existing sign-in rules (R2000, R2009) from 4625 and
  IpAddress, and 4776 is typed but not counted (Q41);
- a synthetic file: an XML declaration and an <Events> wrapper, an event that
  spans lines, a 1102 with UserData, unnamed Data items (param<n>), a damaged
  event counted and kept as text - never dropped;
- the same counts through .gz and inside a .zip.

With --evtx, on the lab folder kept outside the repo (Q43): it holds a clone of
EVTX-ATTACK-SAMPLES (GPL-3.0) and this machine's System log exported twice -
`wevtutil epl System this-pc-System.evtx`, then Windows' own rendering of that
file as UTF-8 event XML (PowerShell; `wevtutil qe /f:xml` writes through the
console code page and loses what it cannot show):

    $w = [IO.StreamWriter]::new("this-pc-System.toxml.xml", $false, [Text.UTF8Encoding]::new($false))
    Get-WinEvent -Path this-pc-System.evtx -Oldest | ForEach-Object { $w.WriteLine($_.ToXml()) }
    $w.Close()


- all 278 samples identified by their channel, every record each chunk header
  names returned and parsed;
- the .evtx read through the pipeline equals Windows' XML of it, event by event
  and item by item (FILETIME to the microsecond - the library's precision);
- a cut file and an overwritten chunk: the missing records counted from the
  chunk headers and kept as a row, never dropped;
- a Sysmon sample through .gz and inside a .zip.

stdlib + the app's own modules (+ the `evtx` wheel for .evtx).
"""

import argparse
import gzip
import os
import re
import shutil
import sys
import time
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



def check_evtx(lab: Path, run, win, query) -> None:
    """W2 on the lab folder (Q43 - kept outside the repo): EVTX-ATTACK-SAMPLES
    (GPL-3.0) and this machine's System log exported twice, as .evtx (`wevtutil
    epl`) and as Windows' own event XML of that file (`Get-WinEvent ... .ToXml()`)."""
    from app.services import identify, winevent

    print(".evtx - every EVTX-ATTACK-SAMPLES file")
    samples = sorted((lab / "EVTX-ATTACK-SAMPLES").rglob("*.evtx"))
    wrong, damaged, records, compared, unlike = [], [], 0, 0, []

    def key(e):
        return (e["record_id"] or "", e["provider"] or "", e["event_id"] or 0, e["channel"] or "",
                e["computer"] or "", e["user_sid"] or "", e["time_created"] or "", sorted(e["data"].items()))
    for f in samples:
        r = identify.identify(f, "log")
        chunks, bad = winevent.evtx_chunks(f)
        named = sum(last - first + 1 for _, first, last, _ in chunks)
        events = [winevent.parse_event(t.xml, t.fixes, t.empty_in_array) for t in winevent.iter_evtx(f)
                  if isinstance(t, winevent.EvtxRecord)]
        records += len(events)
        if bad or len(events) != named or any(e is None for e in events):
            damaged.append(f.name)
        channels = {e["channel"] for e in events if e and e["channel"]}
        want = (winevent.CHANNELS.get(next(iter(channels))) if len(channels) == 1 else None) or \
            {"sigma": {"product": "windows"}}
        if (r["status"], r.get("read_as"), r["sigma"]) != ("supported", "evtx", want["sigma"]):
            wrong.append((f.name, r["status"], r["sigma"]))
        # Windows' own rendering of the same file (toxml/<path>.xml, made like the System one).
        ref = lab / "toxml" / (str(f.relative_to(lab / "EVTX-ATTACK-SAMPLES")) + ".xml")
        if ref.is_file():
            theirs = [winevent.parse_event(t) for t in winevent.iter_event_texts(ref)]
            compared += len(theirs)
            if sorted(map(key, filter(None, events))) != sorted(map(key, filter(None, theirs))):
                unlike.append(f.name)
    check(len(samples) == 278 and not wrong,
          f"{len(samples)} files identified as .evtx with their channel's Sigma service {wrong[:3]}")
    check(not damaged and records == 37364,
          f"{records} records, each chunk's header count returned and parsed {damaged[:3]}")
    check(compared == records and not unlike,
          f"{compared} of them exactly as Windows renders them (Get-WinEvent .ToXml()) {unlike[:3]}")

    print(".evtx vs Windows' own rendering of the same file")
    sys_evtx, sys_xml = lab / "this-pc-System.evtx", lab / "this-pc-System.toxml.xml"
    t0 = time.monotonic()
    me = run(sys_evtx, "log", "evtx")
    took = time.monotonic() - t0
    w = win(me)
    check(me["status"] == "ready" and w.get("events") == 43413 and w.get("unreadable") == 0,
          f"System export: 43,413 events, none unreadable ({me['status']}, {w.get('events')}, "
          f"{w.get('unreadable')}) - {took:.1f} s, {43413 / took:,.0f} events/s through the whole pipeline")
    mx = run(sys_xml)
    sql = ("SELECT record_id, provider, event_id, channel, computer, user_sid, time_created, data "
           "FROM win_events ORDER BY record_id::BIGINT")
    a, b = query(me["case_id"], sql), query(mx["case_id"], sql)

    diff = [x[0] for x, y in zip(a, b) if x != y]
    check(len(a) == len(b) == 43413 and not diff,
          f"every event and item exactly as Windows renders it - GUID values braced, FILETIME to "
          f"100 ns, empty values empty, a string holding a GUID left as written ({diff[:3]})")
    port = query(me["case_id"], "SELECT data['PortName'] FROM win_events WHERE data['PortName'] "
                 "SIMILAR TO '[0-9A-F-]{36}' LIMIT 1")
    check(bool(port), f"Hyper-V's PortName, a string, keeps its bare upper-case GUID ({port[:1]})")

    print(".evtx damaged - counted from the chunk headers, never dropped")
    whole = sys_evtx.read_bytes()
    scratch = Path(os.environ["DATA_DIR"]).parent
    cut_file = scratch / "cut.evtx"
    cut_file.write_bytes(whole[:len(whole) // 2 + 12345])
    corrupt = bytearray(whole)
    at = winevent.EVTX_HEADER + 3 * winevent.EVTX_CHUNK + 9000
    corrupt[at:at + 400] = b"\xff" * 400
    corrupt_file = scratch / "corrupt.evtx"
    corrupt_file.write_bytes(bytes(corrupt))
    for f, events, lost, why in ((cut_file, 21491, 165, "the file ends inside chunk 160"),
                                 (corrupt_file, 43275, 138, "chunk 3 overwritten")):
        m = run(f, "log", "evtx")
        w = win(m)
        rows = [r[0] for r in query(m["case_id"], "SELECT raw FROM raw_events WHERE raw LIKE '[unreadable EVTX%'")]
        check(m["status"] == "ready" and (w.get("events"), w.get("unreadable")) == (events, lost) and len(rows) == 1,
              f"{why}: {events} events + {lost} unreadable, kept as a row ({w.get('events')}, "
              f"{w.get('unreadable')}: {rows[:1]})")
    # The reader stops at a slot with no chunk signature; every good chunk after it is still read.
    first_bad = scratch / "first-chunk-gone.evtx"
    first_bad.write_bytes(whole[:winevent.EVTX_HEADER] + b"\x5a" * winevent.EVTX_CHUNK
                          + whole[winevent.EVTX_HEADER + winevent.EVTX_CHUNK:])
    m = run(first_bad, "log", "evtx")
    w = win(m)
    check(m["status"] == "ready" and (w.get("events"), w.get("unreadable_chunks")) == (43413 - 125, 1)
          and m["mapping"]["logsource"]["sigma"].get("service") == "system",
          f"chunk 0 overwritten: the other 43,288 events read, one damaged chunk named "
          f"({w.get('events')}, {w.get('unreadable_chunks')})")

    print(".evtx compressed")
    sysmon = lab / "EVTX-ATTACK-SAMPLES" / "Execution" / "sysmon_1_11_rundll32_cpl_ostap.evtx"
    m = run(sysmon, "log", "evtx")
    base = sorted(query(m["case_id"], "SELECT event_id, count(*) FROM win_events GROUP BY 1"))
    gz = scratch / "sysmon.evtx.gz"
    with gzip.open(gz, "wb") as fh:
        fh.write(sysmon.read_bytes())
    mg = run(gz, "log", "evtx.gz")
    zp = scratch / "sysmon.zip"
    with zipfile.ZipFile(zp, "w") as z:
        z.write(sysmon, "Microsoft-Windows-Sysmon%4Operational.evtx")
    mz = run(zp, "zip", "zip")
    check(base and all(sorted(query(x["case_id"], "SELECT event_id, count(*) FROM win_events GROUP BY 1")) == base
                       for x in (mg, mz)),
          f"the same Sysmon file through .gz and inside a .zip ({base})")
    p1 = query(m["case_id"], "SELECT e.action, w.data['ProcessGuid'] FROM raw_events e JOIN win_events w "
               "USING (row_id) WHERE w.event_id = 1 ORDER BY row_id LIMIT 1")
    check(p1 and p1[0][0] == "process_created" and re.match(r"^\{[0-9a-f-]{36}\}$", p1[0][1] or ""),
          f"Sysmon 1 typed, ProcessGuid as Windows renders it ({p1[:1]})")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("scratch")
    ap.add_argument("--repo", default=str(REPO))
    ap.add_argument("--evtx", help="lab .evtx folder kept outside the repo (W2, see the docstring)")
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
    empty = scratch / "empty.evtx"
    empty.write_bytes(b"ElfFile\x00" + b"\x00" * 4088)
    r = identify.identify(empty, "log")
    check((r["status"], r["name"], r.get("read_as")) == ("supported", "Windows event log (.evtx)", "evtx"),
          f"an .evtx by its signature, even one with no records: supported (W2) ({r['status']})")

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

    me = run(empty)
    check(me["status"] == "ready" and win(me).get("events") == 0 and win(me).get("unreadable") == 0,
          f".evtx with no records: ready, 0 events ({me['status']}, {win(me)})")

    if args.evtx:
        check_evtx(Path(args.evtx), run, win, query)

    print()
    print(f"{len(FAILED)} FAILED" if FAILED else "WINDOWS OK")
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
