"""Spike (b): SigmaHQ's Windows rules on win_events, through the DuckDB dialect of spike (a).

    convert  <sigma-repo> <rules.json>                 every Windows rule -> SQL + logsource
    run      <rules.json> <case.duckdb>... > out.jsonl  every rule on each case's win_events
    regress  <rules.json> <sigma-repo> <scratch> > out  each regression .evtx, its own rule only

Logsource -> Channel / EventID from the Sigma taxonomy appendix v2.1.0 (Windows Folder,
Category and Service tables), not from pySigma-pipeline-sysmon / -windows: those pin
pySigma < 2, ADR-006 pins 2.0.1. Field names are the events' own (win_events.data), which
the taxonomy says Sigma follows ("field names used in Sysmon events").
"""
import json, re, sys, time, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).parent))

SYSMON = "Microsoft-Windows-Sysmon/Operational"
PS = ["Microsoft-Windows-PowerShell/Operational", "PowerShellCore/Operational"]
# taxonomy v2.1.0, Windows Folder / Category
CATEGORY = {
    "process_creation": ([SYSMON], [1]), "file_change": ([SYSMON], [2]), "network_connection": ([SYSMON], [3]),
    "sysmon_status": ([SYSMON], [4, 16]), "process_termination": ([SYSMON], [5]), "driver_load": ([SYSMON], [6]),
    "image_load": ([SYSMON], [7]), "create_remote_thread": ([SYSMON], [8]), "raw_access_thread": ([SYSMON], [9]),
    "process_access": ([SYSMON], [10]), "file_event": ([SYSMON], [11]), "registry_event": ([SYSMON], [12, 13, 14]),
    "registry_add": ([SYSMON], [12]), "registry_delete": ([SYSMON], [12]), "registry_set": ([SYSMON], [13]),
    "registry_rename": ([SYSMON], [14]), "create_stream_hash": ([SYSMON], [15]), "pipe_created": ([SYSMON], [17, 18]),
    "wmi_event": ([SYSMON], [19, 20, 21]), "dns_query": ([SYSMON], [22]), "file_delete": ([SYSMON], [23]),
    "clipboard_capture": ([SYSMON], [24]), "process_tampering": ([SYSMON], [25]),
    "file_delete_detected": ([SYSMON], [26]), "file_block_executable": ([SYSMON], [27]),
    "file_block_shredding": ([SYSMON], [28]), "file_executable_detected": ([SYSMON], [29]),
    "sysmon_error": ([SYSMON], [255]),
    "ps_classic_start": (["Windows PowerShell"], [400]), "ps_classic_provider_start": (["Windows PowerShell"], [600]),
    "ps_classic_script": (["Windows PowerShell"], [800]), "ps_module": (PS, [4103]), "ps_script": (PS, [4104]),
    # file_access / file_rename: ETW Microsoft-Windows-Kernel-File, not an event log - not readable
}


def service_channels():
    from sigma.pipelines.common import windows_logsource_mapping   # = taxonomy's Service table
    return {k: (v if isinstance(v, list) else [v]) for k, v in windows_logsource_mapping.items()}


def logsource_sql(ls, services):
    cat, svc = ls.get("category"), ls.get("service")
    if cat:
        if cat not in CATEGORY:
            return None, f"category {cat} not an event log"
        chans, ids = CATEGORY[cat]
        cond = f"lower(channel) IN ({', '.join(repr(c.lower()) for c in chans)}) AND event_id IN ({', '.join(map(str, ids))})"
        return cond, None
    if svc:
        if svc not in services:
            return None, f"service {svc} not in the taxonomy"
        return f"lower(channel) IN ({', '.join(repr(c.lower()) for c in services[svc])})", None
    return "TRUE", None


def convert(repo, out):
    import yaml
    from sigma.collection import SigmaCollection
    from duck_dialect import DuckDialect
    services = service_channels()
    b = DuckDialect()
    res = []
    for d in ("rules", "rules-threat-hunting", "rules-emerging-threats"):
        for p in sorted((repo / d).rglob("*.yml")):
            text = p.read_text(encoding="utf-8")
            doc = yaml.safe_load(text)
            ls = doc.get("logsource") or {}
            if ls.get("product") != "windows":
                continue
            r = {"file": p.relative_to(repo).as_posix(), "id": doc["id"], "title": doc["title"],
                 "author": doc.get("author"), "level": doc.get("level"), "status": doc.get("status"),
                 "tags": doc.get("tags") or [], "logsource": ls, "folder": d}
            r["where_ls"], r["not_readable"] = logsource_sql(ls, services)
            try:
                qs = b.convert(SigmaCollection.from_yaml(text))
                r["queries"] = [q for q in qs]
                # identifiers are double-quoted; a value may hold a '"', so strip '...' literals first
                r["fields"] = sorted({f for q in qs for f in re.findall(r'"((?:[^"]|"")+)"', re.sub(r"'(?:[^']|'')*'", "''", q))}
                                     - {"logs"})
            except Exception as e:
                r["error"] = f"{type(e).__name__}: {str(e)[:200]}"
            res.append(r)
    out.write_text(json.dumps(res, indent=1), encoding="utf-8")
    from collections import Counter
    print("windows rules:", len(res), Counter(r["folder"] for r in res), file=sys.stderr)
    print("convert errors:", sum("error" in r for r in res), Counter(r["error"].split(":")[0] for r in res if "error" in r), file=sys.stderr)
    print("not readable logsource:", Counter(r["not_readable"] for r in res if r["not_readable"]), file=sys.stderr)


SPECIAL = {"EventID": "CAST(event_id AS VARCHAR)", "Channel": "channel", "Provider_Name": "provider",
           "Computer": "computer"}


def column(f):
    return SPECIAL.get(f, f"data[{f!r}]")


def run_rule(con, r, row_filter=""):
    """Rows of win_events the rule matches; None when it cannot run on this case."""
    if r.get("error") or r.get("not_readable") or not r.get("queries"):
        return None, "skip"
    cols = ", ".join(f'{column(f)} AS "{f}"' for f in r["fields"]) or "NULL AS _none"
    con.execute(f"CREATE OR REPLACE TEMP VIEW logs AS SELECT row_id, {cols} FROM win_events "
                f"WHERE ({r['where_ls']}) {row_filter}")
    present = con.execute("SELECT count(*) FROM logs").fetchone()[0]
    if not present:
        return None, "no events of its logsource"
    rows = set()
    for q in r["queries"]:
        rows |= {x[0] for x in con.execute(q.replace("SELECT *", "SELECT row_id", 1)).fetchall()}
    return rows, "ran"


def run(rules_json, dbs):
    import duckdb
    rules = json.loads(pathlib.Path(rules_json).read_text(encoding="utf-8"))
    for dbp in dbs:
        con = duckdb.connect(dbp, read_only=True)
        if not con.execute("SELECT count(*) FROM duckdb_tables() WHERE table_name='win_events'").fetchone()[0]:
            continue
        t0, ran, errs = time.time(), 0, []
        for r in rules:
            try:
                rows, how = run_rule(con, r)
            except Exception as e:
                errs.append((r["id"], f"{type(e).__name__}: {str(e)[:160]}"))
                continue
            if how == "ran":
                ran += 1
                if rows:
                    print(json.dumps({"db": dbp, "id": r["id"], "title": r["title"], "level": r["level"],
                                      "status": r["status"], "rows": sorted(rows)}))
        print(json.dumps({"db": dbp, "summary": True, "rules_ran": ran, "seconds": round(time.time() - t0, 1),
                          "errors": errs[:30], "n_errors": len(errs)}))
        con.close()


def regress(rules_json, repo, scratch):
    """Each regression .evtx through the app's own pipeline, then its own rule; compare with match_count."""
    import os, yaml
    os.environ["DATA_DIR"] = str(scratch / "data"); os.environ["AUTH_DIR"] = str(scratch / "auth")
    os.environ["TRIAGE_ENABLED"] = "0"
    sys.path.insert(0, "/app")
    from app.services import db, pipeline, storage
    rules = {r["id"]: r for r in json.loads(pathlib.Path(rules_json).read_text(encoding="utf-8"))}
    co = storage.create_company("Sigma regression")["company_id"]
    for info in sorted((repo / "regression_data" / "rules" / "windows").rglob("info.yml")):
        doc = yaml.safe_load(info.read_text(encoding="utf-8"))
        rid = (doc.get("rule_metadata") or [{}])[0].get("id")
        for t in doc.get("regression_tests_info") or []:
            if t.get("type") != "evtx":
                continue
            ev = repo / t["path"]
            rec = {"rule": rid, "title": (rules.get(rid) or {}).get("title"), "expected": t.get("match_count"),
                   "evtx": t["path"]}
            if rid not in rules:
                rec["result"] = "rule not among the converted Windows rules"
            else:
                try:
                    cid = storage.create_case(ev.name, "log", ev.stat().st_size, company_id=co)["case_id"]
                    pipeline.process_case(cid, ev, "log")
                    con = db.connect(cid, read_only=True)
                    rows, how = run_rule(con, rules[rid])
                    rec["events"] = con.execute("SELECT count(*) FROM win_events").fetchone()[0]
                    rec["result"] = how
                    rec["got"] = None if rows is None else len(rows)
                    con.close()
                except Exception as e:
                    rec["result"] = f"error {type(e).__name__}: {str(e)[:200]}"
            print(json.dumps(rec), flush=True)


if __name__ == "__main__":
    cmd = sys.argv[1]
    if cmd == "convert":
        convert(pathlib.Path(sys.argv[2]), pathlib.Path(sys.argv[3]))
    elif cmd == "run":
        run(sys.argv[2], sys.argv[3:])
    elif cmd == "regress":
        regress(sys.argv[2], pathlib.Path(sys.argv[3]), pathlib.Path(sys.argv[4]))
