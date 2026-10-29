"""Convert SigmaHQ's Windows rules into the SQL the app runs on win_events (specs/sigma_windows.md).

    python tools/sigma_build.py <sigma-repo> <out.json> --commit <sha>

Runs in the image's `sigma` build stage (Dockerfile) - the only place pySigma is installed
(requirements-sigma.txt). The app reads the JSON and never needs pySigma or the network
(gotcha #17). Before converting, the DuckDB dialect is checked against pySigma's SQLite
backend on SQLite (ADR-006's reference) form by form; the build fails on any difference
other than the two where the reference is the wrong one.

Logsource -> Channel / EventID is the Sigma taxonomy appendix v2.1.0's (Windows Folder,
Category and Service tables): pySigma-pipeline-windows / -sysmon pin pysigma<2 (S-D2).
"""
import argparse
import hashlib
import json
import re
import sqlite3
import sys
from importlib.metadata import version
from pathlib import Path

import duckdb
import yaml
from sigma.backends.sqlite import sqliteBackend
from sigma.collection import SigmaCollection
from sigma.pipelines.common import windows_logsource_mapping

_BARE = r"[A-Za-z_][A-Za-z0-9_]*"


class DuckDialect(sqliteBackend):
    """pySigma's SQLite backend with the tokens that mean something else on DuckDB (ADR-006 C)."""
    # Sigma compares strings case-insensitively; DuckDB LIKE is case-sensitive, ILIKE is not.
    wildcard_match_expression = "{field} ILIKE '{value}' ESCAPE '\\'"
    contains_expression = "{field} ILIKE '%{value}%' ESCAPE '\\'"
    # No REGEXP operator; regexp_matches is a search (RE2), like re.search.
    re_expression = "regexp_matches({field}, '{regex}')"
    collation_expression = "{expr} COLLATE NOCASE"
    # Items are VARCHAR: compare numbers as numbers, a value that is not one is no match.
    compare_op_expression = "TRY_CAST({field} AS DOUBLE) {operator} {value}"
    # A boolean is 'true' or 1 to the backend; a bare 1 makes DuckDB cast a VARCHAR item to an
    # integer and fail on 'false' (spike (b)). Both forms as text.
    bool_numeric_values = {True: "'1'", False: "'0'"}

    def convert_condition_field_eq_val_num(self, cond, state):
        return f"TRY_CAST({self.escape_and_quote_field(cond.field)} AS DOUBLE)={cond.value}"

    def __init__(self, *a, **kw):
        kw.setdefault("collate_nocase", True)
        super().__init__(*a, **kw)

    def escape_and_quote_field(self, field):
        if re.fullmatch(_BARE, field):
            return '"' + field + '"'
        return '"' + field.replace('"', '""') + '"'


SYSMON = "Microsoft-Windows-Sysmon/Operational"
PS = ["Microsoft-Windows-PowerShell/Operational", "PowerShellCore/Operational"]
# Sigma taxonomy appendix v2.1.0, Windows Folder / Category. file_access and file_rename are
# ETW (Microsoft-Windows-Kernel-File), not an event log: not readable.
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
}
# The taxonomy's Service table; pySigma's own copy of it.
SERVICE = {k: (v if isinstance(v, list) else [v]) for k, v in windows_logsource_mapping.items()}
FOLDERS = ("rules", "rules-emerging-threats", "rules-threat-hunting")
TABLE_PREFIX = 'SELECT * FROM "logs" WHERE '


def logsource_sql(ls: dict) -> tuple[str | None, str | None]:
    """(SQL over win_events' channel / event_id, why not readable)."""
    cat, svc = ls.get("category"), ls.get("service")
    if cat:
        if cat not in CATEGORY:
            return None, f"category {cat}: not an event log (Sigma taxonomy)"
        chans, ids = CATEGORY[cat]
        return (f"lower(w.channel) IN ({', '.join(repr(c.lower()) for c in chans)}) "
                f"AND w.event_id IN ({', '.join(map(str, ids))})"), None
    if svc:
        if svc not in SERVICE:
            return None, f"service {svc}: not in the Sigma taxonomy"
        return f"lower(w.channel) IN ({', '.join(repr(c.lower()) for c in SERVICE[svc])})", None
    return "TRUE", None


def fields_of(sql: str) -> list[str]:
    # Identifiers are double-quoted; a value may hold a '"', so '...' literals go first.
    bare = re.sub(r"'(?:[^']|'')*'", "''", sql)
    return sorted({f.replace('""', '"') for f in re.findall(r'"((?:[^"]|"")+)"', bare)} - {"logs"})


def techniques(tags: list[str]) -> list[str]:
    return sorted({t.split(".", 1)[1].upper() for t in tags
                   if re.fullmatch(r"attack\.t\d{4}(\.\d{3})?", t)})


def tactics(tags: list[str]) -> list[str]:
    return [t.split(".", 1)[1] for t in tags if t.startswith("attack.") and not re.match(r"attack\.[tgs]\d", t)]


def convert(repo: Path, commit: str) -> list[dict]:
    backend = DuckDialect()
    out = []
    for folder in FOLDERS:
        for path in sorted((repo / folder).rglob("*.yml")):
            text = path.read_text(encoding="utf-8")
            doc = yaml.safe_load(text)
            ls = doc.get("logsource") or {}
            if ls.get("product") != "windows":
                continue
            rel = path.relative_to(repo).as_posix()
            # The whole UUID: SigmaHQ authors copy ids, so different rules share 8 and even 12 hex.
            r = {"id": doc["id"], "rid": "SIGMA-" + doc["id"].lower(),
                 "title": doc["title"], "description": doc.get("description"), "author": doc.get("author"),
                 "status": doc.get("status"), "level": doc.get("level"), "date": str(doc.get("date") or ""),
                 "modified": str(doc.get("modified") or ""), "references": doc.get("references") or [],
                 "falsepositives": doc.get("falsepositives") or [], "tags": doc.get("tags") or [],
                 "techniques": techniques(doc.get("tags") or []), "tactics": tactics(doc.get("tags") or []),
                 "logsource": ls, "folder": folder, "path": rel,
                 "url": f"https://github.com/SigmaHQ/sigma/blob/{commit}/{rel}"}
            r["where"], r["not_readable"] = logsource_sql(ls)
            try:
                queries = backend.convert(SigmaCollection.from_yaml(text))
                for q in queries:
                    if not q.startswith(TABLE_PREFIX):
                        raise ValueError(f"unexpected query shape: {q[:60]}")
                r["conditions"] = [q[len(TABLE_PREFIX):] for q in queries]
                r["fields"] = sorted({f for q in queries for f in fields_of(q)})
            except Exception as e:
                r["error"] = f"{type(e).__name__}: {str(e)[:300]}"
            out.append(r)
    rids = [r["rid"] for r in out]
    dup = {x for x in rids if rids.count(x) > 1}
    if dup:
        raise SystemExit(f"two rules share an id: {sorted(dup)}")
    return out


# The dialect against the reference, form by form (spike (a)'s differential test). The
# reference is wrong on two: `gt` on text (SQLite orders any text above any number) and
# non-ASCII case folding (NOCASE folds ASCII only).
_ROWS = ["Device Code", "device code", "DEVICE CODE", "xx Device Code yy", "Other", None,
         r"C:\Windows\System32\cmd.exe", r"c:\windows\system32\CMD.EXE", "100%_done", "100xxdone",
         "10.1.2.3", "10.2.0.1", "192.168.1.5", "50053", "500", "a'b", "Ünïcode", "ünïcode", "true", "false", "1"]
_FORMS = {
    "equals": "Msg: 'Device Code'", "contains": "Msg|contains: 'device code'",
    "startswith": "Msg|startswith: 'DEVICE'", "endswith": "Msg|endswith: '\\cmd.exe'",
    "wildcard": "Msg: 'dev*code'", "wild_q": "Msg: 'dev?ce code'", "literal_pct": "Msg|contains: '%_'",
    "backslash_eq": "Msg: 'C:\\Windows\\System32\\cmd.exe'", "contains_all": "Msg|contains|all: ['device', 'code']",
    "regex": "Msg|re: '^device'", "regex_i": "Msg|re|i: '^device'", "cased": "Msg|cased: 'Device Code'",
    "cased_contains": "Msg|contains|cased: 'Code'", "null": "Msg: null", "list_or": "Msg: ['Other', 'device code']",
    "quote": "Msg: \"a'b\"", "unicode": "Msg: 'ÜNÏCODE'", "cidr": "Msg|cidr: '10.0.0.0/8'", "int_eq": "Msg: 50053",
    "gt": "Msg|gt: 1000", "bool": "Msg: true",
}
_REFERENCE_WRONG = {"gt", "unicode"}


def selftest() -> None:
    def rule(sel):
        return f"title: t\nlogsource: {{product: test}}\ndetection:\n  sel:\n    {sel}\n  condition: sel\n"

    def ref(q):
        con = sqlite3.connect(":memory:")
        con.create_function("REGEXP", 2, lambda p, s: s is not None and re.search(p, str(s)) is not None)
        con.execute("CREATE TABLE logs (rid INTEGER, Msg TEXT COLLATE NOCASE)")
        con.executemany("INSERT INTO logs VALUES (?,?)", list(enumerate(_ROWS)))
        return sorted(r[0] for r in con.execute(q.replace("SELECT *", "SELECT rid")))

    def duck(q):
        con = duckdb.connect()
        con.execute("CREATE TABLE logs (rid INTEGER, Msg VARCHAR)")
        con.executemany("INSERT INTO logs VALUES (?,?)", list(enumerate(_ROWS)))
        return sorted(r[0] for r in con.execute(q.replace("SELECT *", "SELECT rid")).fetchall())

    sb, db = sqliteBackend(), DuckDialect()
    differ = {name for name, sel in _FORMS.items()
              if ref(sb.convert(SigmaCollection.from_yaml(rule(sel)))[0])
              != duck(db.convert(SigmaCollection.from_yaml(rule(sel)))[0])}
    if differ != _REFERENCE_WRONG:
        raise SystemExit(f"DuckDB dialect differs from the SQLite reference on {sorted(differ)}; "
                         f"expected exactly {sorted(_REFERENCE_WRONG)}")
    print(f"dialect self-test: {len(_FORMS)} forms, differs only where the reference is wrong "
          f"({sorted(differ)})")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("repo")
    ap.add_argument("out")
    ap.add_argument("--commit", required=True)
    args = ap.parse_args()
    selftest()
    rules = convert(Path(args.repo), args.commit)
    body = {
        "provenance": {
            "source": "https://github.com/SigmaHQ/sigma", "commit": args.commit,
            "license": "Detection Rule License (DRL) 1.1",
            "license_url": "https://github.com/SigmaHQ/Detection-Rule-License",
            "taxonomy": "Sigma taxonomy appendix v2.1.0",
            "pysigma": version("pysigma"), "pysigma_backend_sqlite": version("pysigma-backend-sqlite"),
            "folders": list(FOLDERS),
        },
        "rules": rules,
    }
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(body, ensure_ascii=False, indent=0, sort_keys=True), encoding="utf-8")
    ok = sum(1 for r in rules if "conditions" in r and not r["not_readable"])
    print(f"{len(rules)} Windows rules, {ok} runnable, {sum('error' in r for r in rules)} not convertible, "
          f"{sum(bool(r['not_readable']) for r in rules)} not readable; "
          f"sha256 {hashlib.sha256(out.read_bytes()).hexdigest()[:16]}", file=sys.stderr)


if __name__ == "__main__":
    main()
