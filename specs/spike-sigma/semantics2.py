"""Spike (a): SQLite backend on SQLite (NOCASE table, the reference) vs the DuckDB
dialect on DuckDB, same rules, same rows."""
import re
import sqlite3
import duckdb
from sigma.backends.sqlite import sqliteBackend
from sigma.collection import SigmaCollection
import sys, pathlib; sys.path.insert(0, str(pathlib.Path(__file__).parent))
from duck_dialect import DuckDialect

ROWS = ["Device Code", "device code", "DEVICE CODE", "xx Device Code yy", "Other", None,
        r"C:\Windows\System32\cmd.exe", r"c:\windows\system32\CMD.EXE", "100%_done", "100xxdone",
        "10.1.2.3", "10.2.0.1", "192.168.1.5", "50053", "500", "a'b", "Ünïcode", "ünïcode"]
CASES = {
    "equals": "Msg: 'Device Code'",
    "contains": "Msg|contains: 'device code'",
    "startswith": "Msg|startswith: 'DEVICE'",
    "endswith": "Msg|endswith: '\\cmd.exe'",
    "wildcard": "Msg: 'dev*code'",
    "wild_q": "Msg: 'dev?ce code'",
    "literal_pct": "Msg|contains: '%_'",
    "backslash_eq": "Msg: 'C:\\Windows\\System32\\cmd.exe'",
    "contains_all": "Msg|contains|all: ['device', 'code']",
    "regex": "Msg|re: '^device'",
    "regex_i": "Msg|re|i: '^device'",
    "cased": "Msg|cased: 'Device Code'",
    "cased_contains": "Msg|contains|cased: 'Code'",
    "null": "Msg: null",
    "list_or": "Msg: ['Other', 'device code']",
    "quote": "Msg: \"a'b\"",
    "unicode": "Msg: 'ÜNÏCODE'",
    "cidr": "Msg|cidr: '10.0.0.0/8'",
    "int_eq": "Msg: 50053",
    "gt": "Msg|gt: 1000",
}
def rule(sel): return f"title: t\nlogsource: {{product: test}}\ndetection:\n  sel:\n    {sel}\n  condition: sel\n"
def regexp(p, s): return s is not None and re.search(p, str(s)) is not None
def ref(q):
    con = sqlite3.connect(":memory:"); con.create_function("REGEXP", 2, regexp)
    con.execute("CREATE TABLE logs (rid INTEGER, Msg TEXT COLLATE NOCASE)")
    con.executemany("INSERT INTO logs VALUES (?,?)", list(enumerate(ROWS)))
    return sorted(r[0] for r in con.execute(q.replace("SELECT *", "SELECT rid")))
def duck(q):
    con = duckdb.connect(); con.execute("CREATE TABLE logs (rid INTEGER, Msg VARCHAR)")
    con.executemany("INSERT INTO logs VALUES (?,?)", list(enumerate(ROWS)))
    try: return sorted(r[0] for r in con.execute(q.replace("SELECT *", 'SELECT rid')).fetchall())
    except Exception as e: return f"{type(e).__name__}: {str(e)[:80]}"
sb, db = sqliteBackend(), DuckDialect()
diff = 0
for name, sel in CASES.items():
    try:
        qs = sb.convert(SigmaCollection.from_yaml(rule(sel)))[0]
        qd = db.convert(SigmaCollection.from_yaml(rule(sel)))[0]
    except Exception as e:
        print(f"{name:14} CONVERT {type(e).__name__}: {e}"); continue
    a, d = ref(qs), duck(qd)
    diff += a != d
    print(f"{name:14} ref={str(a):22} duck={str(d):22} {'DIFF ' + qd.split('WHERE ')[1] if a != d else ''}")
print("differences:", diff, "of", len(CASES))
