"""Spike (a): does the SQLite backend's detection SQL mean the same thing on DuckDB?

Each case is a one-selection rule; the table holds case variants. The SQL is run
on SQLite (table as the backend expects: TEXT COLLATE NOCASE, like Zircolite,
and as a plain table) and on DuckDB with only the backticks swapped for double
quotes - i.e. the cheapest "run it on DuckDB" option.
"""
import re
import sqlite3

import duckdb
from sigma.backends.sqlite import sqliteBackend
from sigma.collection import SigmaCollection

ROWS = ["Device Code", "device code", "DEVICE CODE", "xx Device Code yy", "Other", None]

CASES = {
    "equals": "Msg: 'Device Code'",
    "contains": "Msg|contains: 'device code'",
    "startswith": "Msg|startswith: 'DEVICE'",
    "wildcard": "Msg: 'dev*code'",
    "regex": "Msg|re: '^device'",
    "regex_i": "Msg|re|i: '^device'",
    "cased": "Msg|cased: 'Device Code'",
    "null": "Msg: null",
}


def rule(sel: str) -> str:
    return f"""title: t
logsource: {{product: test}}
detection:
  sel:
    {sel}
  condition: sel
"""


def regexp(p, s):
    return s is not None and re.search(p, s) is not None


def run_sqlite(q, nocase):
    con = sqlite3.connect(":memory:")
    con.create_function("REGEXP", 2, regexp)
    con.execute(f"CREATE TABLE logs (rid INTEGER, Msg TEXT {'COLLATE NOCASE' if nocase else ''})")
    con.executemany("INSERT INTO logs VALUES (?, ?)", list(enumerate(ROWS)))
    return sorted(r[0] for r in con.execute(q.replace("SELECT *", "SELECT rid")))


def run_duckdb(q):
    con = duckdb.connect()
    con.execute("CREATE TABLE logs (rid INTEGER, Msg VARCHAR)")
    con.executemany("INSERT INTO logs VALUES (?, ?)", list(enumerate(ROWS)))
    q = q.replace("`", '"').replace("SELECT *", "SELECT rid")
    q = re.sub(r"(\S+) REGEXP ('(?:[^']|'')*')", r"regexp_matches(\1, \2)", q)
    try:
        return sorted(r[0] for r in con.execute(q).fetchall())
    except Exception as e:  # noqa: BLE001
        return f"{type(e).__name__}"


b = sqliteBackend()
print(f"{'case':11} {'sqlite NOCASE':16} {'sqlite plain':16} {'duckdb':16} query")
for name, sel in CASES.items():
    q = b.convert(SigmaCollection.from_yaml(rule(sel)))[0]
    a, p, d = run_sqlite(q, True), run_sqlite(q, False), run_duckdb(q)
    flag = "" if a == d else "  <-- DIFFERS"
    print(f"{name:11} {str(a):16} {str(p):16} {str(d):16} {q.split('WHERE ')[1]}{flag}")
