"""Spike (a): convert the SigmaHQ rules for the logsources identify.py can read
with pySigma's SQLite backend, then run each query on SQLite and on DuckDB.

usage: python -I convert_all.py <sigma repo> <out.json>
"""
import json
import re
import sqlite3
import sys
from collections import Counter
from pathlib import Path

import duckdb
import yaml
from sigma.backends.sqlite import sqliteBackend
from sigma.collection import SigmaCollection

# what identify.py / logsources.py can name today (branch IAI-92)
TARGETS = [
    {"category": "firewall"},
    {"product": "azure", "service": "signinlogs"},
    {"product": "m365", "service": "exchange"},
    {"product": "linux", "service": "sshd"},
    {"product": "linux", "service": "auth"},
    {"product": "linux", "service": "syslog"},
]


def target_of(ls: dict) -> str | None:
    for t in TARGETS:
        if all(ls.get(k) == v for k, v in t.items()) and \
                all(k in t or ls.get(k) is None for k in ("category", "product", "service")):
            return "/".join(f"{k}={v}" for k, v in t.items())
    return None


def main(repo: Path, out: Path) -> None:
    picked = []
    for d in ("rules", "rules-threat-hunting", "rules-emerging-threats", "rules-compliance"):
        for p in sorted((repo / d).rglob("*.yml")):
            doc = yaml.safe_load(p.read_text(encoding="utf-8"))
            t = target_of(doc.get("logsource") or {})
            if t:
                picked.append((t, p, doc))
    print("rules picked:", Counter(t for t, _, _ in picked))

    backend = sqliteBackend()
    results = []
    for t, p, doc in picked:
        r = {"target": t, "file": str(p.relative_to(repo)), "id": doc.get("id"),
             "title": doc.get("title"), "author": doc.get("author"),
             "level": doc.get("level"), "status": doc.get("status")}
        try:
            coll = SigmaCollection.from_yaml(p.read_text(encoding="utf-8"))
            r["queries"] = backend.convert(coll)
        except Exception as e:  # noqa: BLE001 - a spike counts every failure
            r["convert_error"] = f"{type(e).__name__}: {e}"
            results.append(r)
            continue
        r["fields"] = sorted({f for q in r["queries"] for f in fields_in(q)})
        r["sqlite"] = [run_sqlite(q, r["fields"]) for q in r["queries"]]
        r["duckdb"] = [run_duckdb(q, r["fields"]) for q in r["queries"]]
        results.append(r)
    out.write_text(json.dumps(results, indent=1, default=str), encoding="utf-8")

    conv_err = [r for r in results if "convert_error" in r]
    ok = [r for r in results if "queries" in r]
    print(f"converted {len(ok)} / {len(results)}; convert errors {len(conv_err)}")
    print("convert errors:", Counter(r["convert_error"].split(":")[0] for r in conv_err))
    for eng in ("sqlite", "duckdb"):
        bad = [r for r in ok if any(x != "ok" for x in r[eng])]
        print(f"{eng}: {len(ok) - len(bad)} run, {len(bad)} fail;",
              Counter(x.split(":")[0] for r in bad for x in r[eng] if x != "ok"))


_IDENT = re.compile(r"(?<![\w'])([A-Za-z_][\w.]*)(?=\s*(?:=|<>|!=|LIKE|REGEXP|IN\b|IS\b|<|>))")
_QUOTED = re.compile(r"`([^`]+)`|\"([^\"]+)\"")


def fields_in(q: str) -> set:
    names = {a or b for a, b in _QUOTED.findall(q)}
    names |= set(_IDENT.findall(re.sub(r"'(?:[^']|'')*'", "''", q)))
    return {n for n in names if n.upper() not in {"AND", "OR", "NOT", "ESCAPE", "SELECT", "FROM", "WHERE"}}


def ddl(fields: list) -> str:
    cols = ", ".join(f'"{f}" VARCHAR' for f in fields) or "x VARCHAR"
    return f"CREATE TABLE {{t}} ({cols})"


def table_of(q: str) -> str:
    m = re.search(r"FROM\s+([`\"]?[\w.<>]+[`\"]?)", q)
    return m.group(1) if m else "logs"


def run_sqlite(q: str, fields: list) -> str:
    con = sqlite3.connect(":memory:")
    con.create_function("REGEXP", 2, lambda p, s: s is not None and re.search(p, s) is not None)
    try:
        con.execute(ddl(fields).format(t=table_of(q)))
        con.execute(q).fetchall()
        return "ok"
    except Exception as e:  # noqa: BLE001
        return f"{type(e).__name__}: {e}"


def run_duckdb(q: str, fields: list) -> str:
    con = duckdb.connect()
    try:
        con.execute(ddl(fields).format(t=table_of(q)))
        con.execute(q).fetchall()
        return "ok"
    except Exception as e:  # noqa: BLE001
        return f"{type(e).__name__}: {e}"


if __name__ == "__main__":
    main(Path(sys.argv[1]), Path(sys.argv[2]))
