"""Spike (a): a spec-shaped value_count correlation on the Entra spray sample.
Oracle = pySigma SQLite backend on SQLite; candidate = hand-written DuckDB SQL.
The base rule is OURS (SigmaHQ has none for AADSTS 50126) - that is the point."""
import json, sqlite3, sys, pathlib, time
sys.path.insert(0, str(pathlib.Path(__file__).parent))
import duckdb
from sigma.backends.sqlite import sqliteBackend
from sigma.collection import SigmaCollection
from entra_run import flatten

RULES = """title: Entra sign-in failed, invalid username or password (spike, not published)
id: 11111111-1111-4111-8111-111111111111
name: entra_failed_password
logsource: {product: azure, service: signinlogs}
detection:
  sel: {ResultType: 50126}
  condition: sel
---
title: Failed login with many accounts per source (shape of the spec's value_count example)
id: 22222222-2222-4222-8222-222222222222
correlation:
  type: value_count
  rules: [entra_failed_password]
  group-by: [IpAddress]
  timespan: 1d
  condition: {field: Username, gte: THRESH}
"""
files = sorted(pathlib.Path("D:/forensic-analyzer-s4/tests/samples/entra-azure-monitor").glob("*.jsonl"))
rows = [flatten(json.loads(l)) for f in files for l in open(f, encoding="utf-8") if l.strip()]
data = [(i, r["resultType"], r["properties.userPrincipalName"], r["properties.ipAddress"], r["properties.createdDateTime"]) for i, r in enumerate(rows)]
print("rows", len(data), "distinct ips", len({d[3] for d in data}), "distinct users", len({d[2] for d in data}))

for thresh in (100, 3):
    q = sqliteBackend(timestamp_field="ts").convert(SigmaCollection.from_yaml(RULES.replace("THRESH", str(thresh))))
    con = sqlite3.connect(":memory:")
    con.execute("CREATE TABLE logs (eid INTEGER, ResultType TEXT COLLATE NOCASE, Username TEXT COLLATE NOCASE, IpAddress TEXT COLLATE NOCASE, ts TEXT)")
    con.executemany("INSERT INTO logs VALUES (?,?,?,?,?)", data)
    try:
        out = con.execute(q[-1]).fetchall()
        oracle = sorted({json.loads(r[1])["IpAddress"] for r in out})
        print(f"thresh {thresh}: sqlite backend -> {len(out)} result rows; sources {len(oracle)}: {oracle[:5]}")
    except Exception as e:
        print(f"thresh {thresh}: sqlite backend query failed: {type(e).__name__}: {e}"); print(q[-1][:600])
    d = duckdb.connect()
    d.execute("CREATE TABLE logs (eid INTEGER, ResultType VARCHAR, Username VARCHAR, IpAddress VARCHAR, ts TIMESTAMPTZ)")
    d.executemany("INSERT INTO logs VALUES (?,?,?,?,?)", data)
    # one group per source, the 1d window anchored at each failed event (sliding, as the spec does not fix boundaries)
    hits = d.execute(f"""
      WITH m AS (SELECT * FROM logs WHERE TRY_CAST(ResultType AS DOUBLE)=50126)
      SELECT a.IpAddress, CAST(a.ts AS VARCHAR) AS window_start, count(DISTINCT lower(b.Username)) AS users
      FROM m a JOIN m b ON b.IpAddress = a.IpAddress AND b.ts >= a.ts AND b.ts < a.ts + INTERVAL 1 DAY
      GROUP BY ALL HAVING users >= {thresh} ORDER BY users DESC, a.IpAddress, window_start""").fetchall()
    dk = sorted({h[0] for h in hits}); print(f"thresh {thresh}: duckdb -> {len(hits)} windows; sources {len(dk)}: {dk[:5]}; same sources as oracle: {dk == oracle if out else None}")
