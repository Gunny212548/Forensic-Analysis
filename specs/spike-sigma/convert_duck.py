"""Spike (a): every SigmaHQ rule for a readable logsource, through the DuckDB dialect, run on DuckDB."""
import json, re, sys, pathlib
from collections import Counter
sys.path.insert(0, str(pathlib.Path(__file__).parent))
import duckdb, yaml
from sigma.collection import SigmaCollection
from duck_dialect import DuckDialect
from convert_all import TARGETS, fields_in

TARGETS = TARGETS + [{"product": "linux"}]   # generic linux (syslog) rules, no service
def target_of(ls):
    for t in TARGETS:
        if all(ls.get(k) == v for k, v in t.items()) and all(k in t or ls.get(k) is None for k in ("category", "product", "service")):
            return "/".join(f"{k}={v}" for k, v in t.items())
repo, out = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
b = DuckDialect(fulltext_field="raw")
res = []
for d in ("rules", "rules-threat-hunting", "rules-emerging-threats", "rules-compliance"):
    for p in sorted((repo / d).rglob("*.yml")):
        doc = yaml.safe_load(p.read_text(encoding="utf-8")); t = target_of(doc.get("logsource") or {})
        if not t: continue
        r = {"target": t, "file": p.relative_to(repo).as_posix(), "id": doc["id"], "title": doc["title"],
             "author": doc.get("author"), "level": doc.get("level"), "status": doc.get("status")}
        try:
            r["queries"] = b.convert(SigmaCollection.from_yaml(p.read_text(encoding="utf-8")))
        except Exception as e:
            r["error"] = f"{type(e).__name__}: {e}"; res.append(r); continue
        fl = sorted({f for q in r["queries"] for f in re.findall(r'"([^"]+)"', q)} - {"logs"})
        r["fields"] = fl
        con = duckdb.connect(); con.execute("CREATE TABLE logs (" + ", ".join(f'"{f}" VARCHAR' for f in fl or ["raw"]) + ")")
        try:
            for q in r["queries"]: con.execute(q).fetchall()
            r["duckdb"] = "ok"
        except Exception as e:
            r["duckdb"] = f"{type(e).__name__}: {str(e)[:200]}"
        res.append(r)
out.write_text(json.dumps(res, indent=1), encoding="utf-8")
print("by target:", Counter(r["target"] for r in res))
print("convert errors:", [(r["file"], r["error"][:120]) for r in res if "error" in r])
print("duckdb fails:", [(r["file"], r["duckdb"]) for r in res if r.get("duckdb", "ok") != "ok"])
print("ok:", sum(r.get("duckdb") == "ok" for r in res), "of", len(res))
print("status:", Counter(r["status"] for r in res), "level:", Counter(r["level"] for r in res))
