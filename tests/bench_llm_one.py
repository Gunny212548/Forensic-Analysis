"""One narrative run through the real /analyze route with a given Ollama
model, graded against tests/README.md's ground truth. Prints one JSON line.

Usage: DATA_DIR=<bench store> python tests/bench_llm_one.py <repo> <case_id> <model> <run>
Driven by tests/bench_llm.py, which builds the store and the case.
"""
import json
import os
import re
import sys
import time

repo, case_id, model, run = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
os.environ["LLM_PROVIDER"] = "ollama"
os.environ["OLLAMA_MODEL"] = model
os.environ["OLLAMA_BASE_URL"] = "http://localhost:11434"
sys.path.insert(0, repo)

from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402

c = TestClient(app)
c.post("/api/auth/login", json={"email": os.environ.get("BENCH_EMAIL", "e2e@test.local"),
                                "password": os.environ.get("BENCH_PASSWORD", "e2e-throwaway-password")})
t0 = time.time()
r = c.post(f"/api/cases/{case_id}/analyze?force=true")
secs = round(time.time() - t0, 1)
out = {"model": model, "run": int(run), "http": r.status_code, "secs": secs}
if r.status_code != 200:
    out["error"] = r.text[:300]
    print(json.dumps(out))
    sys.exit(0)
a = r.json()
meta = a.get("_meta", {})

# Ground truth (tests/README.md "What the AI layer should say").
EXPECTED_STAGES = {"Reconnaissance", "Credential Access", "Initial Access", "Persistence",
                   "Command and Control", "Exfiltration"}
# Stages with evidence in this case besides the planted chain: the port scan
# is Discovery (T1046), the root login can be read as Valid Accounts.
SUPPORTED_STAGES = EXPECTED_STAGES | {"Discovery"}
SUPPORTED_TECH = {"T1046", "T1110", "T1110.001", "T1110.003", "T1078", "T1078.003", "T1098",
                  "T1071", "T1071.001", "T1041", "T1105", "T1595", "T1087"}
ENTITIES = ["10.20.30.40", "root", "10.10.1.5", "203.0.113.77"]

chain = a.get("attack_chain") or []
stages = [s.get("stage", "") for s in chain if isinstance(s, dict)]
text_all = json.dumps(a, ensure_ascii=False)
chain_text = json.dumps(chain, ensure_ascii=False)
techs = set(re.findall(r"T\d{4}(?:\.\d{3})?", json.dumps(
    {k: a.get(k) for k in ("attack_chain", "timeline", "summary", "recommendations")})))

out.update({
    "finish": meta.get("finish_reason"),
    "completion_tokens": (meta.get("usage") or {}).get("completion_tokens"),
    "missing": meta.get("missing_keys") or [],
    "truncated": bool(meta.get("truncated")),
    "stages": stages,
    "expected_stage_hits": sorted(set(stages) & EXPECTED_STAGES),
    "unsupported_stages": sorted(set(stages) - SUPPORTED_STAGES),
    "unsupported_techniques": sorted(t for t in techs if t not in SUPPORTED_TECH),
    "entities_named": [e for e in ENTITIES if e in text_all],
    "benign_in_chain": "10.10.1.9" in chain_text,
    "timeline_n": len(a.get("timeline") or []),
    "recs_n": len(a.get("recommendations") or []),
    "grounding_unsupported": [(u["kind"], u["value"]) for u in (meta.get("grounding") or {}).get("unsupported", [])],
    "summary": (a.get("summary") or "")[:400],
})
print(json.dumps(out, ensure_ascii=False))
