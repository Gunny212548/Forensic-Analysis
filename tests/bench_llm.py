"""Compare local Ollama models on the narrative, against ground truth.

    python tests/bench_llm.py <scratch dir> [model ...] [--runs N]

Builds a throwaway store in <scratch dir>, zips gen_usecase's two files into
ONE case (so the planted chain spans auth + firewall), then runs the real
/analyze route once per model per run - each in its own process, because
config reads LLM_PROVIDER/OLLAMA_MODEL at import - and grades the output with
tests/bench_llm_one.py against tests/README.md's "What the AI layer should
say": expected stages hit, stages and ATT&CK ids no evidence supports,
planted entities named, benign host kept out of the chain, completeness.

Needs Ollama on localhost:11434 and the app's dependencies (fastapi, duckdb).
Nothing touches the real store: the account and case live in <scratch dir>.
Results of 2026-10-12 are recorded in CLAUDE.md (Environment / secrets).
"""

import argparse
import collections
import json
import os
import subprocess
import sys
import zipfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DEFAULT_MODELS = ["qwen2.5:7b-instruct", "qwen3.5:9b", "gemma4:e4b", "gemma4:12b-it-qat"]
EMAIL, PASSWORD = "bench@test.local", "bench-throwaway-password"


def setup(scratch: Path) -> str:
    store, uc = scratch / "store", scratch / "usecase"
    store.mkdir(parents=True, exist_ok=True)
    subprocess.run([sys.executable, str(REPO / "tests" / "gen_usecase.py"), str(uc)],
                   check=True, capture_output=True)
    zpath = uc / "nightfall.zip"
    with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED) as z:
        for name in ("nightfall-auth.log", "nightfall-firewall.csv"):
            z.write(uc / name, name)
    env = {**os.environ, "DATA_DIR": str(store)}
    subprocess.run([sys.executable, str(REPO / "tools" / "create_user.py"), "add", EMAIL,
                    "--name", "Bench", "--role", "analyst", "--password-stdin"],
                   input=PASSWORD + "\n", text=True, env=env, capture_output=True)
    code = (
        "import sys; sys.path.insert(0, sys.argv[1])\n"
        "from fastapi.testclient import TestClient\nfrom app.main import app\n"
        "c = TestClient(app)\n"
        f"c.post('/api/auth/login', json={{'email': '{EMAIL}', 'password': '{PASSWORD}'}})\n"
        "with open(sys.argv[2], 'rb') as fh:\n"
        "    m = c.post('/api/upload', files={'file': ('nightfall.zip', fh)}, data={'company_name': 'Bench'}).json()\n"
        "print(m['case_id'])\n"
    )
    out = subprocess.run([sys.executable, "-c", code, str(REPO), str(zpath)], env=env,
                         capture_output=True, text=True, check=True)
    return out.stdout.strip().splitlines()[-1]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("scratch")
    ap.add_argument("models", nargs="*")
    ap.add_argument("--runs", type=int, default=3)
    args = ap.parse_args()
    scratch = Path(args.scratch)
    case_id = setup(scratch)
    env = {**os.environ, "DATA_DIR": str(scratch / "store"),
           "BENCH_EMAIL": EMAIL, "BENCH_PASSWORD": PASSWORD}
    rows = []
    for model in args.models or DEFAULT_MODELS:
        for run in range(1, args.runs + 1):
            p = subprocess.run([sys.executable, str(REPO / "tests" / "bench_llm_one.py"),
                                str(REPO), case_id, model, str(run)],
                               env=env, capture_output=True, text=True)
            line = (p.stdout.strip().splitlines() or ['{"model": "%s", "http": 0}' % model])[-1]
            r = json.loads(line)
            rows.append(r)
            print(json.dumps(r, ensure_ascii=False))
    by = collections.defaultdict(list)
    for r in rows:
        by[r["model"]].append(r)
    print(f"\n{'model':22} ok   avg_s  exp_stages  unsup_stages  unsup_tech  entities  benign")
    for m, rs in by.items():
        ok = [r for r in rs if r.get("http") == 200 and not r.get("missing")]
        if not ok:
            print(f"{m:22} 0/{len(rs)}")
            continue
        avg = lambda f: sum(f(r) for r in ok) / len(ok)  # noqa: E731
        print(f"{m:22} {len(ok)}/{len(rs)} {avg(lambda r: r['secs']):7.1f} "
              f"{avg(lambda r: len(r['expected_stage_hits'])):10.2f} "
              f"{sum(len(r['unsupported_stages']) for r in ok):12} "
              f"{sum(len(r['unsupported_techniques']) for r in ok):10} "
              f"{avg(lambda r: len(r['entities_named'])):8.2f} "
              f"{sum(r['benign_in_chain'] for r in ok):6}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
