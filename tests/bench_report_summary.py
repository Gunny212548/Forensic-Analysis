"""Measure the report's AI Executive Summary on a real project (specs/forensic_report.md R-D10).

Runs report_summary.draft on the project's confirmed groups N times and prints each run's
paragraphs, the grounding refusals, the time and the tokens. Reads the store; writes nothing.

    python tests/bench_report_summary.py <case_id> [--runs 3] [--module /tmp/report_summary.py]

--module loads report_summary from a file instead of the installed app (to measure a branch
inside the running container without touching it). Needs Ollama (gotcha #64)."""
import argparse
import importlib.util
import json
import sys

sys.path.insert(0, "/app")
from app.services.case import projects  # noqa: E402
from app.services.store import storage  # noqa: E402


def load(path):
    if not path:
        from app.services.report import report_summary
        return report_summary
    spec = importlib.util.spec_from_file_location("app.services.report.report_summary", path)
    mod = importlib.util.module_from_spec(spec)
    mod.__package__ = "app.services.report"
    spec.loader.exec_module(mod)
    return mod


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("case_id")
    ap.add_argument("--runs", type=int, default=3)
    ap.add_argument("--module")
    a = ap.parse_args()
    rs = load(a.module)
    m = storage.load_manifest(a.case_id)
    t = projects.timeline(m["company_id"], m["project_id"])
    g = projects.graph(m["company_id"], m["project_id"])
    if t["undecided"]:
        sys.exit(f"{t['undecided']} suggestions not decided - no draft")
    q = (storage.load_project(m["company_id"], m["project_id"]) or {}).get("question")
    question = q.get("question") if isinstance(q, dict) else q
    groups, edges = t["findings"], g["graph"]["edges"]
    print(f"{len(groups)} confirmed groups, {len(edges)} edges, model {rs.config.LLM_MODEL}")
    texts = []
    for run in range(1, a.runs + 1):
        out = rs.draft(question, groups, edges)
        u = out.get("usage") or {}
        print(f"\n=== run {run}: {out['seconds']} s, completion {u.get('completion_tokens')} tokens, "
              f"finish {u.get('finish')}, kept {len(out['paragraphs'])}, refused {len(out['warnings'])}, "
              f"error {out['error']}")
        for p in out["paragraphs"]:
            print(f"  [{', '.join(p['refs'])}] {p['text']}")
        for w in out["warnings"]:
            print(f"  REFUSED [{', '.join(w['refs'] or [])}] {w['problems']}: {w['text']}")
        texts.append(json.dumps(out["paragraphs"], ensure_ascii=False))
    print(f"\nidentical runs: {len(set(texts)) == 1}")


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    main()
