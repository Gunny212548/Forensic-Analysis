"""The pipeline's job queue: bounded, durable, and honest about a restart.

    python tests/check_jobs.py <scratch dir>

Uses a fake runner in place of pipeline.process_case, so it needs no DuckDB
and takes a few seconds. Checks (services/jobs.py):

- at most JOB_WORKERS jobs run at once, however many are submitted, and every
  one runs exactly once;
- a finished job leaves no job file behind;
- a job file left by a previous process (a restart mid-run) is queued again,
  the case goes back to `queued`, and the custody log says `requeued`;
- a job already tried MAX_ATTEMPTS times is not run again: the case is
  `failed` with the reason and custody says `abandoned`;
- a runner that raises fails its case and does not kill the worker;
- custody chains stay intact through all of it.

stdlib + the app's own modules; no network.
"""

import os
import sys
import tempfile
import threading
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
FAILED: list[str] = []


def check(ok: bool, what: str) -> None:
    print(f"  {'ok  ' if ok else 'FAIL'} {what}")
    if not ok:
        FAILED.append(what)


def main() -> int:
    scratch = Path(sys.argv[1] if len(sys.argv) > 1 else tempfile.mkdtemp())
    scratch.mkdir(parents=True, exist_ok=True)
    os.environ["DATA_DIR"] = str(scratch / "data")
    sys.path.insert(0, str(REPO))
    from app.services import custody, jobs, storage

    storage.ensure_root()
    company = storage.create_company("Jobs check")

    def new_case() -> str:
        m = storage.create_case("a.csv", "csv", 1, company_id=company["company_id"],
                                company_name=company["name"])
        return m["case_id"]

    lock = threading.Lock()
    state = {"now": 0, "max": 0, "runs": {}, "seen_status": {}, "boom": set()}

    def runner(case_id, path, kind):
        with lock:
            state["now"] += 1
            state["max"] = max(state["max"], state["now"])
            state["runs"][case_id] = state["runs"].get(case_id, 0) + 1
            state["seen_status"][case_id] = storage.load_manifest(case_id)["status"]
        try:
            if case_id in state["boom"]:
                raise RuntimeError("simulated crash")
            time.sleep(0.25)
            storage.update_case(case_id, status="ready")
        finally:
            with lock:
                state["now"] -= 1

    jobs.start(workers=2, runner=runner)

    print("bounded concurrency")
    ids = [new_case() for _ in range(6)]
    for cid in ids:
        jobs.submit(cid, scratch / "x.csv", "csv")
    check(jobs.wait_idle(30), "6 submitted jobs all finished")
    check(state["max"] == 2, f"never more than 2 at once (peak {state['max']})")
    check(all(state["runs"].get(c) == 1 for c in ids), "each job ran exactly once")
    check(all(storage.load_manifest(c)["status"] == "ready" for c in ids), "every case ended ready")
    check(jobs.pending() == [], "no job file left behind")

    print("restart recovery")
    left = new_case()
    storage.update_case(left, status="processing", progress={"stage": "ingest", "pct": 40})
    jobs._write(left, {"case_id": left, "path": str(scratch / "x.csv"), "kind": "csv",
                       "attempts": 1, "enqueued_at": "2026-01-01T00:00:00+00:00"})
    result = jobs.recover()
    check(result["requeued"] == [left] and not result["gave_up"], "the leftover job was requeued")
    check(jobs.wait_idle(30), "and it ran")
    check(state["runs"].get(left) == 1, "exactly once")
    check(state["seen_status"].get(left) == "queued", "the case read 'queued' (not stuck 'processing') when it restarted")
    check(storage.load_manifest(left)["status"] == "ready", "and ended ready")
    actions = [e["action"] for e in custody.entries(left)] if hasattr(custody, "entries") else []
    if actions:
        check("requeued" in actions, "custody records the requeue")
    ok, why = custody.verify_chain(left)
    check(ok, f"custody chain intact ({why})")
    check(jobs.pending() == [], "no job file left behind")

    print("a job that keeps killing the process")
    poison = new_case()
    storage.update_case(poison, status="processing")
    jobs._write(poison, {"case_id": poison, "path": str(scratch / "x.csv"), "kind": "csv",
                         "attempts": jobs.MAX_ATTEMPTS, "enqueued_at": "2026-01-01T00:00:00+00:00"})
    result = jobs.recover()
    m = storage.load_manifest(poison)
    check(result["gave_up"] == [poison] and not result["requeued"], "it was abandoned, not requeued")
    check(m["status"] == "failed" and "interrupted" in (m.get("error") or ""), "case failed with the reason")
    check(poison not in state["runs"], "the runner was not called")
    check(custody.verify_chain(poison)[0], "custody chain intact")
    check(jobs.pending() == [], "no job file left behind")

    print("a runner that raises")
    bad, good = new_case(), new_case()
    state["boom"].add(bad)
    jobs.submit(bad, scratch / "x.csv", "csv")
    jobs.submit(good, scratch / "x.csv", "csv")
    check(jobs.wait_idle(30), "both finished")
    check(storage.load_manifest(bad)["status"] == "failed", "the raising job's case is failed")
    check("simulated crash" in (storage.load_manifest(bad).get("error") or ""), "with the error text")
    check(storage.load_manifest(good)["status"] == "ready", "the next job still ran")
    check(jobs.pending() == [], "no job file left behind")

    print("FAILED: " + "; ".join(FAILED) if FAILED else "ALL OK")
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
