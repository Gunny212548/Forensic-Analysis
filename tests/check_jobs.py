"""The pipeline's job queue: bounded, durable, and honest about a restart.

    python tests/check_jobs.py <scratch dir>

Uses a fake runner in place of pipeline.process_case, so it needs no DuckDB
and takes a few seconds. Checks (services/jobs.py, docs/adr/ADR-001):

- at most JOB_WORKERS jobs run at once, however many are submitted, and every
  one runs exactly once; a finished job leaves no job file;
- a job file left by a previous process is queued again, the case goes back to
  `queued`, and custody says `requeued`;
- jobs that were running when the process died are suspects and run ALONE, so
  one that was merely beside the culprit finishes and is not blamed;
- a suspect already stopped MAX_ATTEMPTS times is abandoned (`failed`, custody
  `abandoned`) and not run again;
- a case that finished (`ready`) before its job file was removed is left alone,
  even with attempts exhausted - recovery never overwrites an outcome;
- a job whose case was deleted is removed, and recovery does not create the
  `_unowned` store for it;
- an upload cut off by a restart (state `receiving`) fails its case;
- a graceful stop gives the running job's attempt back;
- submitting a case that already has a job is refused and does not touch the
  running job's file; calling start() again while a job runs requeues nothing;
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
    store = Path(os.environ["DATA_DIR"]) / "customers" / company["company_id"]

    def new_case() -> str:
        m = storage.create_case("a.csv", "csv", 1, company_id=company["company_id"],
                                company_name=company["name"])
        return m["case_id"]

    def job_file(case_id: str, **fields) -> None:
        job = {"case_id": case_id, "state": "queued", "path": str(scratch / "x.csv"),
               "kind": "csv", "attempts": 0, "enqueued_at": "2026-01-01T00:00:00+00:00"}
        job.update(fields)
        jobs._write(case_id, job)

    def actions(case_id: str) -> list[str]:
        return [e["action"] for e in custody.entries(case_id)]

    lock = threading.Lock()
    st = {"now": 0, "max": 0, "runs": {}, "seen_status": {}, "boom": set(), "running": set(),
          "block": {}, "suspects": set(), "violations": []}

    def runner(case_id, path, kind):
        with lock:
            st["now"] += 1
            st["max"] = max(st["max"], st["now"])
            st["runs"][case_id] = st["runs"].get(case_id, 0) + 1
            st["seen_status"][case_id] = storage.load_manifest(case_id)["status"]
            others = st["running"] - {case_id}
            if others and (case_id in st["suspects"] or others & st["suspects"]):
                st["violations"].append(case_id)
            st["running"].add(case_id)
        try:
            storage.update_case(case_id, status="processing")
            if case_id in st["boom"]:
                raise RuntimeError("simulated crash")
            gate = st["block"].get(case_id)
            if gate:
                gate.wait(20)
            else:
                time.sleep(0.25)
            storage.update_case(case_id, status="ready")
        finally:
            with lock:
                st["now"] -= 1
                st["running"].discard(case_id)

    def wait_running(case_id: str) -> bool:
        end = time.monotonic() + 10
        while time.monotonic() < end:
            with lock:
                if case_id in st["running"]:
                    return True
            time.sleep(0.01)
        return False

    jobs.start(workers=2, runner=runner)

    print("bounded concurrency")
    ids = [new_case() for _ in range(6)]
    for cid in ids:
        jobs.submit(cid, scratch / "x.csv", "csv")
    check(jobs.wait_idle(30), "6 submitted jobs all finished")
    check(st["max"] == 2, f"never more than 2 at once (peak {st['max']})")
    check(all(st["runs"].get(c) == 1 for c in ids), "each job ran exactly once")
    check(all(storage.load_manifest(c)["status"] == "ready" for c in ids), "every case ended ready")
    check(jobs.pending() == [], "no job file left behind")

    print("restart recovery: suspects run alone")
    a, b = new_case(), new_case()
    st["suspects"] = {a, b}
    for cid in (a, b):
        storage.update_case(cid, status="processing", progress={"stage": "ingest", "pct": 40})
        job_file(cid, running=True, attempts=1)
    n = new_case()  # a plain job submitted right behind them
    jobs_before = st["max"]
    out = jobs.recover()
    jobs.submit(n, scratch / "x.csv", "csv")
    check(sorted(out["requeued"]) == sorted([a, b]) and not out["gave_up"], "both leftover jobs were requeued")
    check(jobs.wait_idle(30), "and they ran")
    check(st["runs"].get(a) == 1 and st["runs"].get(b) == 1, "exactly once each")
    check(st["seen_status"].get(a) == "queued", "the case read 'queued' (not stuck 'processing') when it restarted")
    check(not st["violations"], f"no job ran beside a suspect ({st['violations']})")
    check(all(storage.load_manifest(c)["status"] == "ready" for c in (a, b, n)),
          "all ended ready - the innocent one was not blamed")
    check("requeued" in actions(a) and custody.verify_chain(a)[0], "custody records the requeue, chain intact")
    check(jobs.pending() == [], "no job file left behind")
    st["suspects"] = set()

    print("a job that keeps stopping the process")
    poison = new_case()
    storage.update_case(poison, status="processing")
    job_file(poison, running=True, attempts=jobs.MAX_ATTEMPTS)
    out = jobs.recover()
    m = storage.load_manifest(poison)
    check(out["gave_up"] == [poison] and not out["requeued"], "it was abandoned, not requeued")
    check(m["status"] == "failed" and "stopped" in (m.get("error") or ""), "case failed with the reason")
    check(poison not in st["runs"], "the runner was not called")
    check("abandoned" in actions(poison) and custody.verify_chain(poison)[0], "custody says abandoned, chain intact")
    check(jobs.pending() == [], "no job file left behind")

    print("a case that finished before its job file was removed")
    done = new_case()
    storage.update_case(done, status="ready", total_rows=10)
    job_file(done, running=True, attempts=jobs.MAX_ATTEMPTS)
    out = jobs.recover()
    m = storage.load_manifest(done)
    check(out["settled"] == [done], "recovery settled it")
    check(m["status"] == "ready" and not m.get("error"), "still ready: the outcome was not overwritten")
    check(done not in st["runs"] and "abandoned" not in actions(done) and "requeued" not in actions(done),
          "not re-run and no false custody entry")
    check(jobs.pending() == [], "the stale job file was removed")

    print("a job whose case was deleted")
    gone = new_case()
    job_file(gone, running=True, attempts=1)
    storage.manifest_path(gone).unlink()
    out = jobs.recover()
    check(out["orphans"] == [gone] and gone not in st["runs"], "dropped, not run")
    check(not (store.parent / "_unowned").exists(), "recovery did not create the _unowned store")
    check(jobs.pending() == [], "the job file was removed")

    print("an upload cut off by a restart")
    cut = new_case()
    jobs.begin(cut)
    out = jobs.recover()
    m = storage.load_manifest(cut)
    check(out["interrupted_uploads"] == [cut], "recovery found it")
    check(m["status"] == "failed" and "restarted before" in (m.get("error") or ""),
          "the case failed with an upload-or-merge-again message")
    check("upload_interrupted" in actions(cut) and cut not in st["runs"], "custody says so; nothing ran")
    check(jobs.pending() == [], "the job file was removed")
    cancelled = new_case()
    jobs.begin(cancelled)
    jobs.cancel(cancelled)
    check(jobs.pending() == [], "a refused upload's job is cancelled")

    print("a graceful stop gives the attempt back")
    g = new_case()
    st["block"][g] = threading.Event()
    jobs.submit(g, scratch / "x.csv", "csv")
    check(wait_running(g), "the job is running")
    before = jobs._read(g)
    jobs.stop()
    after = jobs._read(g)
    check(before["attempts"] == 1 and before["running"], "while running: attempt 1, running")
    check(after["attempts"] == 0 and not after["running"], "after stop(): attempt returned, not running")
    st["block"][g].set()
    check(jobs.wait_idle(30), "the job still finished")
    check(storage.load_manifest(g)["status"] == "ready" and jobs.pending() == [], "ready, no file left")
    jobs.start(workers=2)  # a restart in the same process

    print("a second submit, a second start()")
    d = new_case()
    st["block"][d] = threading.Event()
    jobs.submit(d, scratch / "x.csv", "csv")
    check(wait_running(d), "the job is running")
    try:
        jobs.submit(d, scratch / "x.csv", "csv")
        refused = False
    except jobs.JobActive:
        refused = True
    j = jobs._read(d)
    check(refused and j and j["attempts"] == 1 and j["running"], "refused, and the running job's file is untouched")
    res = jobs.start()
    check(res == {} and storage.load_manifest(d)["status"] == "processing" and "requeued" not in actions(d),
          "start() again requeued nothing and wrote no false custody entry")
    st["block"][d].set()
    check(jobs.wait_idle(30) and st["runs"].get(d) == 1, "it ran exactly once")
    check(jobs.pending() == [], "no job file left behind")

    print("a runner that raises")
    bad, good = new_case(), new_case()
    st["boom"].add(bad)
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
