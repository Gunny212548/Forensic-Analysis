"""Pipeline jobs: a bounded worker pool, and work that survives a restart.

Until now an upload ran its pipeline in whatever thread FastAPI's
BackgroundTasks handed it: five large uploads meant five DuckDB ingests at
once, and a container restart mid-run left the case `processing` forever,
because nothing remembered it had been started.

A job is one small file, `customers/<id>/jobs/<case_id>.json`, written before
the work is queued and deleted when the work ends (the outcome lives on the
case manifest: `ready` or `failed`). So "a job file exists" means "this case
has not finished", and on startup every such file is queued again.

- Re-running is safe: process_case re-verifies the evidence digest, drops the
  case DuckDB and starts clean (gotcha #28), and the re-run is recorded in the
  custody log (`requeued`).
- `attempts` counts how often a worker has started the job. A file that kills
  the process (out of memory) would otherwise be retried at every restart
  forever; after MAX_ATTEMPTS the case is failed with that explanation.
- One process only. The queue is in memory and recovery assumes nothing else
  is running a job - the same single-process assumption as the case locks in
  storage.py. Do not run two workers of the app on one DATA_DIR.
"""

import json
import logging
import os
import queue
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from .. import config
from . import custody, storage

log = logging.getLogger("forensic.jobs")

MAX_ATTEMPTS = 3

_queue: "queue.Queue[str]" = queue.Queue()
_queued: set[str] = set()          # case ids waiting or running, so a job is never queued twice
_guard = threading.Lock()
_workers: list[threading.Thread] = []
_runner: Callable[[str, Path, str], None] | None = None


def _jobs_dir(case_id: str) -> Path:
    d = storage.case_dir(case_id, "jobs")
    d.mkdir(parents=True, exist_ok=True)  # stores made before jobs existed lack it
    return d


def _job_path(case_id: str) -> Path:
    return _jobs_dir(case_id) / f"{case_id}.json"


def _write(case_id: str, job: dict) -> None:
    path = _job_path(case_id)
    tmp = path.with_name(f"{path.name}.{os.getpid()}.{threading.get_ident()}.tmp")
    try:
        tmp.write_text(json.dumps(job, indent=2), encoding="utf-8")
        storage._replace_retry(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)


def _read(case_id: str) -> dict | None:
    try:
        return json.loads(_job_path(case_id).read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return None


def _finish(case_id: str) -> None:
    try:
        _job_path(case_id).unlink(missing_ok=True)
    except OSError:
        log.exception("could not remove the job file of %s", case_id)
    with _guard:
        _queued.discard(case_id)


def _ensure_workers(n: int | None = None) -> None:
    with _guard:
        n = n or config.JOB_WORKERS
        while len(_workers) < n:
            t = threading.Thread(target=_work, name=f"job-worker-{len(_workers) + 1}", daemon=True)
            t.start()
            _workers.append(t)


def submit(case_id: str, path: Path, kind: str) -> None:
    """Record the job, then queue it. Returns at once. Starts the pool if
    nobody has (a submitted job must never sit in a queue nothing reads)."""
    storage.require_owner(case_id)
    _ensure_workers()
    _write(case_id, {"case_id": case_id, "path": str(path), "kind": kind, "attempts": 0,
                     "enqueued_at": datetime.now(timezone.utc).isoformat()})
    _enqueue(case_id)


def _enqueue(case_id: str) -> None:
    with _guard:
        if case_id in _queued:
            return
        _queued.add(case_id)
    _queue.put(case_id)


def _work() -> None:
    while True:
        case_id = _queue.get()
        try:
            job = _read(case_id)
            if job is None:  # finished or cancelled while it waited
                with _guard:
                    _queued.discard(case_id)
                continue
            job["attempts"] = job.get("attempts", 0) + 1
            job["started_at"] = datetime.now(timezone.utc).isoformat()
            _write(case_id, job)
            try:
                (_runner or _default_runner)(case_id, Path(job["path"]), job["kind"])
            except Exception as exc:  # noqa: BLE001 - process_case reports its own; this is the backstop
                log.exception("job %s raised", case_id)
                storage.update_case(case_id, status="failed",
                                    error=f"{type(exc).__name__}: {exc}")
            _finish(case_id)
        except Exception:  # noqa: BLE001 - a worker must outlive any single job
            log.exception("worker error on %s", case_id)
            with _guard:
                _queued.discard(case_id)
        finally:
            _queue.task_done()


def _default_runner(case_id: str, path: Path, kind: str) -> None:
    from . import pipeline  # imported late: pipeline pulls in duckdb and the rules
    pipeline.process_case(case_id, path, kind)


def pending() -> list[str]:
    """Case ids that have a job file, in every customer's store."""
    out = []
    root = storage.customers_dir()
    for store in (root.iterdir() if root.is_dir() else []):
        if storage.valid_company_id(store.name):
            out += [p.stem for p in sorted((store / "jobs").glob("case-*.json"))]
    return out


def recover() -> dict:
    """Queue every job a previous process left behind; fail the ones that
    have already been tried MAX_ATTEMPTS times. Returns what it did."""
    requeued, gave_up = [], []
    for case_id in pending():
        job = _read(case_id)
        if job is None:
            continue
        if job.get("attempts", 0) >= MAX_ATTEMPTS:
            storage.update_case(
                case_id, status="failed",
                error=f"Processing was interrupted {job['attempts']} times (the container "
                      "stopped each time it ran) - possibly out of memory. Not retried again.")
            custody.record(case_id, "abandoned", "system", attempts=job["attempts"],
                           reason="interrupted repeatedly")
            _finish(case_id)
            gave_up.append(case_id)
            continue
        storage.update_case(case_id, status="queued", progress=None)
        custody.record(case_id, "requeued", "system", attempts=job.get("attempts", 0),
                       reason="restart while the case was queued or processing")
        _enqueue(case_id)
        requeued.append(case_id)
    return {"requeued": requeued, "gave_up": gave_up}


def start(workers: int | None = None, runner: Callable | None = None) -> dict:
    """Start the pool (once) and recover leftover jobs."""
    global _runner
    if runner is not None:
        _runner = runner
    _ensure_workers(workers)
    result = recover()
    if result["requeued"] or result["gave_up"]:
        log.warning("job recovery: %d requeued, %d abandoned", len(result["requeued"]),
                    len(result["gave_up"]))
    return result


def wait_idle(timeout: float = 30.0) -> bool:
    """Block until nothing is queued or running (tests)."""
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        with _guard:
            if not _queued:
                return True
        time.sleep(0.02)
    return False
