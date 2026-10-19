"""Pipeline jobs: a bounded worker pool, and work that survives a restart.

Until now an upload ran its pipeline in whatever thread FastAPI's
BackgroundTasks handed it: five large uploads meant five DuckDB ingests at
once, and a container restart mid-run left the case `processing` forever,
because nothing remembered it had been started.

A job is one small file, `customers/<id>/jobs/<case_id>.json`. It is written
when the case is created - state `receiving` while an upload or merge is still
writing the evidence, `queued` once it is handed to the pool - and deleted when
the work ends (the outcome lives on the case manifest: `ready` or `failed`). So
"a job file exists" means "this case has not finished", and on startup
`recover()` decides what each one needs:

- `receiving`: the restart cut the upload off; the raw file is partial. The case
  is failed with that explanation (there is nothing to re-run).
- manifest already `ready` / `failed`: the process died between finishing the
  case and deleting the file. Nothing is re-run and nothing is overwritten; the
  stale file is removed.
- no manifest: the case was deleted (tools/prune_cases.py) while its job was
  waiting. The file is removed.
- otherwise queued again; custody records `requeued`.

Re-running is safe: process_case re-verifies the evidence digest, drops the
case DuckDB and starts clean (gotcha #28).

**What counts as an attempt.** `attempts` is raised when a worker starts a job and
the file says `running`. A job that was running when the process died is a
*suspect*: it may have caused the stop (out of memory) or merely been beside
the job that did. Suspects are therefore run alone, one at a time, so a second
failure can only be their own. A suspect that has stopped the process
MAX_ATTEMPTS times is abandoned; one that was merely beside the culprit finishes
alone and is never abandoned. A graceful shutdown (`stop()`, from the app's
shutdown hook: a deploy, a reboot) gives the attempt back - only a stop nobody
announced counts.

One process only. The queue is in memory and recovery assumes nothing else is
running a job - the same single-process assumption as the case locks in
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
from typing import Callable, Iterator

from .. import config
from . import custody, storage

log = logging.getLogger("forensic.jobs")

MAX_ATTEMPTS = 3
RECEIVING, QUEUED = "receiving", "queued"


class JobActive(RuntimeError):
    """The case already has a job queued or running."""


_queue: "queue.Queue[str]" = queue.Queue()
_queued: set[str] = set()      # case ids waiting or running, so a job is never queued twice
_running: set[str] = set()     # case ids a worker is executing right now
_guard = threading.Lock()
_workers: list[threading.Thread] = []
_runner: Callable[[str, Path, str], None] | None = None
_stopping = False
_recovered = False

# Suspects run alone: a plain job needs `not _excl`, a suspect needs nothing else running.
_gate = threading.Condition()
_active = 0
_excl = False
_suspects_waiting = 0


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ------------------------------------------------------------------ job files

def _jobs_dir(case_id: str, create: bool = True) -> Path:
    d = storage.case_dir(case_id, "jobs")
    # A case nobody owns resolves to the never-created _unowned store; reading
    # or removing its job must not make that directory exist (storage.py).
    if create and d.parent.name != storage._UNOWNED:
        d.mkdir(parents=True, exist_ok=True)  # stores made before jobs existed lack it
    return d


def _job_path(case_id: str, create: bool = True) -> Path:
    return _jobs_dir(case_id, create) / f"{case_id}.json"


def _write(case_id: str, job: dict) -> None:
    path = _job_path(case_id)
    tmp = path.with_name(f"{path.name}.{os.getpid()}.{threading.get_ident()}.tmp")
    try:
        tmp.write_text(json.dumps(job, indent=2), encoding="utf-8")
        storage._replace_retry(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)


def _read_path(path: Path) -> dict | None:
    for attempt in range(20):
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError):
            return None
        except PermissionError:  # Windows: being swapped by a concurrent _write
            if attempt == 19:
                raise
            time.sleep(0.005 * (attempt + 1))


def _read(case_id: str) -> dict | None:
    return _read_path(_job_path(case_id, create=False))


def _finish(case_id: str) -> None:
    with _guard:
        try:
            _job_path(case_id, create=False).unlink(missing_ok=True)
        except OSError:
            log.exception("could not remove the job file of %s", case_id)
        _queued.discard(case_id)
        _running.discard(case_id)


def _job_files() -> Iterator[Path]:
    """Every job file, found by where it is, not by asking who owns the case -
    a job whose case is gone has no owner to ask."""
    root = storage.customers_dir()
    for store in (sorted(root.iterdir()) if root.is_dir() else []):
        if storage.valid_company_id(store.name):
            yield from sorted((store / "jobs").glob("case-*.json"))


def pending() -> list[str]:
    """Case ids that have a job file, in every customer's store."""
    return [p.stem for p in _job_files()]


# ---------------------------------------------------------------- submitting

def begin(case_id: str) -> None:
    """The case exists but its evidence is still arriving (upload, merge). If
    the process stops now, recover() fails the case instead of leaving it
    `queued` for ever."""
    storage.require_owner(case_id)
    _write(case_id, {"case_id": case_id, "state": RECEIVING, "attempts": 0,
                     "enqueued_at": _now()})


def cancel(case_id: str) -> None:
    """The upload or merge was refused: its job goes with it."""
    _job_path(case_id, create=False).unlink(missing_ok=True)


def submit(case_id: str, path: Path, kind: str) -> None:
    """Record the job, then queue it. Returns at once. Starts the pool if
    nobody has (a submitted job must never sit in a queue nothing reads).
    A case that already has a job queued or running is refused, not
    overwritten: that file is the only record of the run in progress."""
    storage.require_owner(case_id)
    _ensure_workers()
    with _guard:
        if case_id in _queued:
            raise JobActive(f"{case_id} already has a job queued or running")
        _write(case_id, {"case_id": case_id, "state": QUEUED, "path": str(path), "kind": kind,
                         "attempts": 0, "enqueued_at": _now()})
        _queued.add(case_id)
    _queue.put(case_id)


def _enqueue(case_id: str) -> bool:
    with _guard:
        if case_id in _queued:
            return False
        _queued.add(case_id)
    _queue.put(case_id)
    return True


# ------------------------------------------------------------------- workers

def _ensure_workers(n: int | None = None) -> None:
    with _guard:
        n = n or config.JOB_WORKERS
        while len(_workers) < n:
            t = threading.Thread(target=_work, name=f"job-worker-{len(_workers) + 1}", daemon=True)
            t.start()
            _workers.append(t)


def _enter(suspect: bool) -> None:
    global _active, _excl, _suspects_waiting
    with _gate:
        if suspect:
            _suspects_waiting += 1
            try:
                _gate.wait_for(lambda: _active == 0)
            finally:
                _suspects_waiting -= 1
            _excl = True
        else:
            _gate.wait_for(lambda: not _excl and _suspects_waiting == 0)
        _active += 1


def _leave() -> None:
    global _active, _excl
    with _gate:
        _active -= 1
        _excl = False
        _gate.notify_all()


def _work() -> None:
    while True:
        case_id = _queue.get()
        try:
            if _stopping:  # shutting down: the job file stays and is recovered next start
                with _guard:
                    _queued.discard(case_id)
                continue
            job = _read(case_id)
            if job is None or job.get("state", QUEUED) != QUEUED:
                with _guard:
                    _queued.discard(case_id)
                continue
            if storage.load_manifest(case_id) is None:  # deleted while it waited
                log.warning("job %s: the case no longer exists, dropping it", case_id)
                _finish(case_id)
                continue
            _enter(bool(job.get("suspect")))
            try:
                with _guard:
                    _running.add(case_id)
                    job["attempts"] = job.get("attempts", 0) + 1
                    job["running"] = True
                    job["started_at"] = _now()
                    _write(case_id, job)
                try:
                    (_runner or _default_runner)(case_id, Path(job["path"]), job["kind"])
                except Exception as exc:  # noqa: BLE001 - process_case reports its own; this is the backstop
                    log.exception("job %s raised", case_id)
                    storage.update_case(case_id, status="failed",
                                        error=f"{type(exc).__name__}: {exc}")
            finally:
                _leave()
            _finish(case_id)
        except Exception:  # noqa: BLE001 - a worker must outlive any single job
            log.exception("worker error on %s", case_id)
            with _guard:
                _queued.discard(case_id)
                _running.discard(case_id)
        finally:
            _queue.task_done()


def _default_runner(case_id: str, path: Path, kind: str) -> None:
    from . import pipeline  # imported late: pipeline pulls in duckdb and the rules
    pipeline.process_case(case_id, path, kind)


# ------------------------------------------------------------ restart / stop

def stop() -> None:
    """The app is shutting down on purpose (deploy, reboot). Jobs still running
    give their attempt back, so only an unannounced stop counts against a file,
    and no worker starts anything new."""
    global _stopping, _recovered
    with _guard:
        _stopping = True
        _recovered = False  # a later start() in this process recovers again
        for case_id in list(_running):
            job = _read(case_id)
            if job and job.get("running"):
                job["attempts"] = max(0, job.get("attempts", 1) - 1)
                job["running"] = False
                job["stopped_at"] = _now()
                _write(case_id, job)


def recover() -> dict:
    """Decide what every job file left by a previous process needs (module
    docstring). Returns what it did."""
    out = {"requeued": [], "gave_up": [], "settled": [], "interrupted_uploads": [], "orphans": []}
    for path in _job_files():
        case_id = path.stem
        with _guard:
            if case_id in _queued:  # this process is already running it
                continue
        job = _read_path(path)
        if job is None:
            log.warning("job file %s is unreadable; left in place", path)
            continue
        manifest = storage.load_manifest(case_id)
        if manifest is None:
            log.warning("job %s: its case no longer exists; removing the job", case_id)
            path.unlink(missing_ok=True)
            out["orphans"].append(case_id)
            continue
        if manifest.get("status") in ("ready", "failed"):
            path.unlink(missing_ok=True)  # finished; only the cleanup was missed
            out["settled"].append(case_id)
            continue
        if job.get("state") == RECEIVING:
            storage.update_case(
                case_id, status="failed", progress=None,
                error="The application restarted before this case's evidence was completely "
                      "written (an upload or a merge was in progress), so the stored copy is "
                      "incomplete. Upload it, or merge, again.")
            custody.record(case_id, "upload_interrupted", "system",
                           reason="restart before the whole file was received")
            path.unlink(missing_ok=True)
            out["interrupted_uploads"].append(case_id)
            continue
        attempts = job.get("attempts", 0)
        was_running = bool(job.get("running"))
        if was_running and attempts >= MAX_ATTEMPTS:
            storage.update_case(
                case_id, status="failed", progress=None,
                error=f"The application stopped {attempts} times while it was processing this "
                      "case (after the first, with nothing else running), so the file itself is "
                      "the likely cause - for example running out of memory. Not retried again.")
            custody.record(case_id, "abandoned", "system", attempts=attempts,
                           reason="the application stopped repeatedly while processing it")
            path.unlink(missing_ok=True)
            out["gave_up"].append(case_id)
            continue
        if was_running:  # suspect: next run is alone (see module docstring)
            job["suspect"] = True
            job["running"] = False
            _write(case_id, job)
        storage.update_case(case_id, status="queued", progress=None)
        custody.record(case_id, "requeued", "system", attempts=attempts, suspect=was_running,
                       reason="restart while the case was queued or processing")
        _enqueue(case_id)
        out["requeued"].append(case_id)
    return out


def start(workers: int | None = None, runner: Callable | None = None) -> dict:
    """Start the pool (once) and recover leftover jobs (once per process: a
    second call while jobs run must not requeue them)."""
    global _runner, _stopping, _recovered
    if runner is not None:
        _runner = runner
    _stopping = False
    _ensure_workers(workers)
    if _recovered:
        return {}
    _recovered = True
    result = recover()
    if any(result.values()):
        log.warning("job recovery: %s", {k: len(v) for k, v in result.items() if v})
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
