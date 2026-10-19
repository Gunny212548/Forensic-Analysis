# ADR-001: Pipeline jobs run in a bounded, durable queue

Status: Accepted (2026-10-19) · Code: `app/services/jobs.py` · Tests: `tests/check_jobs.py`

## Context

An upload ran its pipeline with FastAPI `BackgroundTasks` + `asyncio.to_thread`.
Two defects, both read from the code and then reproduced:

1. **No bound.** Five large uploads meant five DuckDB ingests at once. Each holds a
   file stream and a database; the failure mode is an out-of-memory kill, not a
   slowdown.
2. **No memory of having started.** A container restart mid-run left the case
   `processing` forever. `on_startup` recovered nothing, and (unlike the analysis job,
   which has `JOB_STALE_SECONDS`) the pipeline had no stale rule. A 10 GB file takes
   ~8 minutes, so the window is real, and the only remedy was uploading again.

## Decision

A job is one file, `customers/<company_id>/jobs/<case_id>.json`
(`case_id, path, kind, attempts, enqueued_at, started_at`), written **before** the work
is queued and deleted when the work ends. The outcome is on the case manifest
(`ready` / `failed`), as before. "A job file exists" therefore means "this case has not
finished".

- `JOB_WORKERS` (default 2) daemon threads read an in-memory FIFO queue. Everything
  beyond that waits, and the case reads `queued`.
- On startup `jobs.start()` queues every leftover job file again; the case goes back to
  `queued`, and custody gets a `requeued` entry (who: `system`, with the attempt count).
- `attempts` is incremented each time a worker starts a job. At `MAX_ATTEMPTS` (3) a
  leftover job is **not** run again: the case is `failed` ("interrupted N times,
  possibly out of memory") and custody gets `abandoned`. Without this, a file that
  kills the process is retried at every restart for ever.
- `submit()` starts the pool if nobody has. A job must never sit in a queue nothing
  reads (found when the test harness built the app without its startup hook).
- Upload and merge call `jobs.submit()`; `BackgroundTasks` is gone from both.

Re-running is safe because `process_case` already re-verifies the evidence SHA-256,
refuses on mismatch, and drops the case DuckDB before starting (gotcha #28).

## Alternatives considered

- **Celery / RQ + Redis.** Mature, and handles several replicas. Rejected: a broker to
  operate for a tool with a handful of analysts, and the app must work air-gapped
  (gotcha #17).
- **A SQLite / DuckDB job table.** Fine, but one more database; a per-case file matches
  how review, custody and manifests are already stored, and lives in the customer's own
  store (gotcha #40), so one customer's queue state is never beside another's.
- **Only a semaphore, no persistence.** Fixes defect 1, not defect 2.

## Consequences

- Positive: bounded memory; a restart loses no work; every requeue and abandonment is
  in the hash-chained custody log.
- Negative: **one process only.** The queue is in memory and recovery assumes no other
  process is running a job. Do not run two workers of the app on one `DATA_DIR`
  (same assumption as the per-case lock in ADR-002).
- Negative: a restart re-does the whole file, not just the remainder. Acceptable: the
  longest case is minutes, and the alternative is a checkpointing pipeline.
- Behaviour change: `POST /upload` and `POST /merge` return with the case `queued`
  and it is processed later - as they already did in production; only the in-process
  `TestClient` used to run it before returning. `check_customer_isolation.py`,
  `check_mcp.py` and `bench_llm.py` now wait for the case instead of assuming it.
- Not covered: the analysis map-reduce job (`cases.py::_run_map_reduce_job`) is a
  coroutine on the event loop with its own job record and stale rule. It is not
  unified with this queue; its restart behaviour is the old, time-based one.

## Verified (2026-10-19, container built from the branch, scratch volume)

- `check_jobs.py`: 23 checks - peak 2 of 6 concurrent jobs, each run once, leftover job
  requeued, poison job abandoned, a raising runner does not kill its worker.
- Real pipeline: 178 MB / 1,800,000-row log, `docker kill` at 5% ingest, `docker start`:
  `requeued` -> `ready`, 1,800,000 rows, custody `acquired, verified, requeued,
  verified, processed`. Run twice (before and after the lazy-start fix).
- Real pipeline, 5 simultaneous uploads of 60 MB: peak 2 `processing` at once, all
  five `ready`.
- `check_parity.py` on gen_usecase (4 files) and `tests/samples` (2): exact match.
  The 98-case corpus was not re-run (the change is outside ingest, decode and rules).
- `check_customer_isolation.py` and `check_mcp.py` pass; both pass on `main` too.
