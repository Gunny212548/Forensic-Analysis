# ADR-001: Pipeline jobs run in a bounded, durable queue

Status: Accepted (2026-10-19), revised after code review the same day
Code: `app/services/jobs.py` · Tests: `tests/check_jobs.py`

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
(`state, path, kind, attempts, running, suspect, enqueued_at, started_at`). It is written
**when the case is created** and deleted when the work ends; the outcome is on the case
manifest (`ready` / `failed`), as before. "A job file exists" therefore means "this case
has not finished".

- `state` is `receiving` while an upload or merge is still writing the evidence
  (`jobs.begin`), and `queued` once `jobs.submit` hands it to the pool.
- `JOB_WORKERS` (default 2) daemon threads read an in-memory FIFO queue. Everything
  beyond that waits, and the case reads `queued`.
- `submit()` starts the pool if nobody has, and **refuses** (`JobActive`) a case that
  already has a job queued or running instead of overwriting its file.
- On startup `recover()` (once per process) looks at every job file, found by where it
  is, and decides:

  | job file says | manifest says | recovery |
  |---|---|---|
  | anything | no manifest (pruned) | remove the job file |
  | anything | `ready` / `failed` | remove the job file; **never overwrite the outcome** |
  | `receiving` | `queued` | fail the case: the evidence copy is incomplete, upload/merge again; custody `upload_interrupted` |
  | `queued` / `running` | `queued` / `processing` | queue again; custody `requeued` |
  | `running`, attempts >= 3 | `queued` / `processing` | fail the case; custody `abandoned` |

- **What counts as an attempt** (the part code review changed). A worker raises
  `attempts` when it starts a job. A job that was `running` when the process died is a
  *suspect*: it may have caused the stop (out of memory) or merely have been running beside
  the one that did. Suspects are run **alone, one at a time**, so a repeat can only be their
  own. A suspect that has stopped the application 3 times is abandoned; the innocent one
  finishes on its own run and is never blamed.
- **A deliberate stop is not an attempt.** The app's shutdown hook calls `jobs.stop()`:
  running jobs give their attempt back (`attempts - 1`, `running: false`) and no worker
  starts anything new. A deploy (`docker compose up --force-recreate`) or a reboot during a
  10 GB ingest therefore costs nothing. Only an unannounced stop (SIGKILL, OOM, power) counts.
- `tools/prune_cases.py` removes a case's job file with it and never prunes a case that is
  `queued` or `processing`.

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
- **Count every interruption as an attempt** (the first version). Rejected after review:
  with two workers an out-of-memory file takes the job beside it down too, and three
  deploys during a long ingest would abandon a healthy case with a wrong "possibly out of
  memory" in the evidence record.

## Consequences

- Positive: bounded memory; a restart loses no work; every requeue, abandonment and
  interrupted upload is in the hash-chained custody log.
- Negative: **one process only.** The queue is in memory and recovery assumes no other
  process is running a job. Do not run two workers of the app on one `DATA_DIR`
  (same assumption as the per-case lock in ADR-002).
- Negative: a restart re-does the whole file, not just the remainder. Acceptable: the
  longest case is minutes, and the alternative is a checkpointing pipeline.
- Negative: after a crash the suspects run one at a time, so recovery of two large files
  takes the sum of their times, not the maximum. That is the price of knowing whose fault
  it was.
- Behaviour change: `POST /upload` and `POST /merge` return with the case `queued` and it
  is processed later - as they already did in production; only the in-process `TestClient`
  used to run it before returning. `check_customer_isolation.py`, `check_mcp.py` and
  `bench_llm.py` now wait for the case instead of assuming it.
- Not covered: the analysis map-reduce job (`cases.py::_run_map_reduce_job`) is a
  coroutine on the event loop with its own job record and stale rule. It is not unified
  with this queue; its restart behaviour is the old, time-based one. Adding a reprocess
  route is safe with respect to the queue (`JobActive`), but that route must set the
  manifest back to `queued` itself.
- An upload cut off while the browser is still sending creates no case at all (Starlette
  spools the whole body before the handler runs, gotcha #25). The `receiving` window is
  the copy from that spool into `raw/`, and the merge concatenation (13 GB for the
  FortiGate set).

## Verified (2026-10-19, container built from the branch, scratch volume)

- `check_jobs.py`: 45 checks - peak 2 of 6 concurrent jobs and each run once; suspects
  never run beside another job and the innocent one finishes `ready`; abandonment;
  a `ready` case with an exhausted job file stays `ready`; an orphan job is dropped
  without creating `_unowned`; an interrupted upload fails its case; `stop()` returns the
  attempt; a second `submit` is refused and leaves the running job's file alone; a second
  `start()` writes no false `requeued`; a raising runner does not kill its worker.
- Real pipeline, 178 MB / 1,800,000-row log:
  - `docker kill` at 5% ingest, then `docker start`: custody `requeued` with
    `attempts=1, suspect=true`, case `ready`, 1,800,000 rows.
  - `docker stop` (SIGTERM) at 5% ingest, then `docker start`: `requeued` with
    `attempts=0, suspect=false`, case `ready`, 1,800,000 rows.
- Real merge of two 178 MB cases, `docker kill` during the concatenation: after restart the
  merged case is `failed` with the "upload, or merge, again" message and custody
  `upload_interrupted`.
- 5 simultaneous uploads of 60 MB: peak 2 `processing` at once, all five `ready`.
- `tools/prune_cases.py` dry run: reports a duplicate, and reports none when that
  duplicate is `processing`.
- `check_parity.py` on gen_usecase (4 files) and `tests/samples` (2): exact match;
  `check_rule_meta`, `check_customer_isolation` and `check_mcp` pass (the last two also
  pass on `main`). The 98-case corpus was not re-run (the change is outside ingest,
  decode and rules).
