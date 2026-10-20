# Gotcha #48

**48. Work is queued, durable and bounded, and a manifest is written atomically
(2026-10-19; `docs/adr/ADR-001`, `ADR-002`, branch `arch/atomic-manifest`, pushed,
not merged to main).** Found by reading the code, then reproduced:
- Uploads ran their pipeline in unbounded `BackgroundTasks` threads, and a restart left
  a case `processing` forever (nothing recovered it; only the analysis job had a stale
  rule). `storage.update_case` was load-modify-save with no lock and one shared
  `.json.tmp`, so concurrent writers (progress, the CSV estimator, status) lost each
  other's keys, put an older `status` back, and raised `PermissionError` on Windows.
- **`services/jobs.py`:** one file per case, `customers/<id>/jobs/<case>.json`
  (`state` receiving|queued, `attempts`, `running`, `suspect`), written when the case is
  created (`begin()` in upload and merge - while the evidence is still being written -,
  then `submit()`), deleted when the work ends. `JOB_WORKERS` (default 2) threads.
  `recover()` runs **once per process at startup**: no manifest -> drop the job;
  manifest already `ready`/`failed` -> drop it, **never overwrite the outcome**;
  `receiving` -> fail the case ("upload or merge again"); else queue again.
  **An attempt is an unannounced stop:** the shutdown hook `jobs.stop()` gives the
  attempt back (a deploy or `docker stop` costs nothing); a job that was running when
  the process died is a *suspect* and runs **alone**, so one that was merely beside an
  out-of-memory file is not blamed; a suspect stopped 3 times is `failed`, custody
  `abandoned`. Custody actions added: `requeued`, `abandoned`, `upload_interrupted`.
  `submit()` refuses a case that already has a job (`JobActive`) and starts the pool
  itself - a job must never sit in a queue nothing reads.
- **`storage.update_case`:** a lock per case, a temp file named per pid and thread,
  `os.replace` retried on `PermissionError` (Windows only). `load_manifest` retries only
  that, **not** `JSONDecodeError` (a rename is atomic; code review measured a 3.9 s stall).
- **Traps:** (1) `TestClient` no longer finishes the pipeline before it returns -
  `check_customer_isolation`, `check_mcp` and `bench_llm` now wait (`jobs.wait_idle`).
  (2) **One process only**: the queue and the locks are in memory; never two app
  workers on one `DATA_DIR`. (3) A browser upload that is cut off while still sending
  creates no case at all (Starlette spools the whole body first, gotcha #25); the
  `receiving` window is the spool -> `raw/` copy and a merge's concatenation.
  (4) `tools/prune_cases.py` now removes a case's job and skips `queued`/`processing`.
  (5) The analysis map-reduce job is **not** in this queue (a coroutine on the event
  loop with its own sidecar and a 15-minute stale rule).
- Verified in a container built from the branch: `docker kill` at 5% of a 178 MB /
  1,800,000-row log -> `requeued` (attempts 1, suspect) -> `ready`; `docker stop` ->
  attempts 0, not a suspect; a merge killed during concatenation -> `failed` +
  `upload_interrupted`; 5 simultaneous uploads -> at most 2 `processing`.
  Tests: `tests/check_jobs.py` (45), `tests/check_manifest_atomic.py`.
- **Not done, in this order (the user chose Sprint work first):** the analysis flow -
  a cached narrative is never marked stale after a re-process; the narrative ignores
  analyst rejects (a product decision is open); a map-reduce job survives a restart
  as `running` for 15 minutes; synchronous DuckDB calls on the event loop in
  `analyze_case`; `save_analysis` is not an atomic write; the `_is_local()` provider
  branches (now in `llm.py` and `analysis.py`). ADR-4, ADR-3 and ADR-5 (this paragraph,
  "one process only" above) are done - gotcha #51.
- `JOB_WORKERS` and `MTTC_TARGET_HOURS` are read from the environment but are **not
  in `docker-compose.yml` yet** (the defaults apply).
