# ADR-004: Transport, merge and analysis jobs leave `analysis.py` and `routers/cases.py`

Status: Accepted (2026-10-19) · Code: `services/llm.py`, `merge.py`, `analysis_jobs.py`

## Decision

A pure move, no behaviour change:

- `llm.py`: provider switch (Groq / Ollama), `_chat`, the Ollama request/response mapping,
  `_preflight`, `_OtpmPacer`, the three exceptions and the retry constants.
  `analysis.py` re-exports the names, so `analysis.AnalysisError` still works.
- `merge.py`: the merge rules and `concat_raw`. A refusal is `MergeRefused(status, message)`;
  the route turns it into `HTTPException`, so no service imports FastAPI.
- `analysis_jobs.py`: job state (`job_running`, `job_view`), `sql_context` and the
  map-reduce worker. The routes keep the HTTP answers.
- `routers/cases.py` 664 -> ~400 lines. `case_views.py` came earlier with Sprint 3, which
  also removed `mcp_server.py` importing from a router.

## Consequences

- Verified unchanged: `check_mcp`, `check_workflow`, `check_customer_isolation` (merge
  paths), `check_jobs`, `check_manifest_atomic`, and `bench_llm` (3 runs, byte-identical,
  0 unsupported stages or ids).
- Still open: `on_event` -> lifespan in `main.py`; the `_is_local()` branches remain in
  `llm.py` and `analysis.py`.
