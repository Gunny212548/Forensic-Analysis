# ADR-002: Case manifest writes are atomic

Status: Accepted (2026-10-19) · Code: `app/services/storage.py` · Tests: `tests/check_manifest_atomic.py`

## Context

`storage.update_case` was load -> modify -> save with no lock, called concurrently for
one case by the pipeline's progress writer (about once a second), the CSV estimator
thread, and status changes. `save_manifest` also wrote one shared `<id>.json.tmp`.
Consequences, reproduced by the test before the fix:

- two writers lose each other's keys (last writer wins the whole file), or put an
  older `status` back over `ready`;
- two writers share one temp file; on Windows `os.replace` raised `PermissionError`
  and the test hung. (The 404 on a freshly uploaded case seen once during a parity run,
  noted in gotcha #46, has the same shape; not proven to be this.)

## Decision

- One `RLock` per case around the whole load-modify-save in `update_case`.
- A temp file named per process and thread, so writers cannot share one.
- `os.replace` retried briefly on `PermissionError` (Windows sharing violation);
  `load_manifest` retried on `PermissionError` / `JSONDecodeError`.

## Consequences

- No lost update, no reverted status, no torn read: 8 threads x 200 writes keep every
  key; 300 rounds of a racing progress writer never undo `ready`; 28k-85k concurrent
  reads saw no missing or torn manifest.
- **In-process only.** The lock does not protect two processes. Same single-process
  assumption as ADR-001.
- On Linux (production) `os.replace` is already atomic against readers, so the retry
  loops never fire there; the lock and the unique temp name are what matter.
