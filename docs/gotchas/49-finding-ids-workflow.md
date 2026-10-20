# Gotcha #49

**49. A finding has an id, can be traced to its source, lists the findings it is
chained to, and has its own page (2026-10-19, Sprint 3: IAI-42..49, 78, 79).**
On branch `sprint/findings-workflow` (stacked on `arch/atomic-manifest`, which is
pushed; the Sprint commits are local, nothing is merged to main). Jira: all Done
(2026-10-19, at the user's word). Reviewed and fixed - see gotcha #51, which also
supersedes the `#/result` links and the caching notes below. Tested end to end by
`tests/check_workflow.py` (~100 checks, run in the container).
- **Ids `FD-YYYY-nnnn`** (`finding_ids.py`): only workflow findings (Sigma high /
  critical, `lifecycle.tracked`) get one, numbered **per customer and per year** -
  two customers can both have an `FD-2026-0001`, so the Findings page always shows the
  customer beside it. The registry is an append-only hash-chained log,
  `customers/<id>/findings/ids.jsonl`, written in `process_case` **before the case
  reads `ready`** (after it, a process that waits for `ready` and exits killed the
  thread mid-DuckDB: SIGABRT in `check_mcp`) and lazily on first read for older
  cases. Re-processing a case reuses the ids because the finding key is the same.
- **Source events:** `GET /api/cases/{id}/findings/events?key=<finding_key>` (a
  query parameter - the key contains `|`) returns the rows behind the finding,
  each with `source_file` (a zip member from its row_id range) and the evidence SHA-256.
- **Related findings** (`related.py`, in `findings_view` as `related`,
  `related_count`, `chain`): chained only through **pivot hosts** over the whole
  case, and by account for R2005 / R2006; a shared final target is not a relation.
  A finding lists at most 12; an auth log alone has none (no destination column).
- **The Findings page** (`#/findings`, `services/findings_index.py`):
  `GET /api/findings?company_id&status&severity&area&unassigned&q&limit&offset`
  returns rows, counts per severity and status, `open_count` (the menu badge,
  IAI-78) and the area list; rows are cached per case on the DuckDB, review-log
  and id-registry mtimes. `#/finding/<case>/<url-encoded key>` opens the finding
  (gotcha #51). Only high and critical findings are here; lower ones are reviewed on
  the case's Reports > Findings tab.
- **Customers** (IAI-79): a case is open while a workflow finding is not Resolved
  (`wf_open` in `overview._case_facts`) - not while one is unreviewed.
- **Two places where Jira and the code differ, on purpose:** Jira says *Closed*,
  the code says *Resolved* (NIST CSF); IAI-42 says "Critical or 2 groups", the code
  admits **high and critical** (gotcha #33, the user's decision) - the Jira text is stale.
- **`services/case_views.py`** now holds what routers/cases.py had (`findings_view`,
  `custody_view`, `created_at`, `veris_line`) plus `source_file`, `log_type` and
  `finding_sources`; `mcp_server.py` imported a FastAPI router to get a findings list.
