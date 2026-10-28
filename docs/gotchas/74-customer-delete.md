# Gotcha #74

**74. Deleting a customer (2026-10-28, the user: "ทำให้ลบ Customer ได้"; design
`specs/customer_delete.md`, D1-D4 approved the same day).** An admin or a manager deletes a
customer from its row on the Customers page, with every case it holds, its projects and its
evidence - the whole `customers/<id>/` store (gotcha #40).

- **The record cannot live in the store.** A case's deletion is recorded in its customer's
  `deleted/log.jsonl` (specs/case_delete.md), and the FD-id registry is there too; deleting the
  customer takes both. So the customer's deletion goes to the shared, hash-chained
  `DATA_DIR/deleted/customers.jsonl` - who, when, the customer, its projects, each case's file,
  evidence SHA-256, rows, flagged rows and FD ids - and **carries the customer's earlier case
  deletions inside it** (`case_deletions_before`). Metadata only: no event, no evidence. The
  first real run on a copy of 8091 carried three earlier case deletions of Products Co.
- **Rename first, then remove.** The store is renamed to `customers/.deleting-<id>-<token>` in
  one step; every reader skips a name that is not a customer id (`valid_company_id`), so from
  that instant no list, page, upload or MCP call sees it, and an upload naming the id is refused
  as an unknown customer instead of recreating the store half-way through a removal. If
  `rmtree` then fails, the record says what was left behind (`left_behind`).
- **Busy is a case's rule.** Refused (409) while one of its cases is queued, processing or has
  an AI narrative running (`case_delete.BUSY`, `analysis_jobs.job_running`). The background AI
  review of suggestions does not block it: triage checks its case still exists before each
  write (`should_continue`), as when one case is deleted.
- **The confirmation reads the server, not the table.** `GET /api/companies/{id}/deletion`
  counts cases, projects, suggestions, analyst decisions and FD ids, and names the busy cases;
  the button stays disabled until the customer's name is typed back. The "No customer" row has
  no button - those cases are in no store of their own.
- **Found on the way: `overview._case_facts` assumed a `product` column.** The evidence coverage
  of 440eff5 grouped `raw_events` by `product`; a case built without it (one processed before
  gotcha #61, or `db.init` in a check) raised a BinderException on the Overview and the
  Customers page. It now checks `duckdb_columns()` first, as `db.entity_sql` does - such a case
  is one source of unknown product until re-processed.
- Checks: `tests/check_authz.py` (the matrix, the preview, 409 while busy, the store gone and
  nothing left beside it, every list, 404s, an upload naming it refused, the other customer
  untouched, the record and its chain, a same-named customer later being a new one).
