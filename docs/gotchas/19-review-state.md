# Gotcha #19

**19. Review state lives outside the case DuckDB, and reviews collapsed
findings - both on purpose.**
Requirements FR-2.4/2.7, FR-4.2/4.6, FR-5.6, FR-7.6 and NFR-9 all need the
same thing underneath: an analyst decision attached to a finding, with
history. `review.py` stores one JSON line per decision in
`review/{case_id}.jsonl` and replays the file for current state.

- **Outside the case DB** because `db.drop()` deletes the whole `.duckdb`
  file when a case is re-processed. Verified: after a full re-process of the
  25,579-row case, both decisions were still attached to their findings.
- **Collapsed findings, not rows.** The review unit is
  `finding_key = rid|srcip|username` - the same grouping
  `top_distinct_findings()` already uses. That case has 20,063 finding rows
  over 18,888 distinct events and **4** reviewable findings. Reviewing rows
  one at a time is a requirement that cannot be met; four decisions take two
  minutes. (Was 6 reviewable before R2002/R2003 were restricted to denied
  traffic - see gotcha #23 - and the two that went away were the false
  positives, so the ratio this bullet is making a point about got better,
  not worse.)
- **Append-only** gives FR-2.5 history, FR-7.6 actor/time/reason and NFR
  auditability from one structure instead of three.
- Rejections require a `reason_code` from a fixed set (FR-4.6) - the API
  returns 400 without one, so mapping quality stays measurable.
