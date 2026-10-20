# Gotcha #29

**29. Every rule is documented to the Sigma spec and the ADS framework, and
its status is earned, not assigned (2026-10-12).** `rule_meta.py` gives each
rule Sigma v2.1.0 metadata (UUID v4 `id`, `title`, `status`, `author`,
`date`/`modified`, `references`, `logsource`, `falsepositives`, `level`,
`tags` in Sigma's `attack.<tactic>` / `attack.t1234.001` form) and Palantir's
ADS sections (Goal, Categorization, Strategy Abstract, Technical Context,
Blind Spots and Assumptions, False Positives, Validation, Priority,
Response). `GET /api/rules` serves it; a finding's rule id in the Review tab
opens it, because accept/reject is exactly when an analyst needs the false
positives and blind spots.

- **Status is evidence.** `test` = fired correctly on real data with its
  false positives examined (the gotcha is cited in `validation`);
  `experimental` = synthetic hits only, or none. **No rule is `stable`**:
  Sigma means "may be used in production", and one customer's corpus plus
  synthetic files is not that. Result: 16 test, 4 experimental (R1002 and
  R3002 synthetic-only - R3002's real hits were gotcha #22's decoding bug;
  R3003 has only ever matched denied traffic; R3006 not measured).
- **Metadata, not an export.** The detection stays SQL on this tool's
  canonical schema. A Sigma `detection:` block written from it would look
  portable to other SIEMs and not be - that needs field names from a shared
  taxonomy first (OCSF, the schema step still to come).
- **The tags cannot drift from the SQL.** `tests/check_rule_meta.py` (stdlib
  + duckdb) fails if a rule lacks metadata, its documented techniques differ
  from the ATT&CK ids its SQL writes, a status is not Sigma's, or an id
  repeats. R1001/R1003/R1004 are untagged on purpose and say why.
- `date` is 2026-09-15 for every rule - the first commit, the earliest the
  history shows; the rules predate it.
