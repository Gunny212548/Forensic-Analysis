# Gotcha #63

**63. A generic rule stops running on the rows of a product whose own rules match the same
behaviour (story 4 of `specs/per_product_rules.md`, branch `rules-per-product`, 2026-10-22).**

D13 said the generic R-rules are converted and retired. They are retired **per product**, not
deleted: R2002, R2003, R2004, R2007, R3003, R3004, R3005 no longer run on Palo Alto or Check
Point rows, R3002 not on Palo Alto rows (`rules.RULE_SUPERSEDED`, filled from each product
module's `SUPERSEDES`). They still run on every other row - FortiGate, ESXi, sshd, Entra,
Windows - which have no rule set of their own yet; deleting them would have left those with
nothing. R3001 (large transfer) stays everywhere: no data-transfer rule replaces it yet (Q70).
The sign-in rules (R2000, R2005, R2006, R2008, R2009) are untouched: no firewall product has a
sign-in rule set.

- **How**: `apply_rules` runs a superseded generic rule on the view `generic_events` (rows of no
  superseding product; rows without a product too), its SQL's `raw_events` replaced by the view's
  name. A store without the product column runs it on everything, as before.
- **Behaviours, not ids**: `rules.RULE_EQUIVALENT` maps each product rule to the generic rule of
  the same behaviour (PAN-MAL-1 -> R2007, PAN-INTEL-2 -> R3004 ...), and `generic_sql()` turns it
  into SQL. The compromised-host escalation counts distinct *behaviours* through it - otherwise a
  Palo Alto case lost its critical escalation (R2007 + R3001 became PAN-MAL-1 + R3001, and the
  pattern listed R-ids only) - and VERIS classifies a product rule as its generic twin.
  Confidence families were already mapped (`RULE_FAMILY`, gotcha #62).
- **The Ingest matrix** lists, per product, its own rules and only the generic ones not
  superseded for it (`products.matrix(..., rules.RULE_SUPERSEDED)`).
- **Baseline re-taken** on the dev container (same intel feeds as 8091), 648 -> 668 entries. Moved,
  all intended: R3004 2,426 -> PAN-INTEL-2 2,426 and R2007 1,167 -> PAN-MAL-1 1,167 on the Palo
  Alto corpus (same rows, renamed); new PAN-SCAN-1 12 + PAN-SCAN-3 6 on `log_9_.csv` (twice -
  two copies), flagged 0 -> 18; the Check Point export R3004 9 -> CP-INTEL-2 9, new CP-SCAN-1 12 +
  CP-SCAN-2 30 (flagged 11 -> 53); gen_usecase R2002 15 -> PAN-SCAN-1 15, R3002 1 -> PAN-MAL-2 1.
  Added: the 20 Elastic PAN-OS sample logs (`D:/logtest/palo-elastic-samples`, 0 rows - no reader
  for headerless PAN-OS syslog yet). `tests/samples`: unchanged.
- Old cases keep their R-ids until re-processed.
