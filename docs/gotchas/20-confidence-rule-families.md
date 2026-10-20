# Gotcha #20

**20. Confidence is computed, not asked of the model - and rule *ids* are the
wrong thing to count.**
`db._confidence()` implements section 6 of the requirements: `low` when no
timestamp parsed, `high` when the entity is implicated by >=2 rule
**families** with >=5 supporting events, `medium` otherwise with an explicit
`single-source` / `few-events` flag. A model scoring its own output cannot be
audited; this can be explained in one sentence per finding.

The first version counted distinct rule *ids* and returned `high` for
everything, which is a metric that discriminates nothing. R2002 (port scan)
and R2003 (service sweep) are one observation counted twice, and R2005 cannot
fire unless R1000 already did - so rule ids over-credit. Families
(R1 auth / R2 correlation / R3 network) are closer to independent evidence.
After the change the same corpus gives: beacon case 4 high (was 6 before the
R2002/R2003 deny restriction of gotcha #23 removed two false positives),
Azure case 2 high / 69 medium (`few-events` - each source failed exactly
once), Palo Alto 15 medium (`single-source`). All three re-measured
2026-09-15.

`timezone-unconfirmed` (FR-1.6) is flagged when `ts_raw` carries no zone -
it fires on the Check Point export (`Jun 23, 2026 10:03:02 PM`) and stays
quiet on the Palo Alto and Azure exports, which carry `+07:00` / `Z`. It is
tested against the **source text**, never against the rendered `ts`: since
gotcha #21 every row leaves ingest carrying `+07:00`, so testing the output
would report every source as zone-confirmed. What the flag records is that
the source itself never said and the GMT+7 rule was assumed.
