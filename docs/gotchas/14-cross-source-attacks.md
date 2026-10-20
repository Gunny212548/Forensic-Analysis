# Gotcha #14

**14. Per-source counters miss attacks that spread across sources.**
`R2000` counts failures per `srcip` and needs 3; a real Azure export had 14
distinct IPv4/IPv6 addresses each failing exactly once against one account,
so nothing fired while the account was plainly being sprayed. Two rules cover
the axis the per-source rules can't see:
- `R2005` (T1110.003): one account, failures from >=5 distinct sources. Also
  fires on the ESXi `auth.log` in the corpus - `root` was hit from 6 addresses.
- `R2006` (T1078): one account, successes from >=4 distinct sources inside the
  same hour. Caught 16 sources in `89.251.0.0/24` succeeding within minutes on
  2026-06-07 - the single most suspicious thing in that case, which neither
  the old rules nor the AI had flagged. Hour buckets are crude (a burst across
  a boundary splits) but need no window function.

Both leave `flagged_count` unchanged on that case - same rows, more rules per
row, which is gotcha #6 working as intended.
