# Gotcha #23

**23. Restricting a correlation rule's threshold is not the same as
restricting the rows it flags.**
`R2002` (port scan) and `R2003` (service sweep) had no `WHERE` on the outer
query at all, so **every row of a matching source was flagged**, allowed
traffic included. `R2001` and `R2004` next to them always had one; the
principle was there, it just was not applied to these two.

Cost, measured: on `src10-8-3-215.csv` the pair flagged all 25,579 rows -
including 18,972 `allow` rows of an ordinary workstation - which handed
`db.risk_scores()` two `lvl 7` terms with `n=25,579` and pushed that source
above real findings, while `db._confidence()` read the two rule families as
independent evidence and returned `high` for both false positives.

Both the count and the flagged rows are now deny-restricted. What justified
the threshold staying at `>=10` / `>=20`, over 13,666 sources in the corpus:

| per source | median | p90 | reach >=10 | reach >=20 |
|---|---|---|---|---|
| distinct destination ports | 1 | 1 | 15 | 0 |
| distinct services | 1 | 1 | 25 | 6 |

Every one of the 15 sources reaching >=10 ports is ordinary traffic, and
deny-dominated sources top out at 1 port - so the deny filter removes 15 false
positives and no true ones. Of the 6 sources reaching >=20 services only 2 are
deny-dominated, one being the Check Point export, which carries **900**
distinct services among its denied rows and only 8 among its allowed ones.
The threshold was never the problem; counting rows that were allowed was.

Effect on the corpus: `R2002 -94,301` and `R2003 -82,709` findings, no other
rule moved by a single row, 4 files affected. The Check Point true positive
survives, narrowed from 45,209 rows to the 42,223 that were actually refused
(42,071 drops + 135 prevents + 17 rejects); its 2,978 accepted rows are a
policy gap, which is `R2004`'s finding and not a sweep.
