# Gotcha #24

**24. The workflow threshold matters - the obvious one opens 183 items.**
Only findings that pass a threshold enter the status workflow (IAI-42); the
rest stay visible at case level. Measured 2026-09-28 on 27 deduplicated real
files (no intel feeds loaded), back when findings were to be grouped into
*incidents* by attack-graph chain - a concept dropped on 2026-10-05 (see
*Decisions* below). The counts are therefore **chain groups, not findings**;
re-measure per finding before quoting them for the workflow. The `lvl`
numbers below are the **old 0-15 scale**, replaced by Sigma levels on
2026-10-12 (gotcha #26); re-express the threshold in levels before building
IAI-42. The new levels already do part of this table's job: 20 corpus files
dropped from High to Medium under them, the R3000-only noise included:

| opening rule | chain groups | files with any |
|---|---|---|
| any finding lvl >= 7 (High) **or** >= 2 rule families | 183 | 25 |
| any finding lvl >= 10 (Critical) **or** >= 2 rule families | **6** | 6 |

The first rule is useless because `R3000` (high-risk app allowed) is lvl 8
and fires alone on ordinary hosts: `dst10-8-2-37.csv` alone opened 38,
`log(10).csv` 56. The second leaves exactly the real attacks - the beaconing
host 10.8.3.215, host 10.8.2.37, the ESXi brute force/spray, the Azure spray,
and both `gen_usecase` files. The 21 Palo Alto files that carry only `R3000`
open none; their findings stay visible at case level. Families are the same
R1/R2/R3 split `db._confidence()` uses (gotcha #20).

The same grouping now defines **related findings** (IAI-43/44), shown on a
finding rather than merged into a new object. Chain grouping links sources
**only through pivots** (a target that is also a source). Linking through any
shared target would relate every scanner hitting one public IP - graphs here
are many-sources-to-one-target (see the attack-graph notes). But pivot-only
linking **splits an account-centric attack**: the Azure spray (14 sources, one
account) became 30 groups. `R2005`/`R2006` rows must instead be related by
`username`, which
takes that case to 1 and changes no other case. Pivots also never form
through accounts - a username is never a `srcip` - so auth chains are
single-hop by construction.
