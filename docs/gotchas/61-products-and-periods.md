# Gotcha #61

**61. Every row carries its product; every evidence item says what period it covers (story 1 of
`specs/per_product_rules.md`, branch `rules-per-product`, 2026-10-22).**

- **Product** (`products.py`, D10-D11): each identification profile belongs to one product, and a
  product is a `firewall` or an `os` (D10). Entra ID and Exchange Online are neither, so their
  type is `None` until the user places them; ESXi is filed as an OS. The product is written on
  `raw_events.product` by `pipeline.mark_products` **after** ingest - `ALTER TABLE ... ADD COLUMN`
  then one UPDATE per item's row range - because three readers insert into `raw_events`
  positionally (`INSERT ... SELECT * FROM read_csv`, `checkpoint_le`, the Windows stage) and a
  column in the schema would have broken all three. A store from before has no column:
  `rules._products_present` answers empty and product rules simply do not run there.
- **Product rules** (`rules.RULE_PRODUCT`, D11): a rule that declares a product reads the temp view
  `product_events` (that product's rows) instead of `raw_events`, and is skipped when the case has
  none of them. The product id is checked against `products.PRODUCTS` before it is put in the
  view's SQL. A rule absent from `RULE_PRODUCT` is generic and reads every row - all the R-rules,
  until story 4 retires them; so story 1 moved no finding (host parity: 51 baseline files, 0 moved;
  `check_products.py` re-runs the rules on the same rows without the column and compares).
- **Not applicable** (D12): `products.NOT_APPLICABLE` holds the cells a product's log cannot
  support, with the reason; `products.matrix` gives, per product present, each area's rules, or
  n/a with the reason, or "no rule yet" (a gap in this tool, not the log). On the manifest as
  `detection`, on the Ingest step as *Rules per product and area*.
- **Period** (`period.py`, D15): per item, first / last event, span in days, days with events,
  gaps (runs of days with none - counted, the longest 10 listed), events per day (min / median /
  max) and rows with no time. Days are calendar days of the stored GMT+7 time **after** the
  declared zone and clock offset (`_apply_declared_time` runs first). On the manifest as
  `periods`, on the Ingest step as *Period each file covers*. A gap is a fact, never a
  conclusion - quiet period, uncollected log or filtered export (SP 800-92 §2.3).
- A case processed before story 1 has neither key; the Ingest step says "re-process".

Not yet (story 2): `raw_events` has `bytes_sent` only - the sent / received ratio of M2 and D2
(`detection-behaviours.md`) needs a received column, and Palo Alto's `Bytes Received` is there to
read.
