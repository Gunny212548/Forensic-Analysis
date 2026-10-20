# Gotcha #40

**40. Each customer's evidence is in its own store - and a merge used to
mix two customers (2026-10-14).** The user's requirement: adding a customer
creates that customer's database, and one customer's data is never put
together with another's. `storage.py` now keeps everything of a case under
`customers/<company_id>/` (layout above); `case_dir()` is the one place
that answers "which store holds this case" (a `case_id -> company_id` map,
looked up on disk on a miss and cached - a case never changes customer),
and `db.py`, `review.py` and `custody.py` build their paths on it.

- **A store per customer, not a DuckDB per customer.** One file for all of
  a customer's cases would lock every one of them while one processes (one
  writer per file; MCP readers get a lock error - gotcha #38), and one bad
  file would take every case of that customer with it. The folder gives
  the same separation without either.
- **Adding a customer creates its store**; `save_manifest` puts a case into
  the store its manifest names; a case with no customer cannot be written
  (`UnownedCase`) - FR-2.1 already required one, now it is also where the
  case lives. Ids are regex-checked before they become a path.
- **The merge bug it found:** `POST /merge` accepted cases of different
  customers and filed the result under the first one - two customers'
  evidence concatenated into one file. Now 409.
- **`prune_cases.py` dedupes inside one store only.** The store held the
  same monsoon zip under SUMMIT and under Bigfish; deduping across stores
  would have deleted one customer's evidence because another has a copy.
- **Overview / case list take `?company_id=`** (the UI's customer select;
  a customer row on the Customers page opens its overview). Unscoped, they
  still list every customer - read store by store.
- **Migration:** `tools/migrate_to_customers.py` (dry run; `--apply`) moves
  each case's files with `os.replace` (a rename - bytes untouched), hashes
  the raw file before and after against the acquisition digest, moves the
  manifest last, and appends a `relocated` custody entry, so the chain
  moves intact. Refuses while a case is queued/processing; idempotent.
  **Until it has run the app refuses new customers and cases (503):** the
  old customers are invisible, and "Bigfish" typed on the upload form
  would have become a second Bigfish with a new id (tested both ways).
- Not per customer yet: accounts (any user sees every customer - RBAC is
  IAI-14, deferred by the user), and the MCP access log.

Verified on a branch-built container, scratch store: corpus parity (67),
gen_usecase (4), `tests/samples` (2), `check_mcp` (44) and the new
`tests/check_customer_isolation.py` (22: stores created, the same bytes
uploaded for two customers land in two stores, nothing outside them,
scoped views, cross-customer merge 409, path-shaped ids refused). The
production store, copied, migrated 8 cases / 3 customers: chains intact,
digests unchanged, row counts equal to the manifests.
