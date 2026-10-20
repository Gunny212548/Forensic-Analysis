# Gotcha #41

**41. Login accounts live apart from customer data (2026-10-14).** The
user's requirement, after a reset of `/data` took every account with it:
the database of who can sign in is separate from the customers'.
`users.json` and `session_secret` are in `config.AUTH_DIR`, mounted as its
own volume (`forensic-auth:/auth`), so wiping, backing up or handing over
`forensic-data` never touches accounts or sessions (tested: `/data` wiped
under a signed-in session - the session, a fresh login and the account all
survived), and the two can be permissioned and backed up separately.

- **The default is the sibling of `DATA_DIR`** (`/data` -> `/auth`), not a
  fixed `/auth`, and docker-compose deliberately does **not** set
  `AUTH_DIR`. The test harnesses (`check_mcp`, `check_customer_isolation`,
  `bench_llm`) point `DATA_DIR` at a scratch store and create a throwaway
  account; with a fixed `AUTH_DIR` in the container's environment those
  accounts would land in the production account file. With the sibling
  rule each scratch store gets a scratch `auth/` beside it (verified: after
  both checks ran in the container, `/auth` still held exactly its one
  account). Set `AUTH_DIR` explicitly only outside the container.
- On startup the app warns if `users.json` / `session_secret` are still in
  `DATA_DIR` - they are no longer read there.
- `check_customer_isolation.py` now also fails if an account file appears
  inside `DATA_DIR` (23 checks).
