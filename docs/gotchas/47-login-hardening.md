# Gotcha #47

**47. Sign-in is throttled, audited and bound to the password (2026-10-19,
`specs/login_hardening_design.md`).** `tests/check_auth.py` (45 checks) is
the proof.
- **Throttle is per account, not per address.** Behind Docker the server
  sees the bridge gateway as every client (gotcha #28), so an address limit
  would throttle everyone as one. 5 failures / 15 min per account, plus 60
  across all accounts (`LOGIN_MAX_FAILURES`, `LOGIN_GLOBAL_MAX_FAILURES`,
  `LOGIN_WINDOW_SECONDS`) -> 429 + `Retry-After`, answered before scrypt.
  Unknown accounts count the same, so a 429 does not reveal who has one.
  An attempt is counted when it starts and taken back on success - counting
  after would let parallel requests all pass the check. In memory: resets
  on restart, per process (one uvicorn worker). Costs: an attacker can lock
  a named analyst out for 15 min, and the global ceiling refuses correct
  passwords too while engaged.
- **`AUTH_DIR/audit/login.jsonl`**, hash-chained via `hashchain.py`:
  `login_ok / login_failed / login_throttled / logout`. No password; an
  address matching no account is a 12-hex digest (people paste passwords into
  the account field). A limit engaging is logged once per window. An
  unwritable log is logged and swallowed rather than locking everyone out.
- **The token carries `pv`**, a keyed hash of the stored password hash, so
  `create_user.py add` on an existing account (a reset) ends its old sessions.
  Tokens from before this had none and were refused once: everyone signed in
  again after the deploy.
- Email/password must be strings (254 / 1024 chars max), else the same 401 -
  `{"email": 1}` used to be a 500. Responses carry `X-Frame-Options: DENY`,
  `nosniff`, `Referrer-Policy: same-origin` and `frame-ancestors 'none'`. A
  `script-src` CSP is **not** set: it was not tried against the built bundle.
- `secure=` on the cookie follows the request scheme; behind a TLS proxy it
  needs `uvicorn --proxy-headers`. Not an issue while served directly on 8091.
