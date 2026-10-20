# Login / session hardening - design

Status: **implemented** (approved Q1 as proposed, Q3 yes). Differences from the draft are marked *built:*. Scope: `app/routers/auth.py`,
`app/services/auth.py`, the middleware in `app/main.py`, `frontend/src/pages/Login.jsx`.
Out of scope: roles/RBAC (IAI-14, deferred by the user), MFA, a sign-up page (none on purpose).

## What was read (current behaviour)

- `POST /api/auth/login` - scrypt check (~50ms), same 401 for unknown account and wrong
  password, dummy hash keeps timing equal. Good.
- Cookie `fa_session`: HttpOnly, SameSite=Lax, Secure only when `request.url.scheme == "https"`.
  Signed `{email, exp}`, HMAC-SHA256, constant-time compare. Good.
- Every request re-reads the account, so removing a user ends their sessions. Good.
- Gaps found, below.

## Findings and proposed changes

| # | Finding | Proposal | Perspective |
|---|---------|----------|-------------|
| F1 | **No login rate limit.** ~50ms per guess, unlimited, from anywhere. | In-memory throttle on failed logins, keyed on the normalised account (not IP - see Q1). Over the limit -> `429` + `Retry-After`, **before** the scrypt call so a flood also costs no CPU. | Backend + Frontend |
| F2 | **Logins are not logged.** Review and custody are hash-chained (FR-7.6, ISO 27037); sign-ins, failures and throttling leave no record. | Append `login_ok` / `login_failed` / `login_throttled` / `logout` to a hash-chained `AUTH_DIR/audit/login.jsonl` via `hashchain.py`. Record: time, account, client address as seen, outcome. Never the password. *built:* an address that matches no account is logged as a 12-hex HMAC keyed with the session secret, not as typed (a bare SHA-256 was reversible by dictionary - review 2026-10-20) (people paste a password into the account field); a limit engaging is logged once per window, not once per refused request, so a flood cannot grow the log. | Backend |
| F3 | **A password change does not end sessions.** The token holds only `{email, exp}`. | Put a short fingerprint of the stored password hash in the token; a changed hash invalidates old cookies. Cost: everyone signs in once after deploy. | Backend |
| F4 | **Non-string / huge input is unchecked.** `{"email": 1}` or `{"password": 5}` raises inside `strip()` / `.encode()` -> 500; a multi-MB password goes straight into scrypt. | Validate: both must be `str`, email <= 254, password <= 1024 chars; otherwise the same 401 (no new oracle). | Backend |
| F5 | **No security headers.** The app can be framed (clickjacking on the review/lifecycle buttons). | Middleware adding `X-Content-Type-Options: nosniff`, `Referrer-Policy: same-origin`, `X-Frame-Options: DENY` and CSP `frame-ancestors 'none'`. A fuller CSP (`default-src 'self'`) only after the Vite bundle is checked in a browser - it is local-only, so it should fit, but it is untested. | Backend |
| F6 | **Login page shows every failure as one message.** A 429 would read as "Incorrect account ID or password". | *built:* no frontend change - the 429 body's `detail` already reads "Too many failed sign-ins. Try again in N minutes." and `Login.jsx` already shows `err.message`. | Frontend |
| F7 | `docker-compose.yml:27` still says the secret is "generated once into /data"; it is `/auth` since gotcha #41. | One-line comment fix. | Docs |

Noted, **not** changed: `secure=` follows the request scheme, so behind a TLS-terminating proxy
the cookie would lack `Secure` unless uvicorn runs with `--proxy-headers`. Today the app is
served directly over http on 8091, so there is nothing to fix; it goes in CLAUDE.md as a
deploy note if the user puts a proxy in front.

## Security checkpoint (references/security-checklist.md)

| Check | Result |
|-------|--------|
| Auth | Middleware covers every `/api/*` except 3 public routes - unchanged. |
| Authz | Undefined until IAI-14 - unchanged, stated. |
| Input | F4. |
| Output | `auth.public()` already drops the hash - unchanged. |
| Rate limit | F1. |
| Logging | F2. |
| CSRF | SameSite=Lax + JSON bodies; no change needed. |

## Open questions for the user (they change the design)

- **Q1 - key of the throttle.** Behind Docker the server sees the bridge gateway as the client
  (gotcha #28), so a per-IP limit would throttle everyone together. Proposal: per account,
  **5 failures / 15 min**, plus one global ceiling (e.g. 60 failures / 15 min across all
  accounts) to bound a spray. Trade-off: an attacker can lock a named analyst out for 15 min
  by guessing wrong on purpose. For an internal tool with a handful of accounts I think that is
  the right side of the trade; the alternative is a growing delay (1s, 2s, 4s ... capped) that
  never locks but also slows a legitimate retry less.
- **Q2 - state.** The throttle is in memory: it resets on restart and is per-process. Fine for
  one uvicorn worker (current compose). Persisting it is possible but I would not, until
  there is more than one worker.
- **Q3 - F3 timing.** Include now (one forced re-login), or later?

## Acceptance criteria

1. 5 wrong passwords for one account in 15 min -> 6th attempt is `429` with `Retry-After`, and
   does not run scrypt (measured: < 5ms). The correct password is also refused while locked.
2. After the window passes, the correct password signs in. Another account is unaffected.
3. Unknown accounts are throttled the same way as known ones (no enumeration through 429).
4. Each of login ok / failed / throttled / logout adds one chained line; no line contains a
   password; `verify_chain` passes; an edited line is detected.
5. `{"email": 1}`, `{"password": []}`, a 1 MB password -> 401 (never 500), instantly.
6. After the stored hash changes, an old cookie gets 401 on `/api/auth/me`.
7. Every response carries the F5 headers; the UI still loads and works in a browser.
8. The Login page shows the wait time on 429; autofill behaviour is unchanged
   (inputs stay uncontrolled - CLAUDE.md, login gotcha).
9. Existing checks still pass: `check_mcp` (44), `check_customer_isolation` (31), which both
   sign in.

## Test plan

New `tests/check_auth.py` in the style of `check_customer_isolation.py` (scratch store, throwaway
account, run in the container). Criteria 1-6 are API-level; 7-8 by hand in a browser.
Parity checks are not affected (no ingest/rule change).

## Order of work

F4 -> F1 (+F6) -> F2 -> F5 -> F3 (if Q3 yes) -> F7. Each step is small and testable alone.

## Built

`tests/check_auth.py` (45 checks) passes; `check_customer_isolation` still passes. Limits are env-tunable: `LOGIN_MAX_FAILURES` (5), `LOGIN_GLOBAL_MAX_FAILURES` (60), `LOGIN_WINDOW_SECONDS` (900). The attempt is counted when it starts and taken back on success, so parallel requests cannot all slip past the check. The global ceiling refuses correct passwords too while engaged: it bounds a spray, and costs a 60-failure burst locking everyone out for the rest of the window.
