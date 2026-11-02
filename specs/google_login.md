# Sign in with Google

The user, 2026-11-02: "อยากให้การ login เข้าระบบ ด้วย Google mail ที่เรากำหนด" - and, asked, chose:

- **who:** everyone in the Google Workspace domain(s) we name; one who has no account yet gets
  one as an **analyst** the first time (not only accounts an administrator made, not a list in `.env`);
- **password sign-in stays** beside it (offline, Google down, an administrator's way in);
- **reached through a domain name** (Google takes `https://<domain>` or `http://localhost`, never
  a bare private IP).

No Jira story (the user's call).

## Flow

OpenID Connect Core 1.0 authorization code flow (§3.1) with PKCE (RFC 7636, S256), all of it on
the server (`app/services/google_login.py`, routes in `app/routers/auth.py`). The page only
links to `/api/auth/google/start`; nothing is fetched from Google by the browser bundle, so the
"nothing fetched at runtime" rule still holds for the page itself.

1. `GET /api/auth/google/start` - new `state`, `nonce` (32 random bytes each) and `code_verifier`
   (64 characters); kept in `fa_oauth`, a cookie signed with the session secret (purpose-tagged,
   so it is never a session), HttpOnly, SameSite=Lax, path `/api/auth/google`, 10 minutes, Secure
   when `PUBLIC_URL` is https. 303 to Google with `response_type=code`, `scope=openid email
   profile`, `prompt=select_account`, `code_challenge` (S256) and `hd` (the one domain, or `*`).
2. `GET /api/auth/google/callback` - `fa_oauth` read and cleared whatever happens; `state` must
   equal it (RFC 6749 §10.12); the code exchanged at `oauth2.googleapis.com/token` with the
   client secret and the verifier (stdlib `urllib`, certificate checked).
3. The ID token: its signature is **not** checked - OIDC Core §3.1.3.7 step 6 lets TLS server
   validation stand in for it when the token comes straight from the token endpoint, and Google's
   guide says the same. Checked: `iss` (Google's two spellings), `aud` = our client id and no
   other, `azp` if present, `exp` / `iat` (5 minutes' skew), `nonce`, `sub` and `email` present,
   `email_verified`, then the **`hd` claim** in `GOOGLE_ALLOWED_DOMAINS` - never the `hd`
   parameter, which Google calls a UI hint. No `hd` = a personal Google account = refused.
4. The account (`auth.google_account`, under the account lock):
   - none: made - analyst, no usable password (`"!" + random`, never a `scrypt$` hash),
     `google_sub`, `created_by: google-sign-in`; an `account_created` line (method google);
   - disabled: refused;
   - bound to another `sub`: refused (`google_mismatch`) - Google: "Don't use the email field as a
     unique identifier"; a Workspace address can be handed to someone else;
   - not bound yet (an administrator made it): bound now, an `account_changed` line; its role and
     password stay.
5. The ordinary `fa_session` cookie, 303 to `/#/dashboard`. A refusal is 303 to
   `/?signin=<reason>#/login`; the page words the reason itself (no text from Google or the
   request is shown). Every outcome is a line in `audit/login.jsonl` with `method: google`
   (and `reason`); an address with no account is kept as a keyed digest, as for passwords.

## Settings

`GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `GOOGLE_ALLOWED_DOMAINS` (comma separated, case and
a leading `@` ignored) and `PUBLIC_URL` (the address analysts open; the redirect URI is
`PUBLIC_URL/api/auth/google/callback` and must match what is registered at Google exactly - it is
not taken from the request, which behind a TLS proxy reads http). All four or it is off: no
button, `start` answers `signin=off`, and a warning at start-up names what is missing.

`PUBLIC_URL` https also makes the session cookie Secure for password sign-ins.

## What follows from "the whole domain"

- **Removing an account does not keep its owner out** - their next Google sign-in makes it
  again, as an analyst. **Disable** does (and ends their sessions at once). The Users page says so
  above the accounts and in the remove confirmation.
- An administrator who wants someone in at another role lets them sign in once, then changes the
  role; or makes the account first with a password - it keeps that role when they first use Google.
- The server must reach `oauth2.googleapis.com` over HTTPS, and the browser `accounts.google.com`.
  Analysis stays offline; password sign-in still works without either.

## Not done

- No `prompt=consent`, refresh token or Google API access - only who the person is.
- No allow-list of individual addresses inside a domain (the user chose the domain).
- The Add-account form still asks for a password; a Google-only account is made by signing in.

## Tests

`python tests/check_google_login.py [repo]` - a stand-in for Google's token endpoint, the real app
through TestClient: the start redirect (PKCE S256, state / nonce kept, cookie flags), first sign-in
makes an analyst with no password, an existing account keeps role and password and is bound,
another `sub` refused, personal / other-Workspace / spoofed-domain accounts refused and nobody
made, unverified email, disabled, every ID-token check, state / cookie forged / expired / missing,
Cancel, Google unreachable, removal re-creates and disable ends the session, the Users page never
shows `sub`, off when a setting is missing, both audit chains intact.
