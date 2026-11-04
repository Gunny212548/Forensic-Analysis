# Gotcha #82

**82. Sign in with Google: the `hd` claim, `sub` not email, PUBLIC_URL not the request, and removal is not a ban**

`docs/specs/google_login.md`, 2026-11-02 (the user: the whole Workspace domain may sign in, password kept).

The traps:

1. **Check the `hd` claim, not the `hd` parameter.** The parameter only steers Google's account
   chooser and can be edited in the address bar; Google says to "validate that the returned ID token
   has an hd claim". An email ending in `@corp.test` is not proof either - the test signs in
   `eve@corp.test` with `hd: evil.test` and is refused. No `hd` claim at all is a personal Google
   account (`@gmail.com`), never allowed.
2. **The email is not the person.** Google: use `sub`. A Workspace address can be reassigned; the
   account is bound to the first `sub` that signs in to it (`users.json` `google_sub`) and a different
   one is refused (`google_mismatch`) until an administrator removes the account.
3. **Removing an account does not keep its owner out** - with the whole domain allowed, their next
   Google sign-in makes it again as an analyst. Disable is the ban (and ends sessions at once,
   `auth.user_from_token`). The Users page says so.
4. **The redirect URI comes from `PUBLIC_URL`, never the request.** Google matches it exactly
   (scheme, case, trailing slash) and behind a TLS proxy the request reads `http://`. Google does not
   accept a bare private IP as a redirect URI - analysts must open the tool by a domain name, or
   `http://localhost` on this PC.
5. **The ID token's signature is not checked, on purpose.** It comes straight from Google's token
   endpoint over verified TLS with the client secret - OIDC Core §3.1.3.7 step 6. If the token is ever
   taken from anywhere else (the browser, a header) that no longer holds: verify it against Google's
   JWKS first.
6. **A Google-only account has no password,** stored as `"!" + random` - not a `scrypt$` hash, so
   `_check_hash` refuses everything, and unique so the session binding (`_password_version`) differs
   per account. An administrator's Reset password gives it one; then both ways work.
7. **The pending cookie is SameSite=Lax, not Strict:** the callback is a top-level GET *from*
   accounts.google.com, which Strict would strip the cookie from - every sign-in would fail `expired`.
8. **Two instances on one machine** (gotcha in *Login*): the pending cookie is scoped to
   `/api/auth/google` but still shared by port; test a host copy on `127.0.0.1`.

Verified 2026-11-02 with `tests/check_google_login.py` (a stand-in token endpoint) and the pages on a
host copy; **not yet against Google itself** - that needs the user's OAuth client and domain.
