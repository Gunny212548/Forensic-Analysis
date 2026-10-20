# Gotcha #11

**11. `action` on CSV, and why an auth verdict needs an account attached.**
The line-log decoder was the only thing that ever set `action`, so R1000-R1004
(and R2000, which builds on them) could not fire on *any* CSV — a real Azure AD
sign-in export ingested 91 rows with 14 failures against one account and
produced zero findings. `decode._FIELD_CANDIDATES["auth_status"]` +
`pipeline._ingest_csv_sql`'s `action_expr` now map a sign-in outcome column
onto `auth_success`/`auth_failed`.

Two guards make that safe, and both were put there by a real false positive:
- **Only the auth vocabulary translates** (`success`/`failure`/`failed`, and
  `normalize_auth_status()`). A firewall `Action` column of allow/deny yields
  NULL, so firewall traffic can never become an auth finding. Azure's
  `Interrupted` (the MFA / keep-me-signed-in prompt) maps to nothing — it is
  not a failed authentication.
- **A username is required**, both as a mapped column and non-NULL on the row.
  Without it an Exchange message-trace export (`MessageId, ..., Status`)
  matched `Status` and turned **335 failed email deliveries into 335 failed
  logins**. An authentication event is about an account; if nothing
  authenticated, it isn't one.

`R1000`/`R1001`/`R1002`/`R2000` also lost the word "SSH" from their `descr` and
`RULE_LABELS`. They were written when auth.log was the only source; leaving
"SSH brute-force" on an Azure AD web sign-in would propagate straight into the
AI narrative, which trusts these labels (see the R2001 MITRE lesson).
