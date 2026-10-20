# Gotcha #57

**57. Behaviour profiles describe; they never decide (branch `behaviour-profiles`,
2026-10-20).** `app/services/profiles.py` builds `profile_source` in each case DuckDB at
ingest, after the rules: per source address, sign-in failures / successes / unknown accounts,
accounts tried, the most failures and the most refusals in any 1, 10 and 60 minutes, the
first success after a failure and its gap, destinations, refused ports and services, bytes
(and bytes to public addresses, over R2007's own ranges - `rules.IPV4_RE`,
`NON_PUBLIC_IPV4_RE`, checked to stay verbatim in R2007's SQL), hours active. Design and
decisions: `specs/behaviour_profiles.md` (Q27-Q29).

**Accounts too** (branch `esxi-auth-dedupe`): `profile_account`, per user name lower-cased
("Joe" and "joe" are one account): failures / successes / unknown-account attempts, sources
it failed and signed in from, the most distinct sources failing and signing in within any
hour (a self-join, since a window frame cannot count distinct values), failure bursts in
1 / 10 / 60 min, hosts (n/a where the log names none - ESXi, Entra), hours active. Ranked
among accounts with sign-ins, same `MIN_CROWD`. Routes and MCP tools take a kind:
`/profiles/{source|account}[/{value}]`, `get_profile(kind, value)`, `list_unusual(kind, by)`.
On the real Entra export the one account signed in from 27 addresses, 16 of them inside one
hour (2026-06-07 12:15-12:49, all `89.251.0.x`) - a fact for the analyst, unranked because
the file holds one account.

Why it exists: a rule compares a count with a fixed number, and the user's objection holds -
a number set on one customer's data misfires on a customer with more traffic. A profile ranks
each address against the other addresses **of the same evidence**, so a busy log is compared
with itself. Layer C (D12): no profile fact is a finding, a severity or a gate, and no
threshold of ours is applied.

Rules worth keeping:
- **Counting is SQL, never the model.** The AI reads profiles (small, exact) over MCP
  (`get_profile`, `list_unusual`); it cannot count 65k rows and would not count the same
  way twice.
- **A window is `[t, t + W]`, both ends included** (`RANGE ... INTERVAL W MINUTE FOLLOWING`):
  two events exactly W apart share one. `tests/check_profiles.py` pins both edges.
- **No rank under 20 addresses of the kind** (`MIN_CROWD`): the profile says "not ranked - n
  addresses" instead. The real ESXi `auth.log` has 7 sources, so nothing there is ranked.
- **n/a, not 0**, where an address has no events of that kind; `bytes_public` is NULL only
  when the log has no byte count, 0 when it has bytes but none went to a public address.
- A case processed before profiles existed answers 409 "re-process it"; its events table
  falls back to the plain refused count.

Found while checking it in the browser, **fixed the same day** (branch `esxi-auth-dedupe`):
one failed keyboard-interactive attempt is written twice - by pam_unix
(`support.c`, `_unix_verify_password`: "authentication failure; ... rhost= user=") and,
2-3 s later, by sshd (`auth-pam.c`, `sshpam_query`: "error: PAM: Authentication failure
for root from ..."). Both decoded to `auth_failed`, so profiles **and R2000/R2005** counted
each attempt twice. On the real ESXi `auth.log` all 5 pam_unix lines paired with an sshd
line (same address and account), none alone. Now the sshd line is the attempt and the
pam_unix line is `pam_auth_failure` ("PAM failure report"), cited to Linux-PAM `support.c`
(it was wrongly cited to OpenSSH `auth.c`). Parity: only `auth.log` moved - R2000 35 -> 32,
R2005 39 -> 34, flagged 63 -> 58; R2008 unchanged. On a password (not keyboard-interactive)
attempt sshd writes `Failed password` instead, which was already its own line.

Measured: 0.06-0.09 s per 65,534-row case (six largest corpus cases); a multi-GB file not
measured. Parity unchanged on all 79 baseline files.
