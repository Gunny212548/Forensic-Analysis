# Gotcha #57

**57. Behaviour profiles describe; they never decide (branch `behaviour-profiles`,
2026-10-20).** `app/services/profiles.py` builds `profile_source` in each case DuckDB at
ingest, after the rules: per source address, sign-in failures / successes / unknown accounts,
accounts tried, the most failures and the most refusals in any 1, 10 and 60 minutes, the
first success after a failure and its gap, destinations, refused ports and services, bytes
(and bytes to public addresses, over R2007's own ranges - `rules.IPV4_RE`,
`NON_PUBLIC_IPV4_RE`, checked to stay verbatim in R2007's SQL), hours active. Design and
decisions: `specs/behaviour_profiles.md` (Q27-Q29).

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

Found while checking it in the browser, **not fixed**: the ESXi `auth.log` writes one failed
password twice - `pam_unix(...:auth): authentication failure` and, ~2 s later,
`sshd: error: PAM: Authentication failure for root from ...` - and both decode to
`auth_failed`. Profiles **and R2000** count each attempt twice (10.9.3.91: "6 failed" is
about 3 attempts). A decoder fix (one event per attempt) moves R2000 counts and the baseline.

Measured: 0.06-0.09 s per 65,534-row case (six largest corpus cases); a multi-GB file not
measured. Parity unchanged on all 79 baseline files.
