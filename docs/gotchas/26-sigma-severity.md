# Gotcha #26

**26. Severity is a standard's level, not a number someone picked
(2026-10-12).** Every rule used to carry a hand-chosen `lvl` on Wazuh's 0-15
scale, bucketed by cut points nobody could cite (12+ critical, 7+ high...).
Nothing about Wazuh was left in the code but that scale, and it could not
answer "why is this High?". `severity.py` now grades in two layers, each
backed by a published standard:

- **Behaviour -> level: Sigma rules specification v2.1.0, `level` field.**
  Each rule declares one of `informational / low / medium / high / critical`
  in `rules.RULE_LEVEL`, chosen by the spec's own definitions (quoted in
  `severity.py`). No single rule is `critical`: the spec reserves it for
  near-certainty, which one log event almost never is.
- **A refused row is capped at medium** (`apply_rules`). In the ODNI Cyber
  Threat Framework a blocked attempt never crossed the intrusion boundary
  between Engagement and Presence.
- **Attack path -> escalation (ODNI CTF progression, MITRE ATT&CK tactics).**
  `credential-compromise` (R2000 brute force, then a success from that same
  source on that same account) raises the path to **high**.
  `compromised-host` (two *different* allowed post-intrusion behaviours on
  one source: R2007/R3003/R3002/R3001) raises it to **critical**. Rows go in
  the `escalations` table and the UI quotes the reason on the finding.

`findings.lvl` now stores the level's **weight** (1/2/4/8/16, doubling per
level), not a free number - so `ORDER BY lvl`, the graph and
`db.risk_scores()` keep working unchanged, and one `high` outweighs a
`medium` plus a `low`. Labels always come from `severity.level_of(lvl)`.
Measured: `risk_scores()` still puts the three beaconing destinations on top
(gotcha #16).

What the first version got wrong, so don't loosen it back:
- **Credential compromise is high, not critical.** The first version made it
  critical and also accepted mere R2005 (spray) membership. On the ESXi
  `auth.log` that escalated `10.9.59.182`, which failed twice and got in 9
  seconds later - a typo. A log cannot tell an attacker who guessed the
  password from an owner who mistyped it, so it is not Sigma's
  near-certainty, and it now needs R2000 (>=3 failures) from the same source.
- **Pair on the source, not the account.** The Azure account owner logs in
  successfully from their usual address while someone else sprays it; an
  account-level pairing would have called the owner's own logins a
  compromise (gotcha #13).

Effect on the corpus (host run, 63 distinct files, no intel feeds; rows,
flagged and every per-rule count identical to `tests/baseline.json`):
20 cases High -> Medium (all without escalation - mostly the R3000-only
Palo Alto noise of gotcha #24), 2 Medium -> Low, `src10-8-3-215.csv`
High -> Critical (beaconing + 8 uploads of ~96 MB to `135.119.206.211`),
`nightfall-firewall.csv` stays Critical (malware + large transfer from
10.10.1.5), and the ESXi, Azure and `nightfall-auth.log` cases stay High.
The planted brute-force -> root login is `credential-compromise`.

There is no lateral-movement pattern yet: nothing in the corpus shows a
compromised host attacking onward, so it could not be calibrated.
**A re-process is required after any change here** - manifests carry the
summary, and an old DuckDB still holds 0-15 numbers that `level_of()` will
mis-read.
