# Gotcha #56

**56. A rule answers "does this fit a known attack pattern?" - nothing else (branch
`rules-layers`, 2026-10-20).** Decided with the user (`specs/rules_review.md`,
`specs/case_flow_design.md` D12/D13 on that branch): what the system knows about an
event comes in three layers.

| Layer | Question | Where it lives |
|---|---|---|
| A | What is this event? | the event's `action` / `verdict`, written by the log source profile; the events table's *event* column |
| B | Does it fit a known attack pattern? | `rules.py` - the only thing that makes a finding |
| C | Is it unusual here? | facts computed at read time by `db.list_raw` (`context`), never a finding, no threshold of ours |

What moved, and why:

- **R1000-R1004 left the rule set (layer A).** "Sign-in failed / succeeded, unknown
  account, connection, password changed" named what an event *is*, and made every
  login a finding to review. Their metadata stays in `rule_meta.py` as Sigma status
  `deprecated`, so cases processed before still explain their findings;
  `rule_meta.problems()` accepts deprecated metadata for a rule no longer in `RULES`
  and refuses a deprecated rule that still runs.
- **R2001, R3000, R3006 became layer C facts**: "source refused N times in this evidence item" (a zip case holds several files),
  the vendor's application risk (shown beside the application, `risk N/5` - a property
  of the app, not something unusual), "source/destination listed by <feed>".
- **R1001 could not just go.** `severity.py`'s credential-compromise raised the
  *R1001 login rows* to high - that was the only "the attacker got in" finding. It is
  now **R2008** (high, T1078), sharing R2000's source condition through
  `rules.BRUTE_FORCE_SOURCES`; credential-compromise raises the attack's own rows
  (`_AUTH_RULES` = R2000, R2005, R2006, R2008, R2009).
- **R2005 was misnamed.** ATT&CK T1110.003 (read 2026-10-20): "a single or small list of
  commonly used passwords against many different accounts". R2005 is one account from
  many sources - renamed "distributed password guessing", tagged T1110.001.
- **R2009 is the real spray**: one source failing (wrong password or non-existent
  account) on >= 3 distinct accounts, case-insensitive. Threshold **measured**: 71
  sources in the customers' own logs (ESXi auth.log, Entra KM23 + the store) each
  failed on exactly 1 account; recorded attacks reached 4 (synthetic) and 31 (Splunk
  capture). Small sample - status `experimental`.
- **R2004 lost T1133** ("external-facing remote services ... such as VPNs, Citrix" - an
  allowed connection is that only when the service is one).

Measured (parity, intel feeds copied from the live store - a fresh store has no feeds
and R3003-R3006 then read 0, which looks like a regression and is not): **0 unexpected
moves**; only the moved rules dropped and only R2008/R2009 appeared. Baseline flagged
rows 176,635 -> 47,959. New hits: ESXi `auth.log` R2008 x24, `azuread_signin.jsonl`
R2009 x31, nightfall R2008 x1 / R2009 x11. Check Point benchmark: R2004 still 2,978.
`azure_ad_distributed_spray.jsonl` now has **0 findings** (it had R1000 x31): no rule
sees a spray spread over many sources - the time-window story is next.

Consequence to know: confidence counts rule *families*, and with R1 gone an
authentication-only entity has one family (R2), so it reads "possibly true" (3) where
R1 + R2 used to give 2 - which double-counted the same failed sign-ins anyway.

Still true after this: correlation rules count over the whole file (no time window) -
`rules_review.md` Q18 decided the windows are measured on our own data, story 2.
