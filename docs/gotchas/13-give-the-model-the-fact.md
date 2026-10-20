# Gotcha #13

**13. Give the model the discriminating fact; don't instruct it to guess better.**
Asked to analyse an Azure AD sign-in case, the model called 20 successful
logins from one Thai ISP address "potential compromise" - the shape of the
account's own user. It was not reasoning badly: it had counts and nothing
else, so `success x20` and `success x12` looked alike. `db.source_profiles()`
now computes, per source, `auth_ok / auth_fail / allow / deny / days_active /
span / first_seen` over the whole case, and `_build_prompt()` appends it as a
compact "Source profiles" table (~15 tokens per source; input is not the
capped resource).

Same case, before and after:
- before: *"successful logins from 171.100.141.170, indicating potential
  compromise"* - the habitual user, active on 4 separate days.
- after: *"a burst of successful logins from 16 sources occurred on
  2026-06-07, indicating a likely compromise"* - the `89.251.0.0/24` address
  pool, which is the actual finding.

This is the same lesson as the R2001 MITRE retag and the T1078 coverage fix:
**every time the narrative was wrong, the cause was missing or mislabelled
input, never the model's reasoning.** Prompt hardening for these soft spots
was measured (gotcha #5 sweep) and did nothing. Compute the fact in SQL and
hand it over.

*Refined by a later ablation (8 configs, same case).* Once `R2005`/`R2006`
existed, **every** config got the reading right - including one with no
profiles and no risk table at all - because the finding text now says
"Password spray against X from 14 distinct sources" and the model only has to
repeat it. Re-run against rule-silent events (`R1000`/`R1001` only, the
pre-R2005 situation) the difference reappears sharply:

- with profiles: *"a mix of legitimate access from 171.100.141.170 ... a
  coordinated burst of successful logins from the 89.251.0.0/24 subnet"*
- without: *"20 successful logins from 171.100.141.170"* - leads with the
  owner's own activity and never mentions the burst at all.

So both layers earn their keep, in this order: **a rule that names the
pattern is worth more than any prompt context**, and the profiles are the
safety net for everything no rule covers yet. The profiles cost ~1,200 input
tokens, and input is not the capped resource.
