---
name: add-detection-rule
description: How to write or change a detection rule: product rules (rules_<product>.py, rules_firewall.build, lines, RULE_ID_PATTERN), SigmaHQ pins, generic R-rules, RULE_LEVEL / RULE_LABELS / RULE_META, the current rule set, and the MITRE-tag and outer-WHERE mistakes not to repeat. Load before touching rules*.py, rule_meta.py, areas.py, lines.py, severity.py or sigma.py.
---

# Extending the rule engine

Moved out of `CLAUDE.md` on 2026-11-04, word for word; `CLAUDE.md` keeps the one-line rules and the gotcha index. **Before changing code a gotcha names, read `docs/gotchas/NN-*.md`.** If this file and the code disagree, the code is the fact - fix this file (doc-keeper).

Then prove it with the `validate-changes` skill: the product's own check, `tests/check_rule_meta.py`, every `tests/check_*.py`, and parity.

**A new rule is a product rule now** (`specs/per_product_rules.md`). Firewall products share
`rules_firewall.build(product, prefix, service, unit)` - vertical / horizontal scan, allowed after
probing, beaconing, feed matches - and add their own in `rules_<product>.py` (Palo Alto's PAN-DB
category, Check Point's Threat Prevention verdict); `rules.py` appends each module's `RULES`,
`PREPARE` (lines), `LEVEL`, `LABELS`, `FAMILY` (confidence family = the generic twin's),
`EQUIVALENT` (the generic rule of the same behaviour, for escalations and VERIS) and
`SUPERSEDES` (generic rules that stop on its rows). A product rule reads `product_events`; a
line-drawing rule binds `$above` / `$minimum` / `$note` (`lines.evidence_line`, `lines.trw`); ids
follow `RULE_ID_PATTERN`. Every rule needs its behaviour's document read (D14), a `RULE_META`
entry, a place in `areas.py`, and a case in `tests/check_firewall_rules.py`.

**SigmaHQ's rules are not written here** (`specs/sigma_windows.md`, gotcha #79). They are
SigmaHQ's, converted at image build: `rules_sigma.py` hands the high / critical ones to
`apply_rules` as `SIGMA-<uuid>` Windows product rules, `sigma.apply_marks` runs the rest as
marks. A single Windows event that SigmaHQ covers is not a new in-house rule (W-D1) - unless it is
a product's own verdict (WIN-MAL-2), in which case add SigmaHQ's twin to `sigma.TWINS`. **A new
SigmaHQ commit is a new pin**: `SIGMA_COMMIT` and the archive's `--checksum` in the Dockerfile,
then `tests/check_sigma.py` (its `KNOWN_DIFFER` re-measured, never widened silently) and the
baseline's `sigma` sections re-taken and said so.

The generic rules live in `rules.py` as `(rule_id, SQL)` pairs — each is one
`INSERT INTO findings SELECT ...` over `raw_events`. Correlation rules join
against a `GROUP BY ... HAVING` subquery. Conventions: `R1xxx` single-event
host/auth, `R2xxx` correlation, `R3xxx` network/firewall. Insert `lvl` as
`NULL`, declare the rule's Sigma level in `RULE_LEVEL` (gotcha #26), and
always populate `mitre`. Two exceptions: a rule may write a *lower* weight when the
event itself says so (`apply_rules` keeps `least(written, declared)` - WIN-MAL-2 when
Defender remediated, WIN-HOST-3's blocked change; gotcha #76), and a product's own verdict
that names no attacker behaviour carries no technique (CP-MAL-2's Anti-Virus, WIN-MAL-2).

Adding a rule needs no engine changes — append to `RULES` and it runs. Add a
`RULE_LEVEL` entry (a rule without one defaults to `low`) and a
matching short entry to `RULE_LABELS` too: that is what names the rule's
edges in the attack graph (`descr` is a full sentence with IPs in it, far too
long for an edge). A rule with no label falls back to its bare id.

**And a `RULE_META` entry in `rule_meta.py`** (gotcha #29): a fresh UUID v4,
title, Sigma `status`, the ATT&CK techniques its SQL writes, logsource
category, false positives and the ADS sections. `python
tests/check_rule_meta.py` fails until the metadata exists and its
techniques match the SQL - run it with the parity check.

Current set (in-house; SigmaHQ's 1,492 high / critical Windows rules run beside them,
`SIGMA-<uuid>`): **Palo Alto** PAN-SCAN-1..3, PAN-MAL-1..2, PAN-INTEL-1..3 · **Check Point**
CP-SCAN-1..3, CP-MAL-1..2, CP-INTEL-1..3 (gotcha #62) · **Windows** WIN-BRUTE-1..3,
WIN-AUTH-1 (gotcha #65), WIN-LAT-1..3, WIN-HOST-1..2 (gotcha #66), WIN-MAL-1, WIN-INTEL-1..2
(gotcha #67), WIN-BRUTE-4, WIN-LAT-4 (gotcha #68), WIN-MAL-2 Defender detection, WIN-HOST-3 Defender
turned off (gotcha #76) · **generic** (every other product's rows; superseded on Palo Alto /
Check Point rows, and the sign-in ones on Windows rows, gotcha #63): R2000 brute-force burst · R2002
port scan · R2003 service sweep · R2004 policy gap · R2005 spray (many sources, one account) ·
R2006 multi-source logins within an hour · R2007 beaconing · R2008 login after brute force ·
R2009 measured spray · R3001 large transfer (everywhere - no data-transfer rule yet) · R3002
malware category · R3003-R3005 threat-intel matches. R1000-R1004, R2001, R3000 and R3006 left
the set on 2026-10-20 (gotcha #56).

Three things worth copying when writing new correlation rules:
- **Get the MITRE tag right — it propagates.** `R2001` was originally tagged
  `T1110` (Brute Force) when it actually detects repeated *blocked*
  connections. The AI layer dutifully narrated port-scan denies as
  "brute-force attempts". Retagging it `T1595` (Active Scanning) fixed the
  narrative. The AI trusts the rule engine's labels.
- **Guard aggregates against ordinary behaviour.** `R2004` ("allowed despite
  many blocks") would fire on any user who hits a few blocked sites, so it
  requires >=20 denies *and* denies >= 3x allows. Test new correlation rules
  against `tests/gen_usecase.py`, whose benign rows exist precisely to catch
  this.
- **Write the outer `WHERE` too.** A correlation rule is a join against a
  `GROUP BY ... HAVING` subquery, and it is easy to guard the *threshold* and
  forget that without a `WHERE` on the outer query every row belonging to a
  matching entity gets flagged - its benign rows included. That is exactly
  how R2002/R2003 came to flag 18,972 allowed connections as a port scan
  (gotcha #23). Ask of every new rule: *which rows are the evidence?* and
  filter to those, not just to the entity.
