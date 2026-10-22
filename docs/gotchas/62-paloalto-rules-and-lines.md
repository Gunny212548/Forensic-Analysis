# Gotcha #62

**62. Palo Alto rules draw their lines from the evidence's legitimate members, or by TRW (story 2
of `specs/per_product_rules.md`, branch `rules-per-product`, 2026-10-22).**

- `rules_paloalto.py`: PAN-SCAN-1 vertical scan, PAN-SCAN-2 horizontal scan (TRW), PAN-SCAN-3
  allowed after refusals, PAN-MAL-1 beaconing, PAN-MAL-2 malicious PAN-DB category,
  PAN-INTEL-1..3 feed matches. Authentication and Brute force are n/a (Q61). PAN-DATA-1 waits:
  no legitimacy criterion for transfers yet (Q70).
- **A line over every member is raised by the attackers** (Q70, found while building this): a 99th
  percentile over all (source, host) pairs, one attacker at 50 ports among pairs at 1 - missed at
  20, 31 and 50 members, caught from 99; two attackers missed at 101 and 150. So the population is
  the **legitimate** members only, chosen by a criterion that does not depend on the line - the
  sources TRW decided benign (TRW needs no population) - as Javed & Paxson measured only sign-ins
  that ended in success. `lines.evidence_line`: flagged when `v > 2 x p99 AND v >= minimum`; under
  20 legitimate members `above = -1` and the behaviour's minimum alone decides (Q67).
- **The minimum is the behaviour's definition, not a tuning knob**: 2 distinct refused ports to one
  host in an hour (one port is an event, not a scan); 1 refusal before an allow. On real data the
  benign pairs are never refused (p99 = 0), so the minimum is what decides.
- **TRW** (`lines.trw`): first attempt per new destination host, allow = success, refusal =
  failure (an adaptation, stated); success 0.8 / 0.2, alpha 0.01, beta 0.99 - 4 failures in a row
  decide. Written to `TEMP TABLE trw_paloalto`, reused by PAN-SCAN-1/3 for their population.
  Horizontal only, one source at a time (the paper's own limits).
- **Measured on the customer's 36 Traffic exports** (424,948 rows): TRW 0 scanners / 167 benign /
  1,106 pending, benign first contacts 99.6% successful; refused rows are 24 sources x 9 hosts x
  5 ports - repeats, not scans. PAN-SCAN-1 12 rows (one internal pair, 2 ports), PAN-SCAN-3 32
  rows (3 internal pairs; R2004 had 824 over whole sources), PAN-MAL-1 = R2007's 1,167.
- Rules that draw a line bind `$above` / `$minimum` / `$note` from `rules.RULE_PREPARE`; each
  line's record is on the manifest (`lines`) and the Ingest step (*How each line was drawn*); the
  finding's description carries the line in a few words.
- **Rule ids are no longer only `R\d{4}`**: `rules.RULE_ID_PATTERN` is the shape check, used by the
  finding-events route and the MCP server - both hard-coded `^R\d{4}` and refused every PAN key
  (check_workflow caught it).
- **Families**: confidence counted `substr(rid, 1, 2)`, which would make every PAN rule a new
  family "PA" and lift an entity flagged by R2002 and PAN-SCAN-1 - one behaviour - to two
  families (gotcha #20). `rules.RULE_FAMILY` puts each PAN rule in its generic rule's family
  (`family_sql`) until story 4 re-bases families.
- **While the generic rules still run (until story 4) a Palo Alto case has both**: R2007 and
  PAN-MAL-1 on the same rows, two workflow findings for one beacon. Do not deploy story 2 alone.
- Feed matches do not yet check the indicator's validity at the event's time (T4).
