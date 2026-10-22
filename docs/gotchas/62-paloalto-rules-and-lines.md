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

**Story 3 (Check Point, same day).** The scanning, beaconing and feed-match rules moved to
`rules_firewall.build(product, prefix, service, unit)`, shared by every firewall product; Palo Alto
adds its PAN-DB category rule. Check Point's destination service is `coalesce(dstport, app)` - the
Log Exporter port, or the SmartConsole Service name (gotcha #8). Two things the Check Point data
taught:
- **Only allow and refusal count.** TRW and S5 read `verdict = 'allow'` as success and a refusal
  as failure; anything else is neither. Before, every non-refusal was a "success" - Check Point's
  Detect (61 records, all HTTPS inspection certificate notes) and a `failed log in` would have
  counted as successful connections.
- **S5 needs probing (Q71).** One refusal before an allow flagged 9 internal clients whose HTTPS to
  a CDN was dropped once (44 high findings); the value is now the distinct services refused in
  the hour before the allow, minimum 2 - Check Point 0, Palo Alto 1 pair.
TRW on the export: 7 scanners, all external sweeps of the public addresses
(ICMP echo, 3389, 9443) - real horizontal scans, refused. No Check Point sign-in or category rule:
their documentation could not be obtained (SOURCES.md, *Not obtained*). The test is
`tests/check_firewall_rules.py` (was check_paloalto.py).

**Measured on a synthetic Check Point quarter with ground truth (2026-10-22,
`tests/gen_checkpoint_quarter.py`, 166,268 rows, attacks I1-I6).** Before: I1 fully, I2's
discovery and C2, half its exfiltration; no false positive on ~116,000 plain rows; I3-I6
missed. Three changes followed:
- **TRW restarts after a benign decision.** The paper decides a remote host once over 24-hour
  traces; over a quarter the QakBot workstation (I4) was decided benign on its first four
  ordinary contacts and its sweep of 508 hosts weeks later (85% refused) was never looked at.
  `lines.trw` now walks each source in Python, starts again after every benign decision, and a
  scanner decision carries `episode_start` (its first refused new host) - PAN/CP-SCAN-2 flag
  only that episode's refusals. I4's sweep: 0 -> 507 of 508 rows.
- **Internal -> internet contacts are not TRW observations.** With restarts, a user refused at
  four blocked web sites in a row became a "scanner" (17 plain rows). The paper tests accesses
  to the site's own addresses, so contacts from a private source to a public destination are
  left out; the false positive went. Consequence: on the customer's Check Point export the
  benign population is now 1 source (35 pairs), the vertical-scan line drops to its 2-service
  minimum, CP-SCAN-1 12 -> 25 rows - all external sources probing 2-4 services of a public
  address (baseline updated).
- **CP-MAL-2** (`rules_checkpoint.py`): the Threat Prevention blades' own verdict - IPS,
  Anti-Bot, Anti-Virus, Threat Emulation with Prevent / Detect, fields per sk144192, read from
  the Log Exporter record in `raw`. I5's Log4Shell 174 of 177, I2's CVE-2024-24919 scan and
  file read 26 of 26, Anti-Bot on the I2 beacon and I4's QakBot all caught. URL Filtering's
  Detect (certificate notes) is not a threat blade.
After: still missed - I3 (VPN password spray: no Check Point sign-in rule), I6 (SSH brute force
seen only as connection volume), I2's VPN sign-ins / RDP / most SMB spread (allowed internal
fan-out), I4's C2 on 443/995/2222 (too few, too irregular), half of I2's exfiltration (no
data-transfer rule). False positives by design: the Zabbix heartbeat as beaconing (8,876 rows),
OneDrive uploads over R3001's 50 MB (14).
