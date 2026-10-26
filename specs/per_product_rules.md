# Detection rules per product - design

Status: **Approved 2026-10-22** (the user: "อนุมัติ"). Decided by the user the same day: D10-D16 below
and Q61-Q63, Q65-Q68. Q64 paused.

## Decisions (the user, 2026-10-22)

- **D10 - two log types.** Every evidence file is either **Firewall** (Palo Alto, Check Point,
  FortiGate, Cisco) or **OS** (Linux, Windows). Each product's format differs and is read through
  its own profile (`logsources.py`): firewall formats from the real exports in `D:\logtest`, OS
  formats from the operating system's own documentation and public datasets.
- **D11 - rules per product.** Each product has its own rule set (Palo Alto rules, Check Point
  rules, ...), written on that product's own fields and citing that product's documentation.
- **D12 - the same six detection areas for every product, OS included** (the areas of
  `areas.py`): Authentication · Brute force & spraying · Scanning & policy · Malware & C2 ·
  Data transfer · Threat intelligence. A cell the product's log cannot support is
  **"not applicable", with the reason** - never a silent 0 (Q1 answered yes).
- **D13 - the 14 generic rules are converted, not kept** (Q2 = (a)): R2000-R3005 become
  product rules and leave `rules.py`. Order of work (Q4): Palo Alto, Check Point, then Windows,
  Linux, FortiGate; Cisco after a reader exists.
- **D14 - a rule matches a behaviour, and cites why that behaviour is a finding** (the user,
  2026-10-22): "a rule analyses behaviour from events to find a finding; it must match the
  behaviour, with a reference document for why such events amount to a finding". Every rule
  therefore names (1) the **behaviour** and the document that says it indicates an attack - an
  ATT&CK technique and its detection-strategy analytic (`AN####`), read; (2) **how that behaviour
  shows in this product's log** - the product's field documentation, read; (3) the source of its
  threshold; (4) its tests. A single event is an event (shown on the Timeline), not a finding,
  unless a document says one such event is itself the behaviour.

- **D15 - how long the evidence covers** (the user, 2026-10-22): an export may hold 6 months to
  a year of events, and the system must say how much time each file covers. Today only
  `db.ts_range()` (first / last event of the whole case) exists and no page shows a duration.
  Proposed, per evidence item (each file, each zip member): first and last event time, the span
  in days, the days that hold events and the **gaps** (runs of days with none), and events per
  day - on the Ingest step and in the report's limitations (SP 800-92 §2.3: inconsistent /
  missing log content). It also bounds every rule: a behaviour is counted inside a time window,
  never over the whole file - over a year, three failed sign-ins are not a brute force (the
  R2000 defect of `rules_review.md`).

- **D16 - thresholds come from the case's own evidence, plus TRW** (Q62 answered by the user,
  2026-10-22: "ใช้แบบวัดจาก evidence ของ case ผสม TRW"). No number is set on one customer's data
  and applied to another's. Two methods, both read (`SOURCES.md`):
  1. **Evidence-derived line** (Javed & Paxson 2013 §3.1): measure how the evidence's own
     legitimate population behaves, and draw the line well above that tail. Used for counts and
     volumes - failures per account, refused ports per host, bytes to a destination.
  2. **TRW** (Jung et al. 2004 §4): for behaviours where one source reaches many *new* targets,
     the outcome of each first attempt (succeeded / failed) feeds Wald's sequential test, which
     decides scanner / benign / pending. No time window, so a slow scan is still decided.
  How they combine is an **internal method** (stated as one): TRW's *benign* sources are the
  "legitimate population" whose tail sets the evidence-derived lines. Details in *Thresholds*.

## Thresholds (D16) - per behaviour

| Behaviour | Method | Population / parameters | Window |
|---|---|---|---|
| B1 failures on one account (guessing) | evidence line | failures before an eventual success, counted **per sign-in episode** (the run of failures ending in one success), never summed over the file - a user who mistypes once on 9 days is 9 episodes of 1 (Javed §3.1; D15) | 1 h (Javed's) |
| B5 low-and-slow guessing over days or months | change in the site-wide failure rate (CUSUM, Javed §4.1), then which sources took part | the evidence's own daily failure rate; accounts or sources that never succeed across the whole span | days |
| B2 one source, many accounts (spray) | TRW on accounts | first attempt per new account: success / failure - an adaptation of TRW from hosts to accounts | none |
| B3 one account, many sources | evidence line | distinct failing sources per account per hour among accounts that sign in normally | 1 h |
| B4 failures then success | follows B1-B3 | a success after a B1-B3 finding; excluded: the pair succeeded before, or the user name is one edit from one that succeeded (Javed §4.2) - shown as "likely user error", not dropped | - |
| S1 vertical scan | evidence line | distinct refused ports per source -> host per hour, among TRW-benign sources | 1 h |
| S2 horizontal scan / sweep | **TRW** (hosts, as published) | first attempt per new destination host; a refusal (`deny` / `Drop` / `Reject`) read as a failure - adaptation, stated | none |
| S5 allowed after denied | evidence line on the denials before the allow | as S1 | order + 1 h |
| M1 beaconing | R2007's measured method kept | jitter < 0.6, >= 30 intervals, public egress (`rule_meta.py`) | - |
| M2 sent >> received, D1 volume | evidence line | bytes to public addresses per source -> destination per hour, among internal sources | 1 h |
| D4 fixed-size chunks, D5 same time daily | evidence line | size spread / hour-of-day repeat per source -> destination | days |
| T1-T4 threat intel | a match, no line | feed date and indicator validity carried (SP 800-150 §4.4) | - |

Every finding states which method set its line, the line's value on this case, and the
population it was measured on - so a reader can check it.

- **The line** (Q66): **2 x the 99th percentile** of the legitimate population's value (e.g.
  failures per sign-in episode within 1 h), after Javed & Paxson's ">10 quite rare -> 20". Not
  the maximum: an attacker who guessed right is itself a "failures then success" episode and
  would raise it.
- **Under 20 members** (Q67): no line; every entity showing the behaviour is a finding for the
  analyst, ranked, marked "no line - n members".
- **TRW** (Q68): the paper's parameters - success 0.8 benign / 0.2 scanner, false alarms <= 0.01,
  detection >= 0.99 - needing no population; the case's own measured success ratio of
  TRW-benign sources is shown beside them, and below 0.8 the case states the paper's assumption
  does not hold on this evidence.

## Failed sign-ins: which behaviour is brute force (Q65, read 2026-10-22)

From ATT&CK's detection strategies (SOURCES.md): T1110 DET0463, T1110.001 DET0551, T1110.003
DET0487. Every pattern below is named by an analytic; **none of them gives a count or a window**.

| Behaviour | Analytic | Technique | Area |
|---|---|---|---|
| B1 a series of failures against the same or similar account(s) from one source | AN1521, AN1522, AN1523 | T1110.001 Password Guessing | Brute force & spraying |
| B2 one source failing across many different accounts in a window | AN1336, AN1339 | T1110.003 Password Spraying | Brute force & spraying |
| B3 one account failing from several sources | AN1521 ("from one or more remote IPs") | T1110.001 | Brute force & spraying |
| B4 failures (valid or invalid users) then a success from the same source / user | AN1275, AN1276, AN1522, AN1524 | T1110 -> success | Authentication |
| not brute force: one failure, or the user's own few mistypes | - (no analytic names it) | - | Timeline event only |

Numbers that are published, none of them a detection threshold: NIST SP 800-63B-4 §3.2.2 - a
verifier must disable an authenticator after **at most 100** consecutive failures on one account
("an upper bound ... agencies MAY impose lower limits"); ATT&CK procedure examples - APT28 over
300 attempts per hour per account guessing, about four per hour spraying, Quad7 one per 24 h
precisely to stay under thresholds. So a fixed count alone misses low-and-slow guessing (Q62).

The Check Point export holds one `Failed Log In` - Identity Awareness, `auth_method` Machine
Identity Propagation, no user (corrected 2026-10-22; it was first read as Web UI): an event, not
B1-B4.

The fuller theory - ten behaviours a brute-force detection measures, each sourced (ATT&CK,
CISA TA18-086A, Microsoft's password spray playbook, OWASP OAT-007/008, NIST SP 800-63B-4) - is
`docs/standards/brute-force-detection.md`; the other five areas (scanning, C2, data transfer, threat
intelligence, authentication beyond brute force) are `docs/standards/detection-behaviours.md`.

Palo Alto formats beyond Traffic (Q61): Elastic's PAN-OS pipeline test logs (Elastic License 2.0,
synthetic / anonymised) are in `D:\logtest\palo-elastic-samples` - 19 log types, syslog-framed
CSV **without a header** (positional fields, unlike the customer's Web UI export, which has one);
GlobalProtect and AUTHENTICATION are where a Palo Alto sign-in shows. For format only - no real
attack in them. Field meanings come from the PAN-OS syslog field pages, to be read.

`FG` (Q63): Check Point's `fw log` reference lists `FloodGate-1` among ProductName values and its
examples show `ProductName: FG` with `fg-1_*_rule_name` fields; the export carries the same
`fg-1_server_in_rule_name` on 9,857 records. FG = FloodGate-1 is an inference (the page does not
expand it). It records which FloodGate rule a connection matched - no security verdict, so no
rule reads it as one.

## What the real files hold (measured 2026-10-22, counts only)

**Palo Alto** - `D:\logtest\Palo`, 36 CSV files, one header (PAN-OS export, 118 columns),
424,948 rows.
- `Type` is **TRAFFIC only**: `end` 390,159 (Action `allow`), `drop` 34,789 (Action `deny`,
  Session End Reason `policy-deny`). No THREAT, URL, GlobalProtect, SYSTEM, USERID or AUTH logs.
- `Category` (URL category) is `any` 330,338 / `not-resolved` 94,579; 30 rows carry a real one.
- `Source User` is filled on 1,329 rows; the External Dynamic List columns are empty; App-ID
  (40 applications) and the application's risk are present.

**Check Point** - `D:\logtest\Check point\Search_Report-...869.csv`, Log Exporter records in a
ManageEngine EventLog Analyzer export (gotcha #59), ~20,000 records.
- `product`: `FG` 8,323 · `FG VPN-1 & FireWall-1` 5,778 · `VPN-1 & FireWall-1 FG` 3,032 ·
  `VPN-1 & FireWall-1` 2,151 · Application Control 353 · URL Filtering 265 · Web UI 3 ·
  CloudGuard IaaS 2.
- `action`: Accept 18,874 · Drop 961 · Detect 61 · Key Install 52 · Reject 37 · Block 7 ·
  Failed Log In 1 · Log Out 1.
- Service names (`https`, `domain-udp`, ...) and zones (Internal / External / Local).
  No IPS, Anti-Bot, Anti-Virus or Threat Emulation record.

**Missing since 2026-10-22:** `D:\logtest\windows` (the Windows lab, EVTX-ATTACK-SAMPLES is in
the Recycle Bin) and the Check Point SmartConsole benchmark `Logs_Jun_24_..._Logs_Table.csv`.
`tests/baseline.json` and `check_windows.py --evtx` point at them (Q64).

## The matrix - Palo Alto and Check Point (this design); the rest after them

Rule ids: `<PRODUCT>-<AREA>-<n>`, products `PAN`, `CP`, `WIN`, `LNX`, `FGT`, `CSC`; areas
`AUTH`, `BRUTE`, `SCAN`, `MAL`, `DATA`, `INTEL`.

| Area | Palo Alto (Traffic log) | Check Point (Log Exporter) |
|---|---|---|
| Authentication | **n/a** - a Traffic log records sessions, not sign-ins (Q61) | `CP-AUTH-1` failed sign-in to the gateway's Web UI (`action` Failed Log In). 1 real record |
| Brute force & spraying | **n/a** - same reason (Q61) | `CP-BRUTE-1` repeated Web UI failures from one source. No real test data (Q65) |
| Scanning & policy | `PAN-SCAN-1` vertical scan (one source, many denied destination ports) · `PAN-SCAN-2` horizontal scan (one source, one port, many denied hosts - new, rules_review.md) · `PAN-SCAN-3` allowed **after** being denied (order + window, replaces R2004) | `CP-SCAN-1` many dropped / rejected services (CP has service names, not ports - gotcha #8) · `CP-SCAN-2` horizontal · `CP-SCAN-3` accepted after drops (the SOC benchmark's implied-rule bypass) |
| Malware & C2 | `PAN-MAL-1` beaconing to a public address (R2007's measured method) · `PAN-MAL-2` URL category malware / command-and-control / phishing (PAN-DB names; 0 real rows) | `CP-MAL-1` beaconing · `CP-MAL-2` URL Filtering / Application Control category or `Detect`/`Block` on a malicious category (61 + 7 real records to classify) |
| Data transfer | `PAN-DATA-1` bytes sent to public addresses summed per source -> destination in a window (replaces R3001's any-direction 50 MB) | `CP-DATA-1` the same, if Log Exporter carries byte counts (to confirm in the field list) |
| Threat intelligence | `PAN-INTEL-1..3` feed match on destination allowed / source allowed / blocked (R3003-R3005) | `CP-INTEL-1..3` the same |

Windows (`WIN-*`), Linux (`LNX-*`), FortiGate (`FGT-*`), Cisco (`CSC-*`): their own designs, same
six areas. Windows is mostly SigmaHQ (revision 5) plus the sign-in rules on 4624 / 4625; Linux
the sign-in rules on sshd / PAM.

## What every rule carries (before it may ship)

1. The product fields it reads, each cited to the product's own documentation **read and listed
   in `docs/standards/SOURCES.md`** (gotcha #55).
2. Its threshold method (D16: evidence line / TRW / no line under 20 / match) and, on each case,
   the value it took and the population behind it.
3. Its ATT&CK technique and analytic, from the pages read (`SOURCES.md`: T1110 family, T1046,
   T1595, T1071, T1571, T1573, T1041, T1048, T1030, T1029, T1567, T1078, T1133), and its
   behaviour id from `brute-force-detection.md` / `detection-behaviours.md`.
4. A test on a real file of that product where one exists, and on a synthetic file that holds
   both an attack and the ordinary traffic it must not flag; a test record per SWGDE 18-Q-001 §6.
5. Its area and product in `rule_meta.py` (`logsource` filled - empty today).

## Engine change

`raw_events` has no column saying which product a row came from; a zip's members are told apart
only by row-id ranges on the manifest. Proposed: identification writes the product on every row
(one column, filled at ingest), each rule declares its product, and a rule runs only on rows of
its product - so a mixed zip runs Palo rules on the Palo member only. A product with no rule for
an area is reported "not applicable" on the case, with the reason above.

Retiring the generic rules (D13) re-bases everything that reads an R-id: `areas.py`,
`severity.py` escalations, `confidence.py` families, `related.py`, `rule_meta.py`,
`tests/baseline.json`, `tests/README.md`, `gen_usecase.py`, the measurement document and the
docs. Cases processed before keep their R-ids until re-processed.

## Stories

1. Engine: product on every row, rule declares product and area, "not applicable" on the case.
   **Built 2026-10-22** (gotcha #61), with D15's period per evidence item; no finding moved.
2. Palo Alto rules (table above), with their sources read and tests. Measured on the customer's
   36 Traffic exports first (424,948 rows, counts only, 2026-10-22): TRW decided 167 sources
   benign, 0 scanners, 1,106 pending (1-3 hosts each); benign first contacts succeeded 99.6%
   (the paper assumes 0.8 - holds). Refused rows: 24 sources, 9 hosts, 5 ports - repeats, not
   scans (at most 2 ports to a host in an hour). Allowed after denied within an hour: 3 pairs.
   Internal -> public bytes: 821 pairs, p99 0.73 MB/h. Built in this story: PAN-SCAN-1..3,
   PAN-MAL-1..2, PAN-INTEL-1..3; PAN-DATA-1 waits for Q70's D1 criterion. **Built 2026-10-22**
   (gotcha #62); generic rules unchanged (host parity 51 files, 0 moved).
3. Check Point rules. **Built 2026-10-22** (gotcha #62): CP-SCAN-1..3, CP-MAL-1, CP-INTEL-1..3 -
   the firewall rules every firewall shares (`rules_firewall.py`), a service being the Log
   Exporter port or the SmartConsole Service name. On the customer's export (20,000 records,
   five minutes): TRW 7 scanners (all external, each dropped on one service across 4-5 public
   addresses), 41 benign, 315 pending; CP-SCAN-1 3 external pairs (e.g. 8 consecutive ports).
   **Not written ("no rule yet")**: CP-AUTH / CP-BRUTE - `auth_status` values undocumented in
   anything read, one machine-identity failure in the data; CP-MAL-2 - no Check Point category
   definitions obtainable, no Threat Prevention record in the data (SOURCES.md, *Not obtained*).
   Check Point's 61 Detect records are HTTPS inspection certificate notes (OCSP unreachable,
   expired certificate), not threats - no rule reads Detect as one. CP-DATA-1 waits with
   PAN-DATA-1.
   **Then (2026-10-22, the user's test on a synthetic Check Point quarter):** CP-MAL-2 added -
   the Threat Prevention blades' Prevent / Detect (sk144192 fields); TRW restarts after a benign
   decision and leaves internal -> internet contacts out (gotcha #62). Still missing for that
   test: a Check Point sign-in rule (I3 spray), connection volume to a login service (I6),
   internal fan-out of allowed connections (lateral SMB / RDP), a data-transfer rule.
4. Retire R2000-R3005 and re-base everything that reads an R-id; baseline re-taken and explained.
   **Built 2026-10-22, per product** (gotcha #63): the generic rules a product's rules replace stop
   running on that product's rows and keep running elsewhere - FortiGate, ESXi, sshd, Entra and
   Windows have no rule set yet, and deleting the R-rules would have left them with none. R3001
   and the sign-in rules stay everywhere. Escalations and VERIS count behaviours
   (`RULE_EQUIVALENT`). Baseline 648 -> 668, every move a rename or a new product-rule finding.
5. Windows - its own design, `specs/windows_rules.md` (5a sign-ins **built 2026-10-26**, gotcha #65;
   5b lateral movement / host activity, 5c Sysmon network) · 6. Linux · 7. FortiGate · 8. Cisco
   (reader first).

## Questions

- **Q61 - Palo Alto Authentication and Brute force.** A Traffic log has no sign-in events, so both
  cells are n/a on the files you have. The user has no other Palo Alto log (2026-10-22); Elastic's
  samples show the GlobalProtect / AUTHENTICATION formats but hold no real attack. **Open:**
  write `PAN-AUTH` / `PAN-BRUTE` on those formats now (reader + rules tested on the samples and a
  synthetic file), or keep both cells n/a until a real export arrives. **Answered 2026-10-22:
  n/a** ("a Traffic log records sessions, not sign-ins"); `PAN-AUTH` / `PAN-BRUTE` are written
  when a real GlobalProtect / Authentication export arrives, so every rule is tested on real data.
- **Q62 - thresholds. Answered 2026-10-22 (D16): evidence-derived + TRW.** Was:
  published (A) / ranked within the evidence (B) / analyst-adjustable (C) / several signals (D).
- **Q70 - answered 2026-10-22: the line is measured on the legitimate members only.** Found in
  story 2: a 99th percentile over *every* member lets the attackers raise the line above
  themselves unless they are under 1% of the population (computed with DuckDB `quantile_cont`,
  one attacker at 50 ports among members at 1: missed at 20, 31 and 50 members, caught from 99;
  two attackers missed at 101 and 150, caught at 201) - and no member count can promise that.
  Javed & Paxson avoid it by measuring legitimate users only (sign-ins that end in success).
  So each rule selects its legitimate population by a criterion that does not depend on the
  line: B1 episodes ending in a success; S1 / S5 the sources TRW decided benign (TRW needs no
  population). Q67's 20 counts legitimate members. A line is never below the behaviour's own
  minimum (S1: 2 distinct refused ports to one host in an hour - one port is an event, not a
  scan; S5: a denial then an allow to the same host within an hour). D1 data transfer has no
  legitimacy criterion yet - its rule waits.
- **Q71 - S5 needs probing, not one refusal** (story 3, 2026-10-22, proposed to the user): with a
  minimum of 1 refusal before an allow, the Check Point export gave 44 high findings - 9 internal
  clients whose HTTPS to a CDN was dropped once, then accepted - and the Palo Alto exports 32.
  The behaviour is a gap found by probing (the SOC benchmark: a scan, then accepts), so the value
  is now the **distinct services refused** in the hour before the allow, minimum 2: Check Point
  0, Palo Alto 1 pair (6 rows).
- **Q69 - log sources outside D10's two types** (story 1). VMware ESXi was filed as an **OS**
  (a hypervisor's own operating system; its auth.log is OpenSSH / PAM lines). Microsoft Entra ID
  sign-ins and Exchange Online message trace are neither a firewall nor an OS: their type is left
  unset. Open: which type (or a third one) do they belong to?
- **Q63 - answered:** `FG` = FloodGate-1 (an inference, see above; the user agrees).
- **Q64 - the missing samples.** Paused by the user 2026-10-22 ("one product at a time").
- **Q65 - answered 2026-10-22:** treat it as a failed sign-in and decide from documented
  behaviour which failures are brute force - see *Failed sign-ins* above.

- **Q66 - answered 2026-10-22: 2 x the 99th percentile**, counted per sign-in episode within the
  window, never summed over the file (the user's check: a user who mistypes on 9 days of a year
  is not a finding) - see *Thresholds*.
- **Q67 - too small a population. Answered 2026-10-22 (option ง / d).** Under 20 members
  (`MIN_CROWD`, gotcha #57) no tail can be measured, and **no line is drawn**: every entity
  showing the behaviour (e.g. failures with no success; refused ports) becomes a finding,
  ranked by the behaviour's count, with its facts, and marked "no line - this evidence has n
  <members>; every case goes to the analyst". A line exists only to cut a crowd too large to
  read; under 20 the analyst reads them all ("the system suggests, the analyst confirms").
  Rejected by the user: (a) a published number from another organisation - not this
  evidence's; (b) not running the rule - an attack could be missed; (c) pooling the
  customer's other cases - not chosen.
- **Q68 - answered 2026-10-22: the paper's TRW parameters**, with the case's measured value shown
  beside them - see *Thresholds*.

Q63 answered above (inference, stated as one).
