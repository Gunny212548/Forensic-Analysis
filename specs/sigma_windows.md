# SigmaHQ rules on Windows events - design (story 6, ADR-006's engine)

Status: **Approved 2026-10-29 - Q124-Q133 as recommended** (the user: "ok"), Q133 included: a
Windows export of this PC may be used to measure the noise. Branch `sigma-windows`.
Spike (b) scripts: `specs/spike-sigma/win_run.py` (convert / run / regress) and the DuckDB
dialect of spike (a), `duck_dialect.py`, with one fix found here (booleans, S-D2).

## Why

Revision 5 of `specs/case_flow_design.md` and W-D1 (Q81) split detection: in-house rules for
sequences and counts, SigmaHQ for single events. The Windows rules (stories 5a-5g) are built;
the single events are not. On the Kinnaree quarter five of fifteen incidents had no
suggestion at all - K1 web shell, K6 WMI, K8 DCSync, K9 pass-the-hash, K11 an RDP-to-cloud
exfiltration - so the attack timeline built from confirmed events has holes exactly there.
The user asked (2026-10-29) what SigmaHQ is, why, and whether it is needed; the answer was
"for Windows, measure first". This is the measurement and the design that follows from it.

## What was read (2026-10-29, `docs/standards/SOURCES.md`)

- **Sigma taxonomy appendix v2.1.0** (`sigma-specification/specification/sigma-appendix-taxonomy.md`):
  Windows Folder, Category table - each category's EventID and Channel (`process_creation`
  "EventID: 1 / Channel: Microsoft-Windows-Sysmon/Operational", `ps_script` 4104 on two
  PowerShell channels, `file_access` / `file_rename` "ETW Provider: Microsoft-Windows-Kernel-File");
  Service table - each service's Channel; Fields: "The field names follow the field names used in
  Sysmon events".
- **Detection Rule License 1.1**: using the rules on data, "messages based on matches with the
  Rules must retain ... identification of the authors(s) ("author" field) of the Rule"; sharing
  the rules also needs a link to the rule and to the licence.
- **SigmaHQ `regression_data/README.md`**: each rule of status `test` / `stable` points to an
  `info.yml` with a real `.evtx` sample and its `match_count`; SigmaHQ's CI fails a rule whose
  sample does not give that count.
- ADR-006 (spike (a)), the Sigma rules specification 2.1.0 (`level`, `status`), already read.

## What was measured (spike (b), SigmaHQ commit `05d1031`, 2026-10-21)

**Conversion.** 2,878 Windows rules (`rules` 2,425, `rules-emerging-threats` 324,
`rules-threat-hunting` 129). 2,859 convert to DuckDB SQL; 19 do not (17 use a feature the
SQLite backend does not support, 2 a placeholder); 17 read ETW or a channel the taxonomy does
not name (`file_access` 13, `file_rename` 2, `smbserver-` / `smbclient-connectivity`). Every
converted rule runs on DuckDB. pySigma-pipeline-windows 2.0.1 and -sysmon 2.0.0 require
`pysigma<2.0` - unusable with ADR-006's pin - so the logsource map is the taxonomy's own table.

**Correctness - SigmaHQ's own regression samples.** 445 Windows `.evtx` tests, each read by
the app's own .evtx reader and run against its rule alone: **439 give exactly the expected
count**, 2 more than expected, 3 give 0 (Defender "Exclusions Added", Defender "Configuration
Changes", "Local Network Connection Initiated By Script Interpreter"), 1 not run (a keyword
rule, "Mimikatz Use"). The six are named in the build story and each is either fixed or listed
as a known difference.

**Detection - the quarters with ground truth** (the suggestion unit is rule | source | account
here; S-D5 proposes a better one):

| | Kinnaree (15 incidents) | Mekong (11) |
|---|---|---|
| In-house rules find | 10 | 11 |
| SigmaHQ, any level, finds | **15** - all five the in-house rules miss | 8, none new |
| SigmaHQ high / critical | 13 incidents, **47 suggestions, 0 on a look-alike** | 4 incidents, 10 suggestions, 0 wrong |
| SigmaHQ with medium too | 1,714 suggestions (17 wrong) | 371 suggestions (71 wrong) |

Medium is where the noise is: on Kinnaree "Suspicious Machine Account Replication - DcSync
Indicator" flags the directory sync look-alike's 2,184 rows, Kerberoasting / RC4 rules the old
device's 311, PDQ / msiexec rules the deployment tool.

**Public data the rules were not built on** (`D:/logtest/internet`, gotcha #78): 250 of the
datasets match something, 177 at high / critical, and the titles name the dataset's technique
(Empire PsExec -> "CobaltStrike Service Installations", Rubeus -> "Rubeus Execution", the RDP
Task Manager dump -> "LSASS Memory Dump Creation Via Taskmgr"). OTRF's two DCSync datasets give
no high match - to read before building.

**Real, benign data** - the user's `WinEvents.log` (338 events, 8 computers, the only real
Windows export in hand): 535 rules had events of their logsource; high: Defender threat detected
(2, Meterpreter and Glupteba - real) and Defender real-time protection disabled (1) - the same
three WIN-MAL-2 / WIN-HOST-3 find; 11 more at medium / low / informational.

**Cost.** ~45 s for all rules on a 90-day quarter (one query per rule over `win_events`).

**What the measurement cannot say.** Kinnaree is synthetic and its key has been read; its
generator writes real tools' command lines, which is what SigmaHQ matches - "0 wrong at high"
is likely better than a real network gives. No large real benign Windows export has been run
(Q133).

## Proposed decisions

### S-D1 - Windows first (Q124)

Run SigmaHQ on `win_events` only. Entra (ADR-006: 2 of 19 rules match, one every row), Linux
(keyword rules on the raw line) and firewalls (no SigmaHQ rule for traffic) are later stories.

### S-D2 - the engine is ADR-006's option C, the logsource map the taxonomy's (Q125)

pySigma 2.0.1 + pySigma-backend-sqlite 2.1.1 (LGPL, unmodified libraries, pinned exactly), the
DuckDB dialect of spike (a) moved into the app, plus the fix this spike found: a boolean is
compared as `'true'` or `'1'` (the backend's bare `1` makes DuckDB cast every value of a VARCHAR
item and fail on `'false'`). Logsource -> `channel` / `event_id` from the taxonomy tables
(category and service); fields are `win_events.data`'s own item names, as the taxonomy says;
`EventID`, `Channel`, `Provider_Name`, `Computer` are the table's columns. A rule whose logsource
is ETW or not in the taxonomy is "not readable"; one whose logsource has no event in the case is
"not applicable" (ADR-006 decision 3) - both counted on the case, never shown as 0 matches.

### S-D3 - rules are bundled, pinned and attributed (Q126)

A pinned SigmaHQ commit is converted when the image is built (a build stage, like the UI's: the
build needs the network, an analysis never does - gotcha #17) into one JSON of rules: id, title,
author, level, status, tags, references, false positives, logsource, SQL, the rule's path and
URL at that commit. The case records the commit, the pySigma versions and the file's SHA-256
(ADR-006 decision 4). Every match shown names the rule's author and links the rule and DRL 1.1.
Folders: `rules` and `rules-emerging-threats`; `rules-threat-hunting` (written for hunting, not
alerting) only as marks (S-D4).

### S-D4 - high / critical are suggestions; the rest are marks on the timeline (Q127)

The Sigma rules specification 2.1.0 draws the same line (`docs/STANDARDS.md`, already read): "While
`low` and `medium` level events have an informative character, events with `high` and `critical`
level should lead to immediate reviews by security analysts".

- **High and critical**: a finding like any other - in Attack events, decided by the analyst,
  explained by the AI (gotchas #64 / #71 / #72), in the attack timeline and graph once confirmed.
- **Medium, low, informational** (and every threat-hunting rule): a **mark on the event** in the
  Timeline and the events table (revision 2's "rule and SigmaHQ matches shown as marks on events,
  not as a separate list"), filterable, never a suggestion, never counted as one. The analyst can
  pivot from a mark; nothing waits for a decision on it.
- Measured: Kinnaree +47 suggestions over the in-house 526, Mekong +10; the AI review adds ~9 s
  each.

### S-D5 - one suggestion per rule, host and account (Q128)

The finding key is `rid|source|account` (gotcha #19, #69). A host event usually has no source
address, so by the row's own columns every host of one rule would fold into one suggestion. A
SigmaHQ finding names its entity (`entity_src` = the computer the event was logged on,
`entity_user` = the account in the event - Sysmon `User`, else `SubjectUserName`), so one
suggestion is one rule on one host for one account.

### S-D6 - ids, levels, areas, metadata from the rule (Q129)

- `rid` = `SIGMA-` + the first 8 hex of the rule's UUID (`RULE_ID_PATTERN` widened), the full UUID
  kept in the metadata.
- Level = the rule's own `level` (gotcha #26's weights); the refused-row cap does not apply (no
  verdict on a host event).
- ATT&CK techniques and tactics from the rule's `attack.*` tags; area by its first tactic:
  credential-access / execution / persistence / privilege-escalation / defense-evasion / discovery
  / collection -> Host activity, lateral-movement -> Lateral movement, command-and-control ->
  Malware & C2, initial-access / impact / exfiltration -> Host activity. The Overview's cards keep
  their number (eight).
- Rule metadata (`/api/rules/<rid>`) from the YAML: title, description, author, status, level,
  false positives, references, the link and DRL - not an ADS of ours (gotcha #29 is for our rules).

### S-D7 - where an in-house rule already decides, SigmaHQ's twin is a mark (Q130)

A Defender detection is WIN-MAL-2's (one per host and detection, outcome attached, gotcha #76);
SigmaHQ's "Windows Defender Threat Detected" fires on the same events. Listed twins, each with the
in-house rule named on the mark, are marks only: Defender threat detected / real-time protection
disabled (WIN-MAL-2 / WIN-HOST-3). Others are added only when measured on the same rows.

As built (2026-10-29): a twin selects only event ids of the provider its in-house rule reads and
decides nothing more about them - six: Threat Detected and AMSI Trigger (WIN-MAL-2's 1006 / 1015 /
1116 / 1117), Real-time Protection / Malware and PUA Scanning / Virus Scanning disabled and Tamper
Protection Trigger (WIN-HOST-3's 5001 / 5010 / 5012 / 5013). Virus Scanning Disabled was found on
story 5f's capture (`check_windows_rules.py` failed with it as a second suggestion of SRV2's 5012).
Not twins: Configuration Changes and Exploit Guard Tamper (5007 values WIN-HOST-3 does not read),
RedSun (one named threat - it says more than WIN-MAL-2).

### S-D8 - stored beside the in-house findings, baselined apart (Q131)

High / critical go into `findings` (so review, AI, FD ids, graph and Overview work unchanged) with
their `SIGMA-` rid; marks go into a table of their own (`sigma_marks`: row_id, rule id, level).
`tests/baseline.json` gains a per-file SigmaHQ section (rules ran / not applicable / matches by
rid) beside the in-house counts, so an in-house drift and a SigmaHQ drift are told apart -
revision 5's "Sigma findings are stored apart" kept in the baseline, not in the table.

### S-D9 - run in the pipeline after the in-house rules (Q132)

A stage between the rules and the escalations, its progress counted; ~45 s on a large case. A rule
that fails at run time is listed with its error on the case, the rest go on.

## Built (2026-10-29, stories 6a + 6b)

- **Build stage** (`Dockerfile` `sigma`, `requirements-sigma.txt`, `tools/sigma_build.py`): SigmaHQ
  `05d1031f` as its GitHub archive, checked by SHA-256 (fetching by git hash through BuildKit failed
  mid-transfer after 9 minutes); the dialect's differential self-test runs first and fails the build
  on any difference but the two where SQLite is wrong; the JSON (6.8 MB) lands at `/opt/sigma` -
  outside `app/`, which the dev compose mounts over. The archive build and the git checkout give the
  same file byte for byte (`2e640a30...`). The app never imports pySigma.
- **Runtime**: `sigma.py` (bundle, logsource CTE, marks, the case record), `rules_sigma.py` (1,492
  suggesting rules as Windows product rules), `rules.apply_rules(failures=)`: a SigmaHQ rule that
  fails is listed on the case and the rest run; one of ours still fails the case.
- **The case**: `manifest.sigma` (commit, versions, file hash, ran / not applicable / not readable /
  not convertible, matches, failures) shown as "SigmaHQ rules" on the Ingest step; marks on each event
  in the events table and timeline (`db._events`, a link to the rule, its author in the tooltip); the
  rule card shows a SigmaHQ rule as SigmaHQ wrote it, with its author, link and DRL 1.1 (fetched one
  rule at a time now - the list would be 1,500 rules); `flagged_by_origin` beside `flagged_count`.
- `tests/check_sigma.py`; `check_parity.py` keeps SigmaHQ's counts in a `sigma` section of each
  entry (S-D8), `flagged` and `rules` staying ours.

**Where the build differs from the design, and why:**
- **Q129's id**: `SIGMA-` + the **whole UUID**, not 8 hex - SigmaHQ authors copy ids, so different
  rules share 8 hex (4 pairs) and even 12 (`7e9cf7b6-e827-11ed-...`).
- **S-D7's twins**: six, not two (above).
- **One column name was a trap**: a rule field called `Data` is win_events' `data` column to DuckDB
  (identifiers are case-insensitive) - the rule's fields are selected into a CTE and its condition
  runs there alone, host and account under names no Sigma field has.

**Measured with the build:**
- SigmaHQ's own regression samples through the app's pipeline: **439 of 445 exact**, the same six as
  the spike, each named in `check_sigma.py` (a keyword rule; two Defender 5007 rules and one network
  rule give 0; two give 2 of 1).
- **Kinnaree** (the pipeline, the S-D5 key): SigmaHQ 80 suggestions on 648 events - 78 hold attack
  events, 2 the admin's benign true positive on HQ-PC040, **0 events on a look-alike**; incidents K1-K12
  and K15 (13), with ours all 15. In-house unchanged (523 suggestions). 44 s for the case.
- **Mekong**: `check_windows_rules.py` - no plain or look-alike event flagged, every incident as before.
- **This PC's own logs (Q133)**: System, Application, PowerShell (both), Defender and Task Scheduler,
  143,776 events: **0 SigmaHQ suggestions**; 9 rules mark events (Application Uninstalled 124,
  Defender history deletion 80, the Defender twin 45, web-request cmdlets in script blocks 23 - this
  session's own PowerShell - and five more). The Security log needs administrator rights and there is
  no Sysmon here: of 2,878 rules 350 had events, so this says nothing about the Sysmon / Security rules'
  noise. That measurement still needs a real export with both.
- **This PC's Security log (2026-11-02)**, exported as administrator: 31,578 events over five days
  (2026-10-28 - 11-02), one standalone workstation, its owner the only user. Every runnable SigmaHQ
  Security rule ran - 166 of 169 (93 high / critical): **0 SigmaHQ suggestions**, two informational
  rules mark 71 events (User Logoff 59, VSSAudit source registration 12). 9.7 s for the case. What it
  cannot say: no domain, no remote sign-in (4624 types 5 / 2 only), and process creation is not audited
  by default (25 4688s, all at boot), so the Security rules saw a quiet machine. The Sysmon rules -
  2,253 of the 2,878 - are still unmeasured on real data.
  In-house, the same file gave two suggestions: WIN-BRUTE-1 (12 of 18 failed sign-ins, the owner's
  account, logon type 2, wrong password `0xC000006A`; the failing process Chrome's password-manager
  re-authentication or the lock screen's svchost) and WIN-AUTH-1 after it, which itself says "this
  account had signed in from this source before the failures began (likely the owner)". With 8
  legitimate episodes the rule draws no line (under 20 members, Q67), so every episode of two or more
  failures goes to the analyst - as designed.

## Not in this story

Entra / Linux / firewall SigmaHQ rules; correlation rules (SigmaHQ has none); the Sysmon `Hashes`
item split into `md5` / `sha1` / `imphash` (rules on those fields read NULL - counted, listed);
Security 4688 under `process_creation` (the taxonomy maps the category to Sysmon 1 only; a host
with 4688 and no Sysmon runs none of those rules - stated on the case); SigmaHQ updates (a new
commit is a new pin, its baseline re-taken).

## Stories

- **6a engine and bundle**: dialect + taxonomy map in the app, the build stage, the rules JSON
  with provenance, `check_sigma.py` (the 445 regression samples - 439 exact as the floor, the six
  listed; the dialect's differential test of spike (a)).
- **6b in the case**: the pipeline stage, findings (high / critical) and marks, entity, areas,
  metadata route, Attack events showing author / DRL, marks on the Timeline and events table.
- **6c measured**: Kinnaree / Mekong / public data / the real file re-scored; parity with the SigmaHQ
  section; docs (STANDARDS.md row, SOURCES.md, gotcha).

## Questions

- **Q124 - scope (S-D1).** Windows only in this story? Recommended: yes.
- **Q125 - engine (S-D2).** ADR-006 option C, the logsource map from the taxonomy, booleans as text?
  Recommended: yes; ADR-006 becomes Accepted for Windows.
- **Q126 - bundle (S-D3).** Convert a pinned SigmaHQ commit at image build; `rules` +
  `rules-emerging-threats` as rules, `rules-threat-hunting` as marks only? Recommended: yes.
- **Q127 - suggestions vs marks (S-D4).** High / critical as suggestions, the rest as marks on
  events? Recommended: yes - medium made 1,714 suggestions on Kinnaree.
- **Q128 - the unit (S-D5).** One suggestion per rule, host and account? Recommended: yes.
- **Q129 - ids and areas (S-D6).** `SIGMA-<8 hex>`, the rule's level, area by its first tactic?
  Recommended: yes.
- **Q130 - twins (S-D7).** SigmaHQ's Defender rules as marks beside WIN-MAL-2 / WIN-HOST-3?
  Recommended: yes.
- **Q131 - storage (S-D8).** High / critical in `findings`, marks in `sigma_marks`, the baseline's
  SigmaHQ section apart? Recommended: yes.
- **Q132 - when (S-D9).** In the pipeline after the in-house rules (~45 s on a big case)?
  Recommended: yes.
- **Q133 - real benign data.** No large real Windows export has been run: may a Security / System
  / PowerShell export of this PC (or one you choose) be used to measure the noise before 6b ships?
  It is your data; it stays outside the repo. Recommended: yes, before 6b is deployed.

## Story 6d - process creation from Security 4688 (design, 2026-11-02, awaiting approval)

**Why.** The taxonomy maps `process_creation` to Sysmon 1 only (S-D2), so 1,425 runnable SigmaHQ rules -
half the bundle - judge nothing on a host that audits process creation (4688) but has no Sysmon, which
is the usual customer export. The user chose this as the next Windows work while the Sysmon noise round
waits (2026-11-02).

**What was read.**
- Sigma taxonomy appendix 2.1.0: `process_creation` is EventID 1 of Sysmon; 4688 appears nowhere; "The
  field names follow the field names used in Sysmon events".
- SigmaHQ's own `tests/thor.yml` (commit 05d1031, the pinned one): `process_creation` also as
  `EventID: 4688`, service `security`, with `fieldmappings: Image: NewProcessName, ParentImage:
  ParentProcessName` - the mapping SigmaHQ ships for THOR / SPARK.
- Microsoft, event 4688 (archived Windows 10 page): the items `NewProcessName` (full path of the new
  process), `ParentProcessName` (version 2, Windows 10, "Creator Process Name"), `CommandLine` ("By
  default Process Command Line field is empty" - a group policy adds it); process ids hexadecimal;
  `MandatoryLabel` a SID, not Sysmon's `IntegrityLevel` word.
- DuckDB 2.0, NULL Values / Boolean Type / Logical Operators: any comparison with NULL is NULL; `NULL
  AND false` is false, `NULL OR true` is true, `NOT NULL` is NULL; WHERE keeps only rows that are
  true; `coalesce` is the exception. Not on those pages, measured on 2.0.0: `ILIKE ... ESCAPE`, `=
  ... COLLATE NOCASE`, `regexp_matches`, `IN (...)` and `lower` of NULL are NULL.

**Measured with a prototype** (scratch script over the app's pipeline, the bundle unchanged): the
1,425 rules run over each case's 4688 rows under the map below, every matched row classed by the
dataset's ground truth.

| | 4688 rows | rules run | high / critical rows: attack / look-alike / plain | other levels (marks) |
|---|---|---|---|---|
| Kinnaree (key read) | 7,641 | 1,220 | 45 / **0** / **0** - K1, K4, K5, K10, K12, K15 | 24 attack, 236 look-alike (PDQ 123, WinRM 73) |
| Mekong | 11,150 | 1,220 | 6 / **0** / **0** - W4, W7, W10 | 13 attack, 73 look-alike |
| Brute force -> pivot | 2,595 | 1,220 | 2 / 0 / **0** - C2, C4 | 12 attack, 19 plain |
| `windows-security.log` (attack_data) | 4 | 1,220 | the lsass dump via comsvcs, 4 rules | - |
| This PC's Security | 25 (no command line) | 1,220 | nothing | nothing |

In the three generated sets every 4688 has a Sysmon 1 twin (same host, process id, image, time): of
Kinnaree's 7,641 pairs the account agrees in 6,696; the other 945 are all SYSTEM processes - 4688 names
the computer account (`APP01$`), Sysmon `NT AUTHORITY\SYSTEM` - so running both would put one process
under two suggestions.

### Proposed decisions

**S-D10 - the map is SigmaHQ's own (Q134).** On a Security 4688: `Image` <- `NewProcessName`,
`ParentImage` <- `ParentProcessName` (thor.yml), `CommandLine` <- `CommandLine` (same item name). An
empty item is unknown (NULL), never an empty string: "not audited" must not read as "no argument".
Every other Sysmon field (`OriginalFileName`, `Hashes`, `ParentCommandLine`, `User`, `IntegrityLevel`,
...) is unknown on a 4688. No value is translated (no `MandatoryLabel` SID -> `IntegrityLevel` word,
no hex -> decimal id): no document maps them.

**S-D11 - a rule runs on a 4688 only where its answer cannot depend on what 4688 lacks (Q135).**
- A rule whose condition is plain three-valued logic (no `coalesce`, `IS NULL`, `IS DISTINCT`): on
  every 4688. With the unknown fields NULL, the condition is true only when it would be true whatever
  their values (the truth tables above), so an unknown field can lose a match - a renamed binary its
  `OriginalFileName` would have caught - but never make one. **1,094 rules**: 493 whose every field
  4688 holds and 601 that also name a field it lacks.
- A rule that uses `coalesce` / `IS NULL` - the dialect's `NOT COALESCE(filter, FALSE)`, where an unknown
  filter field lets the event through: only on a 4688 that holds every field the rule uses (126 rules -
  most need a command line, so they judge nothing where the policy is off).
- The rest - such a rule on a field 4688 never has - do not run on 4688: **205 rules**, each listed with
  the field.
- Total: **1,220 of 1,425 rules on 4688, 680 of them high / critical**; today 0.

**S-D12 - Sysmon first, 4688 where Sysmon is not (Q136).** A 4688 is read only when its host has no
Sysmon 1 in the case at that time (outside the span from the host's first to its last Sysmon event).
One process is then one event and one suggestion, the SYSTEM split above cannot happen, and a host whose
Sysmon was installed part-way keeps its 4688 from before. Not chosen: both (duplicate rows; 945 of
Kinnaree's would open a second suggestion), or 4688 only when the case has no Sysmon at all (a mixed
estate loses its unmonitored hosts).

**S-D13 - said on the case (Q137).** The case's SigmaHQ record adds the 4688 count read, how many had
no command line ("process command line not audited - rules on CommandLine judged N events as unknown"),
and the 205 rules not run on 4688 with the field each needs. The Ingest step's SigmaHQ line shows the
first two. Findings and marks are unchanged in form: their event is the 4688.

**Not in 6d.** A field 4688 does not carry; 4688's `User` (the Sysmon field) - `ACCOUNT` keeps reading
the subject as today; a SigmaHQ commit change (the bundle and its pin stay; the map is applied at run
time in `sigma.py`).

### Build and checks (6d)
- `sigma.py`: `logs_cte` unions the 4688 rows for a `process_creation` rule per S-D10..12; the record of
  S-D13 in `apply_marks`.
- `tests/check_windows.py`: the attack_data 4688 sample raises "Process Memory Dump Via Comsvcs.DLL"
  from its 4688; a `coalesce` rule skips a 4688 without a command line; a host with Sysmon gives no 4688
  match; a host without keeps it.
- `tests/check_windows_rules.py` on Mekong with its Sysmon files removed: no plain or look-alike event
  raises a SigmaHQ suggestion. `check_sigma.py` unchanged (its samples are Sysmon). Parity: the Windows
  entries with 4688 and no Sysmon change their `sigma` section - re-taken and listed.

### Questions (6d)
- **Q134 - the map (S-D10).** SigmaHQ's thor.yml map plus `CommandLine`, an empty item unknown, nothing
  translated? Recommended: yes.
- **Q135 - which rules (S-D11).** 1,220 rules by the three-valued rule above, 205 listed as not run?
  The stricter choice - only rules whose every field 4688 holds - is 619 rules (383 high / critical).
  Recommended: 1,220.
- **Q136 - Sysmon first (S-D12).** 4688 only where the host's Sysmon does not cover that time?
  Recommended: yes.
- **Q137 - on the case (S-D13).** The 4688 counts and the 205 rules on the SigmaHQ record, two
  figures on the Ingest step? Recommended: yes.
