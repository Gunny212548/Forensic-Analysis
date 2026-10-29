# SigmaHQ rules on Windows events - design (story 6, ADR-006's engine)

Status: **Proposed 2026-10-29** - waiting on the user (Q124-Q133). Branch `sigma-windows`.
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

### S-D8 - stored beside the in-house findings, baselined apart (Q131)

High / critical go into `findings` (so review, AI, FD ids, graph and Overview work unchanged) with
their `SIGMA-` rid; marks go into a table of their own (`sigma_marks`: row_id, rule id, level).
`tests/baseline.json` gains a per-file SigmaHQ section (rules ran / not applicable / matches by
rid) beside the in-house counts, so an in-house drift and a SigmaHQ drift are told apart -
revision 5's "Sigma findings are stored apart" kept in the baseline, not in the table.

### S-D9 - run in the pipeline after the in-house rules (Q132)

A stage between the rules and the escalations, its progress counted; ~45 s on a large case. A rule
that fails at run time is listed with its error on the case, the rest go on.

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
