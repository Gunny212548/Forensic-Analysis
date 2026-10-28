# Windows story 5f - Microsoft Defender Antivirus: its own verdicts and being turned off

Status: **Approved 2026-10-28 - Q114-Q119 as recommended.** Branch `rules-windows-defender`.

## Why

The user's `WinEvents.log` (D:/logtest/window test, NXLog JSON, 338 rows, 8 hosts of
corp.local / prod.corp.local, 2021-08-03 .. 2021-10-02) was processed with 0 suggestions. The
file holds one event per event ID, so no count or sequence rule can fire, and that 0 is right by
the rules. But four of its rows are things an analyst must see, and no rule reads them:

| row | host | time (+05:45 as written) | what |
|---|---|---|---|
| Defender 1116 | IT02 | 2021-09-02 13:13 | `Trojan:PowerShell/Meterpreter.gen!A`, Severe, Source AMSI, powershell.exe, Detection User CORP\Leo |
| Defender 1117 | IT02 | 2021-09-02 13:15 | the same Detection ID - Action Quarantine |
| Defender 1011 | IT02 | 2021-09-28 12:39 | `Trojan:Win32/Glupteba!ml`, Severe, `C:\Windows\b6a1458f396.exe` deleted from quarantine |
| Defender 5001 | ACC01 | 2021-09-21 13:11 | real-time protection disabled; 5000 (enabled) at 13:13 |

W-D1 (Q81) left single events to the SigmaHQ story. That story is not built, and a Defender
detection is not "a single suspicious event" that we judge: it is the endpoint product's own
verdict, as CP-MAL-2 reads Check Point's Threat Prevention verdict.

## What was read (docs/standards/SOURCES.md, 2026-10-28)

- **Microsoft, "Review event logs and error codes to troubleshoot issues with Microsoft Defender
  Antivirus"** (ms.date 2026-05-11). Each event's symbolic name, message and fields:
  1006 MALWARE_DETECTED, 1015 BEHAVIOR_DETECTED, 1116 STATE_MALWARE_DETECTED ("detected malware or
  other potentially unwanted software"), 1117 STATE_MALWARE_ACTION_TAKEN, 1118 ..._ACTION_FAILED,
  1119 ..._ACTION_CRITICALLY_FAILED ("The endpoint might not be protected"), 1007 / 1008 action
  taken / failed, 1011 QUARANTINE_DELETE ("deleted an item from quarantine"; fields Name, ID,
  Severity, Category, Path, User), 5000 / 5001 RTP_ENABLED / RTP_DISABLED, 5010
  ANTISPYWARE_DISABLED, 5012 ANTIVIRUS_DISABLED, 5013 "Tamper protection blocked a change", 5007
  CONFIG_CHANGED ("If this event is unexpected, you should review the settings as the event might
  be the result of malware"), 5004 RTP_FEATURE_CONFIGURED (its Configuration field is listed with
  no values), 2050 sample submitted ("This event is informational"). On 1117: "The **Allow**,
  **No action**, and **None** actions don't remediate detected threats." Severity examples "Low,
  Moderate, High, or Severe". 1122 / 1125 / 1126 are not on the page; 1121's field list looks
  copied from 1120.
- **Microsoft, "How Microsoft identifies malware and potentially unwanted applications"**
  (updated 2026-09-10): names follow CARO; the Type lists (malware: Backdoor, Exploit, HackTool,
  PWS, Ransom, Trojan, TrojanDownloader, VirTool, Worm ...; unwanted software: Adware,
  BrowserModifier ...; PUA ...; Tampering; Vulnerable, VulnerableDriver; Behavior, Tool). The format
  itself is an image - the text-only part is "Type describes what the malware does"; "A suffix that
  begins with ! is an indicator used by Microsoft internally".
- **ATT&CK T1685 Disable or Modify Tools** (v1.0, 11 Sep 2026; tactic TA0112 Defense
  Impairment): "Adversaries may disable, degrade, or tamper with security tools ... antivirus ...".
  Procedure examples name Windows Defender 18 times (Maze "disabled Windows Defender's Real-Time
  Monitoring", LazyWiper `Set-MpPreference`, PureCrypter `-ExclusionPath`, QakBot / Meteor /
  Raspberry Robin exclusion lists). T1562.001's URL returns an empty page - T1685 is the id cited.
  **DET0497 AN1369** (Windows): "killing AV/EDR processes, stopping services, altering Sysmon
  registry keys, or tampering with exclusion lists" - log sources 7045, Sysmon 5, 13/14; **no
  Defender event id**, TimeWindow a mutable element with no value.
- **SigmaHQ** `win_defender_threat.yml` (57b649ef, stable, high): EventID 1006, 1015, 1116, 1117,
  no field condition, tags `attack.execution, attack.t1059`; `win_defender_real_time_protection_disabled.yml`
  (b28e58e4, stable, high): EventID 5001, false positives "Administrator actions (should be
  investigated)" and "Seen being triggered occasionally during Windows 8 Defender Updates".
- ATT&CK data sources: none names antivirus or EDR alerts (data sources deprecated since v18).

## Proposed decisions

### W-D12 - an endpoint product's own verdict is read like a firewall's (Q114)

W-D1 stands for events *we* would judge suspicious (an encoded command line, an access mask).
A Defender detection is Defender's judgement, already made - the same class as CP-MAL-2 and
PAN-MAL-1. Two in-house rules, single-event, so no line (D16 does not apply - there is no
number). When the SigmaHQ story runs, its 57b649ef and b28e58e4 are superseded on Windows rows by
these (`SUPERSEDES`, as story 4), so one detection is never two suggestions.

### W-D13 - WIN-MAL-2 Defender detection: one suggestion per detection, outcome attached (Q115, Q116)

- **Evidence**: 1006, 1015, 1116 (detected). Their outcome events - 1117 / 1118 / 1119 (and the
  older 1007 / 1008) - join the same suggestion by `Detection ID` on the same host (observed in
  the events as written; the page lists no Detection ID - stated as an internal method), else by
  host + threat `ID` + `Path`. One detection = one suggestion; its rows are the detection and its
  outcome events.
- **Text**: `Defender: Trojan:PowerShell/Meterpreter.gen!A (Trojan, Severe) on IT02 - powershell.exe,
  CORP\Leo, via AMSI - Quarantine`. The threat's Type (the part before `:`) is shown as Microsoft
  names it, not mapped.
- **Level (Q115)**: high when the threat was not remediated - no outcome event in the evidence, an
  outcome of Allow / No action / None (the page's warning), or 1118 / 1119; **medium** when 1117 /
  1007 says Quarantine, Remove, Clean or Block - Defender stopped it, as a refused row is capped at
  medium (gotcha #26). SigmaHQ's level is high for all four ids.
- **Technique**: none. A detection says what Defender found, not what the attacker did; SigmaHQ's
  blanket T1059 would put adware into Execution. As CP-MAL-2's Anti-Virus verdicts carry none.
  Area **Malware & C2**.
- **Entity**: the host and the Detection User (`User` on 1006).
- **1011 (Q116)**: an item deleted from quarantine had been quarantined, so the threat was on that
  host - but its detection event may be outside the evidence (as Glupteba's is). Recommended: a
  1011 whose threat has no detection event on that host in the evidence becomes a WIN-MAL-2
  suggestion of its own at **medium**, saying "the detection itself is not in the evidence".
  1013 (history deleted) and 2050 (sample submitted, "informational") stay Timeline.

### W-D14 - WIN-HOST-3 Defender turned off or tampered with (Q117, Q118)

- **Evidence**: 5001 (real-time protection disabled), 5010 (malware scanning disabled), 5012
  (virus scanning disabled) - **high** (SigmaHQ b28e58e4's level); 5013 (tamper protection blocked
  a change) - **medium**: the attempt was refused.
- **Facts on the suggestion, no window** (Q118): when Defender was turned back on (the next 5000
  on that host, or "not in the evidence"), and the Defender update events (2000 / 2001 / 2014)
  nearest before and after - SigmaHQ's update false positive - for the analyst and the AI to weigh.
- **5007 (Q117)**: most 5007s are routine (the file's is `MpCampRing = 0x4`). Recommended: only a
  5007 whose New Value is under `...\Windows Defender\Exclusions\` - exclusion lists are what
  AN1369 and five T1685 procedures name. The key path itself is observed, not documented on
  Microsoft's page (stated on the rule).
- **5004**: Timeline only - the page lists Configuration with no values, so "0 = off" would be a
  guess.
- **Technique** T1685, tactic TA0112 Defense Impairment (`TACTICS["t1685"]`). Area **Host
  activity**. Entity: the host.

### W-D15 - every form of a Windows log (Q119)

The rules read `win_events.data` by Defender's own item names (`Threat Name`, `Severity Name`,
`Detection ID`, `Action Name`, `Detection User`, `Process Name`, `Path`, `Source Name`). NXLog JSON
writes those names (seen); event XML and .evtx carry them as EventData names; Winlogbeat may write
them differently, and the Splunk text form names items from message templates
(`app/data/windows`) - Defender's channel templates may not be exported yet. Recommended: check
each reader on a real or exported Defender event before the rule claims that form; a form not
checked is listed as a blind spot in RULE_META, not guessed.

## Not in this story

ASR (1121 / 1122) and network protection (1125 / 1126) - not on Microsoft's page as read; Defender
for Endpoint alerts (a different product, not a local event log); stopping the Defender service
(7036 / Sysmon 5, AN1369's other half - a sequence, its own story); SigmaHQ's other `windefend`
rules.

## Test

- `tests/check_windows_rules.py`: built events for 1116 + 1117 Quarantine (one suggestion, medium),
  1116 alone (high), 1116 + 1117 Allow (high), 1118 (high), 1011 with and without its 1116, 5001 + 5000,
  5013 (medium), 5007 MpCampRing (none) and an exclusion (high).
- `WinEvents.log` re-processed: WIN-MAL-2 2 (Meterpreter medium, Glupteba medium), WIN-HOST-3 1
  (ACC01, back on at 13:13), nothing else.
- `tests/gen_windows_domain.py` (Mekong quarter) and the blind quarter unchanged unless they hold
  Defender events (checked, reported); `tests/check_rule_meta.py`; parity on `tests/samples` and
  `D:/logtest` - the EVTX samples may contain Defender events, every move listed.

## Questions

- **Q114 - the split (W-D12).** An endpoint product's own verdict is an in-house rule, like a
  firewall's; W-D1 stays for events we would judge ourselves? Recommended: yes.
- **Q115 - WIN-MAL-2's level (W-D13).** High when not remediated (no outcome, Allow / No action /
  None, 1118 / 1119), medium when quarantined / removed / cleaned / blocked? Recommended: yes.
- **Q116 - 1011 (W-D13).** A quarantine delete whose detection is outside the evidence becomes its
  own medium suggestion? Recommended: yes.
- **Q117 - 5007 (W-D14).** Only exclusion changes, or none of 5007? Recommended: exclusions only.
- **Q118 - turned back on (W-D14).** Show the next 5000 and the nearest update events as facts,
  with no window and no level change? Recommended: yes.
- **Q119 - forms (W-D15).** Claim only the forms checked on a real Defender event? Recommended: yes.
