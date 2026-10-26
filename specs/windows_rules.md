# Windows detection rules - design (story 5 of `specs/per_product_rules.md`)

Status: **Approved 2026-10-26** - Q81-Q84 and Q86 as recommended; Q85 yes, over **three months**
(the user: "3 เดือน"). The user: "เริ่ม design กฎของ Windows
เลย". Builds on D10-D16 of `per_product_rules.md` and the readers of `windows_event_logs.md`.

## Where Windows stands today

- **Read:** event XML, `.evtx`, Splunk WinEventLog text, Winlogbeat / NXLog JSON (W1-W4, gotcha #60).
  Every event keeps its own items in `win_events.data` (a MAP, ADR-006 decision 2) and gets a
  layer-A type from its Microsoft page (`winevent.SECURITY_TYPES`, `SYSMON_TYPES`).
- **Detected:** only sign-ins. 4625 / 4624 feed the generic R2000 / R2005 / R2006 / R2008 / R2009,
  which still run on Windows rows (gotcha #63). Nothing reads a process, a service, a ticket or a
  logon type.
- **Measured:** the 278 EVTX-ATTACK-SAMPLES files - every one an attack - gave **0 findings**
  (baseline, W2). Seen and not fixed: R2006 flags a DC's machine account (`WIN-DC-259$`).
- **Test data:** `D:\logtest\windows` (the EVTX-ATTACK-SAMPLES clone, Elastic's Winlogbeat files,
  OTRF datasets) **is gone** - not on disk on 2026-10-26 (Q64). In the repo:
  `tests/samples/attack-data/windows-security*.log` (spray, XML and text), `windows-sysmon.log`,
  `tests/samples/otrf/rdp_interactive_taskmanager_lsass_dump.json` (283 NXLog records: an RDP
  logon, Task Manager dumping LSASS - 4624 x18, 4688 x17, Sysmon 1 / 3 / 10 / 11 / 18).

## What the documents say (read 2026-10-26, `docs/standards/SOURCES.md`)

ATT&CK's detection strategies for the Windows behaviours an attacker leaves in these logs:

| Technique | Strategy / analytic | The pattern (paraphrased) | Shape |
|---|---|---|---|
| T1021.001 RDP | DET0327 / AN0931 | an RDP logon (4624, 4648, 4778/4779) followed by unusual process execution, file access or onward movement (Sysmon 1, 3, 22) | sequence, "e.g., 5 minutes" |
| T1021.002 SMB / admin shares | DET0530 / AN1468 | access to ADMIN$ / C$ followed on the target by a remote service, a scheduled task or suspicious process | sequence across two hosts, "e.g., 5-10 minutes" |
| T1550.002 Pass the Hash | DET0409 / AN1144 | NTLM network logons (LogonType 3) with no accompanying domain logon events; source user context that does not fit the system | correlation, no number |
| T1558.003 Kerberoasting | DET0157 / AN0444 | 4769 service tickets with RC4 (0x17); an account requesting an unusual number of service tickets in a short period | count per account, threshold left open |
| T1569.002 Service Execution | DET0421 / AN1185 | a temporary service (sc.exe, PsExec) created and run; services.exe starting a non-standard binary (4697, Sysmon 1 / 13) | sequence, no number |
| T1003.001 LSASS Memory | DET0363 / AN1030 | a process opens lsass.exe with full access (0x1F0FFF) and then writes a dump file or touches the registry (Sysmon 10 -> 11 / 13) | sequence, "e.g., 5 minutes" |
| T1070.001 Clear Windows Event Logs | - | the page came back empty - **not read**, not cited | - |

Two things follow from that table:
1. **Every Windows analytic is a sequence or a count** - a logon *then* activity, an access *then*
   a dump. Not one of them is "this single event is the attack". The time windows appear only as
   examples ("e.g., 5 minutes"), and no count is given.
2. **Windows links the events itself**, so most sequences need no time window at all: a 4624's
   `TargetLogonId` is the `SubjectLogonId` of every 4688 / 4697 / 4698 that logon session does on
   that host, and a Sysmon `ProcessGuid` / `SourceProcessGuid` ties a process to what it opened and
   wrote. Both are in `win_events.data` today (checked on the committed samples).

## Proposed decisions

### W-D1 - in-house rules for sequences and counts; SigmaHQ for single events (Q81)

`WIN-*` rules are written only for what ATT&CK describes as a sequence or a count - the part
SigmaHQ cannot do (it publishes 0 correlation rules, ADR-006). A single suspicious event (an
encoded PowerShell command line, an LSASS access mask, a known tool name, a log cleared) is
SigmaHQ's: thousands of maintained Windows rules, run beside ours by ADR-006's engine, not
rewritten here. Until that story is built, single events stay what they are today: Timeline
events, typed, not findings.

### W-D2 - link by the session, not by a clock (Q82)

A sequence on one host is joined through `TargetLogonId` -> `SubjectLogonId` (logon session) or
`ProcessGuid` (Sysmon process). No window, no threshold to justify (D16), and an attacker who
waits an hour is still caught. A time window is used only where nothing links the events - two
hosts (the SMB access on the target and the session on the source) - and then it is the
analytic's own example value, shown on the finding as "the window ATT&CK gives as an example".

### W-D3 - two more detection areas (Q83)

The six areas (D12) were drawn for network logs; what happens on a host has no card. Proposed:
add **Lateral movement** (`LAT`) and **Host activity** (`HOST`: credential theft, service and task
execution, and later SigmaHQ's execution / persistence / stealth matches). Firewall products show
both as n/a: "a firewall log records connections, not what ran on a host". The Overview gets eight
cards instead of six.

### W-D4 - Kerberos and NTLM failures are sign-in failures on a DC (Q84, reopens Q41)

On a domain controller, a spray against domain accounts shows mostly as **4771** (Kerberos
pre-authentication failed) and **4776** (NTLM credential validation), not 4625. Q41 kept them out
of the count because a DC can log them beside a 4625 for the same attempt. Proposed: count 4625,
4771 with a bad-password status and 4776 with a bad-password status as failures, **one attempt
per account, source and second** (an internal method, stated), so a doubled attempt counts once.
The status values come from the 4771 / 4776 Microsoft pages already read for W1.

## Proposed rules

| Id | Behaviour | Windows events | Line / link | ATT&CK |
|---|---|---|---|---|
| WIN-BRUTE-1 | B1 guessing: failures on one account from one source, per sign-in episode | 4625, 4771, 4776 (W-D4) | evidence line, episodes ending in a success (D16, Q66) | T1110.001, DET0551 |
| WIN-BRUTE-2 | B2 spray: one source, many accounts | same | TRW on accounts (D16) | T1110.003, DET0487 |
| WIN-BRUTE-3 | B3 one account failing from many sources; machine accounts (`...$`) left out (to confirm on the 4624 / 4625 pages) | same | evidence line, 1 h | T1110.001, AN1521 |
| WIN-AUTH-1 | B4 failures then a success from the same source / account | + 4624 | follows BRUTE-1..3 | T1110, DET0463 |
| WIN-LAT-1 | RDP logon followed by process execution in that session | 4624 LogonType 10 -> 4688 / Sysmon 1, same LogonId | session link (W-D2); first-time source -> host pairs ranked first | T1021.001, AN0931 |
| WIN-LAT-2 | network logon followed by a service or task created in that session (PsExec-style) | 4624 LogonType 3 -> 4697 / 4698, same LogonId | session link | T1021.002 AN1468, T1569.002 AN1185 |
| WIN-LAT-3 | NTLM network logon with no Kerberos activity for that account from that source | 4624 LogonType 3 NTLM, no 4768 / 4769 | needs the DC's log in the same case, else n/a with that reason | T1550.002, AN1144 |
| WIN-HOST-1 | Kerberoasting: one account requesting RC4 service tickets for many services | 4769 TicketEncryptionType 0x17 | evidence line on distinct services per account per hour (the analytic leaves the number open) | T1558.003, AN0444 |
| WIN-HOST-2 | LSASS dump: a process opens lsass.exe, then writes a file | Sysmon 10 -> Sysmon 11, same ProcessGuid | process link (W-D2) | T1003.001, AN1030 |
| WIN-MAL-1 | beaconing of one process to a public address | Sysmon 3 | the firewall rules' measured method (R2007, `rules_firewall.py`) | T1071 |
| WIN-INTEL-1..3 | feed match on a destination (Sysmon 3) or a sign-in source (4624 / 4625) | Sysmon 3, 4624, 4625 | a match, no line | as PAN / CP-INTEL |

**n/a, with the reason shown on the case:** Scanning & policy - Security and Sysmon record no
refused connection (the Filtering Platform's 5157 would; not typed yet); Data transfer - no byte
counts in either log.

Each rule still needs, before it ships (per_product_rules.md, *What every rule carries*): its
fields cited from the event's Microsoft page; any event not yet typed (4778 / 4779 RDP reconnect,
5140 / 5145 share access, 7045 System-log service install) typed from its own page, read first; a
test.

The WIN rules supersede R2000 / R2005 / R2006 / R2008 / R2009 on Windows rows only (gotcha #63's
`RULE_SUPERSEDED`), which also ends R2006 on machine accounts.

## Tests (Q85)

The lab is gone, so the rules would be tested on four committed samples, one of them holding a
single attack. Proposed: `tests/gen_windows_domain.py`, built like `gen_checkpoint_quarter.py` - a
small Active Directory domain (one DC, about 40 workstations, a few servers) over three months of
ordinary work (sign-ins, mistyped passwords, admins on RDP, backups, scheduled tasks, service
accounts asking for tickets), with planted attacks and a ground-truth file: a spray seen as 4771
on the DC, password guessing, Kerberoasting, pass-the-hash lateral movement, PsExec-style service
creation, RDP followed by commands, an LSASS dump. Each rule is scored for misses and false
positives on it; the committed samples and the OTRF dump stay as real-data checks. EVTX-ATTACK-
SAMPLES comes back if `D:\logtest\windows` is restored (Q64, paused).

## Stories (Q86)

- **5a - sign-ins:** WIN-BRUTE-1..3, WIN-AUTH-1, W-D4, the domain generator, R-rules superseded on
  Windows rows.
- **5b - lateral movement and host activity:** WIN-LAT-1..3, WIN-HOST-1..2, the two areas (W-D3),
  the events to type.
- **5c - network on the host:** WIN-MAL-1, WIN-INTEL-1..3.
- Not in story 5: SigmaHQ's single-event rules - ADR-006's own story.

## Questions

- **Q81 - the split (W-D1).** Write in-house WIN rules only for sequences and counts, and leave
  single events to the SigmaHQ story? Recommended: yes.
- **Q82 - link by session (W-D2).** Join one host's events by LogonId / ProcessGuid instead of a
  time window, using ATT&CK's example window only across hosts? Recommended: yes.
- **Q83 - areas (W-D3).** Add *Lateral movement* and *Host activity* (eight cards), or keep six and
  fold Windows rules into the nearest existing area? Recommended: add the two.
- **Q84 - 4771 / 4776 (W-D4).** Count Kerberos and NTLM bad-password failures with 4625, one
  attempt per account, source and second? Recommended: yes - otherwise a spray against a DC is
  invisible.
- **Q85 - test data.** Build `gen_windows_domain.py` with ground truth? Recommended: yes, before
  story 5a's rules. **Answered: yes, three months** (like the Check Point quarter).
- **Q86 - order.** 5a -> 5b -> 5c, as above?
