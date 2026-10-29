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

As read (2026-10-26, `SOURCES.md`): a bad password is 4625 Status / SubStatus `0xC000006A`, 4771
Failure Code (`Status`) `0x18`, 4776 Error Code `0xC000006A`; an unknown user name `0xC0000064` /
4771 `0x6` (counted too - the analytics name failures "for valid or invalid users"). **4776 has no
source address**, only the Source Workstation name, and it is logged on the DC for an NTLM attempt
that the target host logs again as a 4625. So: 4625 and 4771 are counted with their IpAddress; a
4776 is counted only when no 4625 for the same account falls in the same second, and its source is
the workstation name, said so on the finding. A machine account (a name ending in `$`, "Computer
account name ends with $", 4769 page) is left out of BRUTE-3.

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
  Windows rows. **Built 2026-10-26** (gotcha #65): on the synthetic quarter (88 files, 98,403 events)
  W1, W2, W6, W9 and W7's reuse of the guessed account found, 0 plain or look-alike events flagged
  (the generic rules: W1 missed, 3,079 plain rows); W3 low-and-slow missed (B5, no rule). One
  incident added to the generator for B3: W9, distributed guessing from 30 internet addresses.
  W-D4 as built: a DC's 4771 / 4776 / 4768 joins a host's 4625 / 4624 of the same account and
  outcome within one second; the same event id twice is two attempts.
- **5b - lateral movement and host activity:** WIN-LAT-1..3, WIN-HOST-1..2, the two areas (W-D3),
  the events to type. **Built 2026-10-26** (gotcha #66). Q87 (the user, 2026-10-26): WIN-LAT-1 flags
  an RDP session that ran a process only when its (source, account, host) shows RDP on **one day**
  of the evidence (AN0931's first-time pairs) - admins' recurring sessions are a habit. No event was
  typed: the five rules need only 4624 / 4688 / 4697 / 4698 / 4769 and Sysmon 1 / 10 / 11, already
  typed; 4778 (RDP reconnect), 5140 / 5145 and 7045 wait for their pages and a rule that needs them.
  Synthetic quarter: W5, W7, W8 found, the Zabbix rollout found (btp), 0 plain or look-alike events.
  Real OTRF RDP capture: the outside client's NTLM logon found (WIN-LAT-3); the reconnect (type 7)
  and the dump without a Sysmon 10 missed - blind spots on the rules.
- **5c - network on the host:** WIN-MAL-1, WIN-INTEL-1..3. **Built 2026-10-26** (gotcha #67) as
  WIN-MAL-1 and WIN-INTEL-1..2: a blocked twin (INTEL-3) has nothing to match - Windows logs no
  refused connection. WIN-MAL-1 is R2007's method per (host, process, destination) with silences
  over an hour left out (R2007 missed W4's working-hours beacon). With 5a-5c every incident of the
  quarter is found and no plain or look-alike event is flagged.
- Not in story 5: SigmaHQ's single-event rules - ADR-006's own story.
- **5d - what 5a-5c left** (below): B5 low-and-slow, failed 4768, the RDP reconnect, admin-share
  access. **Approved 2026-10-26, Q88-Q92 as recommended** (the user: "Q88-Q92 : yes ทำตาม design
  เลย"). **Built 2026-10-26** (gotcha #68): W3 156 of its 246 failures by WIN-BRUTE-4 (Jul 2 - Aug 27;
  the last month missed - a late run dropped as a singleton), W10 by WIN-LAT-1 through the 4778, W11 by
  WIN-BRUTE-2 through 4768 0x6, W8's copy by WIN-LAT-4; no plain or look-alike event flagged; the OTRF
  reconnect found (WIN-LAT-1 8 rows). Two changes the measurement forced, both stated in gotcha #68: the
  normal is cleaned as the paper cleans it (pointwise brute-forcers left out, §5's automation test),
  and Z is counted in quarters of a failure, not whole ones.

## Story 5d - what 5a-5c left (approved 2026-10-26)

Documents read for it (`SOURCES.md`, 2026-10-26): Javed & Paxson §4.1, §5 and §6's parameters in
full; Microsoft 4768's failure codes, 4778 / 4779, 5140, 5145. No Microsoft page for System 7045
was found.

### W-D5 - B5 low-and-slow: Javed & Paxson's two steps (WIN-BRUTE-4, Q88)

W3 is three failures a day from a different internet address each time: no source, account or
hour ever has enough to count, so BRUTE-1..3 cannot see it by design. Javed & Paxson detect it
site-wide, then name who took part:

1. **Site analyzer.** The case's attempts (`win_attempts`, one attempt however many events record
   it) in time order, cut into *events* of n attempts; Y = failures per event (GFI, §4.1).
   **Normal from the case's own evidence (§5, D16):** drop sources that never succeed and sources
   with a failure ratio ≥ 0.95 over ≥ 20 attempts, fit a beta-binomial to the rest's Y by moments;
   μ is its mean. CUSUM: Zn = Yn - μ - k, Sn = max(0, Sn-1 + Zn), alarm when Sn > H and rising;
   **k = δ / 2**; **H from the in-control ARL** (the Markov chain of §4.1, over the fitted
   distribution) for the paper's false-alarm rate, one per 3,720 events. An epoch = the alarmed
   events plus the out-of-control ARL stepped back. An epoch that no longer alarms without its
   top-failing source is a singleton and dropped - BRUTE-1 / BRUTE-2 already name it.
2. **Participants (§4.2).** In an epoch, a failed attempt is benign if its (source, account) pair
   succeeds anywhere in the evidence, or the source succeeds as an account at edit distance 1. The
   rest are the finding, listed with what they share (target host, accounts). The paper does the
   "coordination glue" step by hand; here the analyst does it too - the system orders, not decides.

n stays the paper's 100. **δ is the open choice (Q88)**: the paper's δ = 10 failures per 100 was
set for LBNL's rate and would never see W3. Rough prototype on the quarter (raw 4624 / 4625, not
`win_attempts`): ~238 attempts a day, ordinary failures ~1 per 100 outside three spikes (W6),
W3 ≈ +1.3 per 100. With δ = 1 to 2 the alarmed events held 110-149 of W3's 246 failures - and
134-170 plain failures, which is what step 2 has to remove. To be measured with the rule itself.

### W-D6 - a refused TGT (4768) is a failed attempt (Q89)

4768's page: a refused TGT is a Failure event with a Result Code other than 0x0; **0x6 "The
username doesn't exist"**; 0x18 (wrong password) cannot occur in 4768 - 4771 carries it. Proposed:
4768 0x6 counts as a failed attempt (as 4771 0x6 and 4625 0xC0000064 already do), and joins a
host's 4625 by W-D4's one-second rule. 0x12 (account disabled, expired or locked out) and 0x17
(password expired) are refusals, not guesses - kept as Timeline events. This is what makes a
Kerberos user-name enumeration (an AS-REQ per guessed name, nothing else logged) visible to
BRUTE-2.

### W-D7 - the RDP reconnect joins WIN-LAT-1 (Q90)

4778 (Audit Other Logon/Logoff Events) records a reconnect to an existing session: SessionName
`RDP-Tcp#N`, ClientAddress, AccountName, and **LogonID - the session's own id**. Checked on the
OTRF capture: its 4778 carries `0x10ac67`, the id under which Taskmgr.exe (the LSASS dump) runs,
while the four 4624 type 7 of the reconnect each have new ids that run nothing. So: a 4778 with
an `RDP-Tcp#` session counts as an RDP session for WIN-LAT-1 - the same one-day rule (Q87) over
(ClientAddress, account, host), the same process link through LogonID. `Console` (Fast User
Switching) is not RDP and is left out. The OTRF dump would then be found.

### W-D8 - admin-share access, on the target only (Q91)

AN1468: ADMIN$ / C$ accessed, then on the target a remote service, a task or a process. 5140 is
logged once per session at the first access, with the session's SubjectLogonId and IpAddress; 5145
per file, with RelativeTargetName and AccessMask (0x2 = WriteData). Proposed, all on one host and
linked by the session (W-D2), no window:
- **WIN-LAT-2** also counts a session whose 5140 names `ADMIN$` or `C$` and then creates a service
  or task (the share shown on the finding).
- **WIN-LAT-4** (new): a file written into `ADMIN$` / `C$` (5145, AccessMask with 0x2) and then
  run on that host - a 4697 ImagePath or a 4688 / Sysmon 1 image naming the same file (PsExec
  copies PSEXESVC.exe to ADMIN$, then installs it). T1021.002 (AN1468); T1570 Lateral Tool Transfer only once its page is read.
The step across two hosts (which session on the source started it) is left out: it needs a time
window, and the target alone already shows the movement. 5145 needs Detailed File Share auditing,
which many sites leave off - a host without 5145 is n/a for WIN-LAT-4 with that reason.

### W-D9 - 7045 is not typed (Q92)

No Microsoft page documents System 7045, so it is not typed (gotcha #55). 4697 covers a service
install where Security System Extension auditing is on; a host that logs only 7045 is a blind spot
recorded on WIN-LAT-2.

### Test data for 5d

`gen_windows_domain.py` gains: W8 with its 5140 ADMIN$ and 5145 write of PSEXESVC.exe; W10 an RDP
reconnect at night from an outside address followed by commands; W11 a Kerberos user-name
enumeration (4768 0x6 for 200 guessed names from one workstation). Look-alikes: an admin's
habitual reconnects, software deployment through ADMIN$ (a btp, as the Zabbix rollout), a single
mistyped user name. Scored as before: every incident found, no plain or look-alike row flagged, W3
by WIN-BRUTE-4 and not by chance; parity and the OTRF capture re-run (the dump expected found).

## Story 5e - two false positives the blind test found (approved and built 2026-10-26)

Q98 yes, Q99 a (the user: "Q98 : yes / Q99 : a ทำตาม design เลย"). Built (gotcha #70): on the
blind quarter, not-attack rows flagged 43,523 -> 2,567, every incident found as before.

The user's blind test (`D:\logtest\blind-windows`, `gen_windows_blind.py` seed 20260401 - a textile
company's quarter, incidents K1-K15, an answer key) was uploaded to 8091
(case-20261026-090407-fbc50d64) and scored once against its answer key, with the rules unchanged.
43,523 rows that are not attacks were flagged; two causes are fixed here. **After this story the
kinnaree quarter is no longer blind** for these two rules: its answer key has been read, so a result
on it measures the fix, not the rule set. An honest re-test needs a quarter the rules were not fixed
on (another seed, its key unread).

### W-D10 - a sprayer's own computer account is not an account it broke into (Q98)

WIN-AUTH-1 flags a success from a source WIN-BRUTE-1..3 flagged - for the same account, or for **any**
account when the source was a sprayer. On the blind quarter the sprayer is WEB01 (K2 / K3, after the
web shell): its machine account `web01$` signs in from its own address all day, and every one of those
was flagged - 231 rows, the finding text itself saying "likely the owner". Proposed: the spray branch
leaves out computer accounts (a name ending in `$` - Microsoft 4769, read), as WIN-BRUTE-3 already
does; the same-account branch is unchanged (a guessed machine account that then signs in is still
flagged). Measured on the two cases: blind quarter 231 -> 0 (K3's pimchanok.k / napat.s, K5's
svc_print and K14 kept); Mekong unchanged (no computer account in WIN-AUTH-1).

### W-D11 - a beacon every host makes is not to a rare destination (Q99)

The analytics behind beaconing ask for regular callbacks to **rare** destinations from processes that
do not belong there: "beacon-like patterns or POST-heavy behavior to rare domains" (T1071.001 DET0027
AN0076), "encrypted TLS traffic to rare external hosts" (T1573 DET0273 AN0761), "abnormal processes"
(T1071 DET0444 AN1225) - re-read 2026-10-26; none defines "rare". On the blind quarter 40,725 of the
59,143 flagged rows (69%) are one beacon: ESET's `ekrn.exe` checking in with `198.51.100.10` on a
timer - the same process to the same address on **40 of the 43 hosts** with Sysmon network events. The
real beacons are one host each (K7 `wuauhelper.exe`, K15 `rundll32.exe`; Mekong's W4 `updater.exe`).

Proposed: a (process image, destination) that beacons on **more than half** of the hosts with Sysmon
network events in the evidence is the fleet's, not a rare destination - left out of WIN-MAL-1, and
listed on the case's line record (`lines`, "fleet-wide timers left out: ekrn.exe -> 198.51.100.10 on 40
of 43 hosts") so the analyst can see what was not flagged. "More than half" is an internal method,
stated, not a measured threshold (D16 has nothing to measure "rare" on: the evidence holds no
legitimate beacons to draw a line over). Measured: blind quarter 40,725 -> 0, K7 and K15 kept; Mekong
unchanged.

**Q105 (code review, 2026-10-27; the user chose the floor):** "more than half" had no floor, so on one
host's evidence - the commonest forensic case - every beacon was "more than half" of one host and
WIN-MAL-1 could never fire. The fleet test now applies only from **20 hosts with Sysmon network events**
(`lines.MIN_LEGIT`, as Q67 / gotcha #57's MIN_CROWD); under that every beacon is flagged and the line
record says why. The blind quarter (43 hosts) and Mekong are unchanged.

**The risk, said plainly:** an implant on more than half of the machines, all calling the same address,
would be left out - and listed on the line record. Under half, it is flagged as today. The other choice
(Q99 b) keeps them flagged at level low: no beacon hidden, but the 40,725 rows stay false positives and
each host stays a suggestion.

### Tests

`tests/check_windows_rules.py`: a small capture - a sprayer whose own `...$` signs in (not flagged) and a
sprayed user who signs in (flagged); one process to one address on most hosts (left out, on the line
record) beside one host's beacon (flagged). The Mekong quarter unchanged; parity. The blind quarter
re-scored and reported as a measurement of the fix only.

## Story 5g - a deployment tool's routine is not lateral movement (approved 2026-10-29)

Q120 yes, Q121 / Q122 as recommended (the user: "yes", 2026-10-29). Every rule scored on the three
ground-truth quarters with the code of story 5f (Lotus Check Point, Mekong, Kinnaree): Mekong flags no
plain or look-alike event; on Kinnaree 2,560 of the 2,567 not-attack rows are WIN-LAT-2 / WIN-LAT-4 -
2 of WIN-LAT-2's 4 suggestions and 2 of WIN-LAT-4's 3 are a backup product's guest helper
(`svc_veeam` from 10.50.1.40, `VeeamGuestHelper` on 5 servers, **91 of the 91 days**) and a software
deployment tool (`svc_pdq` from 10.50.1.50, `PDQDeployRunner-1..3` on 43 machines, **3 days**). The
attacks the rules find are each one day: K10's smbexec service `BTOBTO`, K12's task
`\Microsoft\Windows\Defrag\ScheduledDefragCheck` and `kin.exe`; Mekong's W8 `PSEXESVC` and its two
benign rollouts (Zabbix agent, a patch through C$ - one day each, shown to the analyst on purpose).

### W-D16 - a remote service, task or copied file seen on two days or more is expected (Q120)

The analytics name the tuning and leave its content to the defender: AN1468's UserContext "Distinguish
expected remote administrators vs. rare/first-time access by specific users" (T1021.002 DET0530), and
AN1185's ServiceBinaryAllowlist "Known binaries/services expected to be invoked via services.exe" and
RemoteExecutionHosts "Approved remote hosts that may trigger service execution (e.g., via PsExec)"
(T1569.002 DET0421) - re-read 2026-10-29. No allowlist comes with an upload (no asset inventory), so
"expected" is read off the evidence, the way Q87 read AN0931's first-time pairs for WIN-LAT-1:

- **WIN-LAT-2**: the (source, account, service or task name) of each hit; flagged only when that name
  was created by that account from that source on **one day** of the evidence (4697 / 4698 in a
  network logon's session, any host).
- **WIN-LAT-4**: the (source, account, file path) of each write then run; flagged only when that file
  was written by that account from that source on **one day**.
- A one-time rollout stays flagged - an analyst decides it (Mekong's two benign ones).

**The risk, said plainly:** an attacker who installs the same service name from the same source as the
same account on two different days is left out of both rules - the blind spot WIN-LAT-1 already has.
A different name, a different source or a different account on any day is still flagged.

Measured before building (the queries on the scored cases): Kinnaree's Veeam and PDQ out (0 of the
2,560 rows), K10 and K12 kept; Mekong unchanged.

**Built 2026-10-29** (gotcha #77). Kinnaree: WIN-LAT-2 not-attack rows 1,232 -> 0 (suggestions 4 -> 2),
WIN-LAT-4 1,328 -> 8 (3 -> 2) - only FILE01 and APP01 audit 5145, and there two PDQ runner files were
written on one day, so by the rule's own evidence they are a first time; left for the analyst. K10 /
K12 unchanged, Lotus unchanged. Found writing the test: WIN-LAT-4 read `%SystemRoot%` only in lower
case, so a 4697 never matched the written file (Windows writes it mixed case) - now lowered first;
Mekong's W8 gains its service-install row (WIN-LAT-4 3 -> 4 attack rows), nothing else moves.

### W-D17 - LSASS opened with the right to read its memory (Q123, approved 2026-10-29)

Found on public data the rules were not built on (2026-10-29, `D:/logtest/internet`: EVTX-ATTACK-SAMPLES
271 files, OTRF Security-Datasets 91 host datasets). WIN-HOST-2 fired on 6 OTRF datasets that are not a
dump (DCOM, WMI, a service DLL hijack, mimikatz key extraction): `svchost.exe` (the Prefetch writer)
opening lsass.exe with GrantedAccess `0x3000` and then writing a `.pf` file. The rule never read the
access. What was read (2026-10-29):

- Microsoft, MiniDumpWriteDump, hProcess: "This handle must have PROCESS_QUERY_INFORMATION and
  PROCESS_VM_READ access to the process."
- Microsoft, Process Security and Access Rights: PROCESS_VM_READ (0x0010) "Required to read memory in a
  process using ReadProcessMemory."; PROCESS_QUERY_LIMITED_INFORMATION is 0x1000.
- AN1030 (T1003.001 DET0363), AccessMask: "Set to 0x1F0FFF to detect full memory access attempts; can
  be scoped down to reduce noise."

Decision: WIN-HOST-2 counts a Sysmon 10 only when its GrantedAccess carries PROCESS_VM_READ
(`& 0x10`) - the least a process needs to read lsass's memory, by a dump (MiniDumpWriteDump) or directly
(ReadProcessMemory, mimikatz's 0x1010). Scoped down from AN1030's 0x1F0FFF as its own field allows; a
handle that cannot read memory cannot dump credentials. Expected from the hits' access values: the six
`0x3000` datasets out; procdump, Dumpert / AndrewSpecial, powerdump and the RDP Task Manager dump kept
(0x1fffff / 0x1f3fff / 0x1410); Mekong's W7 (0x1fffff) kept; OTRF's PowerShell-remoting `wsmprovhost.exe`
(0x1410, 0x1f3fff, then a CLR log) still flagged - it can read memory, the analyst decides.

**Built 2026-10-29** (gotcha #78), measured as expected: the six datasets fire nothing, every dump kept,
Lotus / Mekong / Kinnaree unchanged.

### Not changed (Q121, Q122)

- **WIN-LAT-1, the admin's RDP from the jump host** (Kinnaree, 1 suggestion, 7 rows): a pair seen on one
  day is exactly AN0931's first-time pair the user chose (Q87); left for the analyst.
- **CP-MAL-1, a monitoring proxy's 15-minute heartbeat** (Lotus, 1 suggestion, 8,876 rows): by timing
  it is a beacon (gotcha #15), and the fleet test of W-D11 needs a fleet - one proxy is one host. Left
  for the analyst. R3001's OneDrive uploads (14 rows) wait for a data-transfer legitimacy criterion
  (PAN-DATA-1).
- Missed incidents are new detections, not fixes: K1 / K6 / K8 / K11's single events wait for the
  SigmaHQ story (W-D1); K9 is WIN-LAT-3's stated blind spot; Lotus I3 / I6 need a Check Point sign-in
  document (or the user's OK to use the undocumented "Failed Log In").

### Tests

`tests/check_windows_rules.py`: a remote service and a copied-then-run file created on two days from
one source as one account (not flagged), and the same on one day (flagged) - beside the Mekong
quarter, unchanged. Parity. Kinnaree and Lotus re-scored, reported as a measurement of the fix.

## Questions

- **Q120 - expected remote services (W-D16).** Flag WIN-LAT-2 / WIN-LAT-4 only when their (source,
  account, service / task / file) is seen on one day of the evidence? Recommended: yes.
- **Q121 - WIN-LAT-1's jump host.** Leave as Q87 chose? Recommended: yes.
- **Q122 - CP-MAL-1's heartbeat.** Leave for the analyst? Recommended: yes.
- **Q123 - LSASS access (W-D17).** Count a Sysmon 10 on lsass.exe for WIN-HOST-2 only when its
  GrantedAccess carries PROCESS_VM_READ (0x10)? Recommended: yes. **Answered: yes** (the user: "ok").

- **Q98 - the sprayer's own computer account (W-D10).** Leave computer accounts out of WIN-AUTH-1's
  spray branch only? Recommended: yes.
- **Q99 - fleet-wide beacons (W-D11).** (a) leave a (process, destination) beaconing on more than half
  of the Sysmon hosts out of WIN-MAL-1, listed on the line record; or (b) keep it at level low.
  Recommended: (a).
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
- **Q88 - B5 (W-D5).** WIN-BRUTE-4 by Javed & Paxson's CUSUM + participants step, and which shift
  δ to detect? Recommended: the method as written, δ = 1 failure per 100 attempts (k = 0.5), H from
  the paper's false-alarm rate; the analyst decides the participants.
- **Q89 - 4768 (W-D6).** Count 4768 0x6 as a failed attempt, 0x12 / 0x17 as Timeline only?
  Recommended: yes.
- **Q90 - reconnect (W-D7).** A 4778 `RDP-Tcp#` reconnect counts as an RDP session for WIN-LAT-1?
  Recommended: yes.
- **Q91 - shares (W-D8).** Widen WIN-LAT-2 with 5140 ADMIN$ / C$ and add WIN-LAT-4 (file written
  to the share, then run), target host only? Recommended: yes, no cross-host step.
- **Q92 - 7045 (W-D9).** Leave 7045 untyped until a document is found? Recommended: yes.
