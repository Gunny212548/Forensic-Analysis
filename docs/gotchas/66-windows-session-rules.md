# Gotcha #66

**66. Windows lateral movement and host rules: link by the session, and what a real capture missed**

Story 5b of `specs/windows_rules.md` (2026-10-26): WIN-LAT-1 (uncommon RDP, then commands),
WIN-LAT-2 (remote service or task in a network logon), WIN-LAT-3 (NTLM network logon without
Kerberos), WIN-HOST-1 (Kerberoasting), WIN-HOST-2 (LSASS read, then a file written), in two new
detection areas, *Lateral movement* and *Host activity* (Q83 - the Overview has eight cards, two
rows of four; a firewall shows both as n/a).

**No window, no number.** Every ATT&CK analytic for these (DET0327 / DET0530 / DET0409 / DET0157 /
DET0421 / DET0363) is a sequence; their windows are only examples ("e.g., 5 minutes"). Windows ties
the steps together itself: a 4624's `TargetLogonId` is the `SubjectLogonId` of each 4688 / 4697 /
4698 of that session and Sysmon 1's `LogonId`; Sysmon 10's `SourceProcessGUID` is the
`ProcessGuid` of what that process wrote (Sysmon 11). Logon ids repeat after a restart, so an event
is joined to the **latest** 4624 of its id on its host before it (`ASOF JOIN`, `win_session_acts`).
System sessions (0x3e7, 0x3e4, 0x3e5, 0x0) are never a logon's.

**WIN-LAT-1 is "a pair seen on one day" (the user's choice, 2026-10-26).** Admins RDP to servers
and run cmd / PowerShell every week - the synthetic quarter has ~100 such sessions - so "RDP then a
process" alone flags habit. A (source, account, host) with RDP on one day of the evidence is
AN0931's "first-time source/destination pair"; on two or more days it is a habit. The finding
states the evidence's span ("1 of the 92 days"), because in a one-day file every pair is first.

**WIN-LAT-3 compares an account with itself.** AN1144's "NTLM ... with no accompanying domain logon
events" is read as: the account has Kerberos (4768 / 4769 status 0x0) in the evidence, but never
from the address of this NTLM network logon. The second-floor scanner's `svc_scan` (NTLM all day,
never Kerberos) is therefore not flagged, and a case without the DC's log finds nothing.

**WIN-HOST-1's legitimate members are the AES requests** - Q70 again: the weak-ticket requests are
the behaviour, so the line is drawn on each account's most distinct services an hour with 0x11 /
0x12 tickets only (40 accounts, p99 1 -> above 2). Six finance users' daily RC4 ticket to one
legacy service stays under it; W5's 14 in 90 seconds does not.

**What the OTRF RDP capture taught** (`tests/samples/otrf`, real, 283 records): the RDP is a
*reconnect* - 4624 LogonType 7 from 1.2.3.4 - and Task Manager runs in the first logon's session
(0x10ac67), whose 4624 is not in the capture, so WIN-LAT-1 cannot link it (4778, the reconnect
event, is not read yet). The dump file `lsass.DMP` is there (Sysmon 11) but the capture's only
Sysmon 10 on lsass are svchost's (0x1000), so WIN-HOST-2's sequence is incomplete. Both are written
as blind spots on the rules; a single lsass dump file is a SigmaHQ single-event rule's (W-D1). What
it did find: WIN-LAT-3 on the outside client's NTLM logon (NLA) - baseline 0 -> 1.

Measured on `tests/gen_windows_domain.py` (seed 20260701): W5, W7, W8 found; the Zabbix rollout
(4 servers, label btp) found by WIN-LAT-2; 0 plain or look-alike events flagged. W4 (the phishing
chain and its beacon) is left: the chain is single events (SigmaHQ), the beacon story 5c.

Check: `tests/check_windows_rules.py` (5b cases included).
