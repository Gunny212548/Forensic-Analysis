# Gotcha #76

**76. An endpoint product's own verdict is read like a firewall's - and Defender names its items
differently in every event (2026-10-28, `specs/windows_defender_rules.md`, Q114-Q119 as
recommended).**

**What was missed.** The user's `WinEvents.log` (NXLog JSON, D:/logtest/window test) was ready with
0 suggestions. Right by the rules - it holds one event per event id, so no count or sequence can
fire - but it held a Defender detection of `Trojan:PowerShell/Meterpreter.gen!A` on IT02 (via AMSI,
CORP\Leo, quarantined), a Glupteba deleted from quarantine, and real-time protection turned off on
ACC01 for two minutes. W-D1 (Q81) had left single events to the SigmaHQ story, which is not built.
Q114 splits it: an event *we* would judge stays SigmaHQ's; a product's own verdict (Defender, as
Check Point's Threat Prevention in CP-MAL-2) is an in-house rule.

**WIN-MAL-2** (Malware & C2, no technique) groups 1006 / 1015 / 1116 with their outcome events
(1007 / 1117 taken, 1008 / 1118 / 1119 failed) by host and Detection ID. Medium when remediated
(Quarantine / Remove / Clean / Block, none failed), else high - 1117's own warning: "The Allow, No
action, and None actions don't remediate detected threats." A 1011 whose threat has no detection
event on that host is its own medium suggestion. **WIN-HOST-3** (Host activity, T1685 / TA0112):
5001 / 5010 / 5012 high, 5013 medium, 5007 only for `Windows Defender\Exclusions\`; when it was
turned back on and the nearest update event are written on the finding, no window.

**Read the provider's templates, not one sample.** `Get-WinEvent -ListProvider 'Microsoft-Windows-
Windows Defender'`: 1006 / 1015 write `Path Found` and `Domain` + `User`; 1007 / 1008 `Cleaning
Action`; 1116-1119 `Path`, `Action Name`, `Detection User`. The first SQL, written from the NXLog
sample's 1116, would have read no path, action or user from the older pair.

**A rule can lower its own level now.** `rules.apply_rules` sets `lvl = least(written, declared)`;
every rule wrote NULL before, so nothing else moved (parity exact). Only a lower level is kept.

**No generic twin.** Mapping WIN-MAL-2 to R3002 (as CP-MAL-2 is) was written, then removed: R3002 is
malware traffic a firewall let through - VERIS would call a detection a Downloader and the
compromised-host pattern would count a quarantined one.

**Measured.** WinEvents.log: 3 suggestions (Meterpreter medium, Glupteba medium, ACC01 high), nothing
else. This PC's Defender log as event XML and as .evtx (upload kind `log` - `evtx` is not an upload
kind, identify reads `.evtx` from a log): 39 detection rows each, 36 medium, 3 high (a Mimikatz the
user allowed); 0 of 2,616 routine 5007s flagged. Winlogbeat / Splunk text not checked on a Defender
event and not claimed. Parity `tests/samples` 11, `D:/logtest` 59 exact; baseline 668 -> 669
(WinEvents.log).

Check: `tests/check_windows_rules.py <scratch> [--winevents "D:/logtest/window test/WinEvents.log"]`.
