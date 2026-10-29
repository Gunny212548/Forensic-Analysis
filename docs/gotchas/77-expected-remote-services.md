# Gotcha #77

**77. A deployment tool's routine is not lateral movement; Windows writes `%SystemRoot%` in mixed case**

Story 5g of `specs/windows_rules.md` (2026-10-29, Q120-Q122). Every rule was scored on the three
ground-truth quarters with story 5f's code (Lotus Check Point, Mekong Windows, Kinnaree Windows): Mekong
flagged no plain or look-alike event, but on Kinnaree 2,560 of the 2,567 not-attack rows were WIN-LAT-2
/ WIN-LAT-4 - a backup product's guest helper (`svc_veeam`, `VeeamGuestHelper`, on **91 of 91 days**)
and a software deployment tool (`svc_pdq`, `PDQDeployRunner-1..3`, 3 days, 43 machines). Every attack
the two rules find was one day (K10 smbexec `BTOBTO`, K12's task and `kin.exe`, Mekong's W8 and its two
benign one-day rollouts).

**W-D16:** WIN-LAT-2 flags a (source, account, service or task name) only when it was created on one
day of the evidence, WIN-LAT-4 a (source, account, file path) written on one day - "expected" read off
the evidence, as AN1468's UserContext ("expected remote administrators vs. rare/first-time access") and
AN1185's ServiceBinaryAllowlist / RemoteExecutionHosts ask (re-read 2026-10-29), and as Q87 read
AN0931 for WIN-LAT-1. The blind spot is stated on both rules: the same name from the same source as the
same account on two days is left out. Join the day count with `IS NOT DISTINCT FROM` - a 4697 in a
session with no address has a NULL source.

**What the evidence cannot say.** WIN-LAT-4 still flags 8 PDQ rows (one suggestion): only FILE01 and
APP01 audit 5145, and there `pdqdeployrunner-1/-2.exe` were written on one day. The rule sees one day,
so it is a first time by its own evidence - left for the analyst, not patched with WIN-LAT-2's view.

**`%SystemRoot%` (found writing the test).** WIN-LAT-4 matched a 4697's `ServiceFileName` against the
written file after `lower(replace(x, '%systemroot%', ...))` - the replace ran on Windows' mixed-case
`%SystemRoot%\PSEXESVC.exe` and never matched, so a service install was never the run half of a pair.
W8 was still found through its 4688 / Sysmon 1; a host with service auditing and no process auditing
would have shown nothing. Now `replace(lower(x), ...)`: Mekong's W8 gains its 4697 row (WIN-LAT-4 3 -> 4
attack rows).

Measured: Kinnaree WIN-LAT-2 not-attack rows 1,232 -> 0 (suggestions 4 -> 2), WIN-LAT-4 1,328 -> 8
(3 -> 2), K10 / K12 unchanged; Mekong unchanged except W8's row; Lotus unchanged. Left on purpose
(Q121, Q122): WIN-LAT-1's admin RDP from the jump host (AN0931's first-time pair), CP-MAL-1's monitoring
heartbeat (a beacon by timing, one host - no fleet to test).

Check: `tests/check_windows_rules.py` (story 5g capture: a tool's agent on two days not flagged, an
admin's one-day service flagged by both rules).
