# Gotcha #68

**68. Windows story 5d: low-and-slow needs the paper's whole cleaning, a reconnect is the session's own id**

Story 5d of `specs/windows_rules.md` (2026-10-26, Q88-Q92 as recommended): WIN-BRUTE-4 (B5,
Javed & Paxson's CUSUM), 4768 0x6 counted as a failed attempt, the RDP reconnect (4778) in
WIN-LAT-1, ADMIN$ / C$ in WIN-LAT-2 and the new WIN-LAT-4 (a file written to the share, then run).

**CUSUM saw nothing until the normal was cleaned the way the paper cleans it.** Measured on the
synthetic quarter (W3: three failures a day from rotating internet addresses, Jul 6 - Sep 25):
- Normal fitted on every source that ever succeeds: mean 2.53 failures per 100 attempts, variance
  110. H hit its cap (200 failures) and still had an in-control ARL of 1,952 events; the one epoch
  ran from the evidence's first day (stepped back by an out-of-control ARL of 727).
- With the attempts WIN-BRUTE-1..3 flagged left out (the paper runs on data "filtered to remove
  high-rate brute-forcers", §3.1 / Fig. 5): mean 1.57, variance 30, H 98 - still blind. Every
  remaining spike was one source: svc_backup's stale password on SQL01 (the btp), every 15 minutes.
- With §5's automation test as well (Zhang's chi-squared on seconds-of-minute and minutes-of-hour,
  3-day windows of >= 50 attempts, two-sided at 0.001 - the stale job's two windows): mean 0.75,
  variance 2.3, a beta-binomial with rho 0.02.

**The integer Z hid a one-failure shift.** The paper picks k "so that Zn is integer-valued ... for
convenience". With mu = 0.75 the integer mu + k is 2, so k = 1.25 instead of delta / 2 = 0.5, and W3
(about +1 failure per 100) left Z's mean negative: H 16, out-of-control ARL 438 events in a
285-event quarter. Z is now counted in quarters of a failure (`lines.CUSUM_SCALE`): k = 0.50, H
21.5, in-control ARL 3,721 (the paper's 3,720), out-of-control ARL 45.5.

Result: five alarm runs, the first four merged into one epoch (Jul 2 - Aug 27) by the step back;
**156 of W3's 246 failures** flagged, 142 sources against W3's 4 accounts, no plain or look-alike
event. Missed: W3's last month - after Aug 27 one run (Sep 14-15) no longer alarmed without its
top source and was dropped as a singleton. Javed's reset (an event at or below the normal mean ends
the run) fragments a slow attack into short runs; the step back is what joins them. The
participants step (a pair that ever signs in, or a name one letter from one the source signs in
with, is benign) removed every ordinary failure inside the epoch, including the new mistyped-name
look-alikes.

`lines.cusum_h` searches H by doubling, then halving: a chain of 800 states (200 failures in
quarters) returned a negative ARL - the elimination loses precision when the ARL is astronomical.

**A reconnect carries the session's own logon id; its 4624 type 7 do not.** On the OTRF capture the
4778 names `0x10ac67`, under which Task Manager (the dump) and rdpclip run; the reconnect's four
4624 type 7 each have a new id that runs nothing, and the session's first 4624 is outside the
capture. So WIN-LAT-1 starts a session at a 4624 type 10 *or* a 4778 `RDP-Tcp#N` (Console is Fast
User Switching), and a process belongs to the latest start of its id. OTRF: WIN-LAT-1 0 -> 8 (the
4778, one 4688, six Sysmon 1); WIN-HOST-2 still misses the dump (no Sysmon 10).

**Shares.** 5140 is once per session; its `SubjectLogonId` is the session's. 5145's file is
`ShareLocalPath` (written `\??\C:\Windows`) + `RelativeTargetName`; WriteData is AccessMask 0x2. A
4697's ServiceFileName may say `%SystemRoot%`. Detailed File Share auditing (5145) is often off -
a host without it shows nothing to WIN-LAT-4 (rule_meta says so; the n/a matrix is per area, not
per rule). 7045 is not typed: no Microsoft page for it was found.

**The generator keeps the old quarter.** 5d's events draw from their own `random.Random(seed + 5)`,
swapped in after W8, so every 5a-5c event is unchanged (record numbers shift where new events
interleave). Added: W8's 5140 / 5145, W10 (an admin's disconnected RDP session reconnected at night
from 198.51.100.23), W11 (200 invented names, 4768 0x6, from W1's guest device), the patch pushed
through C$ (btp, found by WIN-LAT-2 / -4), an admin's lunchtime reconnects on 15 days and 8
mistyped user names (look-alikes, not flagged).

Parity: `otrf/rdp_interactive_taskmanager_lsass_dump.json` WIN-LAT-1 0 -> 8 (flagged 1 -> 9); every
other entry unchanged (samples, `D:/logtest` 59 names, `Logtest` 67).

Check: `tests/check_windows_rules.py`.
