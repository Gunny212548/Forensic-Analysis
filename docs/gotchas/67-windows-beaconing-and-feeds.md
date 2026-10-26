# Gotcha #67

**67. Windows beaconing and feed matches: a beacon sleeps when the host does**

Story 5c of `specs/windows_rules.md` (2026-10-26): WIN-MAL-1 (beaconing per process, Sysmon 3),
WIN-INTEL-1 (a connection to a listed address), WIN-INTEL-2 (a sign-in attempt from one). They
supersede R2007 / R3003 / R3004 / R3005 on Windows rows; R3001 / R3002 stay generic (Windows logs
carry no bytes or category, so they never match there).

**R2007 missed a five-minute beacon.** On the synthetic quarter W4's implant connects every
300 ± 30 s - while the workstation is on (08:00-18:00, weekdays), Aug 3 to Sep 20. R2007 measures
every interval of a (source, destination) pair over the whole file, so each night (~14 h) and each
weekend became an interval and its jitter rose far above 0.6. WIN-MAL-1 keeps R2007's measured
method (>= 30 intervals, mean 30 s - 1 h, CV < 0.6, public IPv4 destinations) and changes one
thing, stated: a silence longer than the method's own longest period (1 h) is not an interval and
is left out of the statistics. It is keyed on (host, process, destination) - Sysmon names the
process, a firewall cannot. R2007 itself is unchanged: its numbers were measured on firewall data
and PAN-MAL-1 / CP-MAL-1 run its SQL.

**A feed refuses documentation addresses.** `intel._clean_ip` drops anything `ipaddress` calls
private, and Python counts 192.0.2.0/24, 198.51.100.0/24 and 203.0.113.0/24 as private - so the
generator's C2 address can never be on a feed. The check writes a test feed with a public
address instead (`185.220.101.5`, and the quarter's brute forcer `45.155.205.99`).

**WIN-INTEL-2 reads the attempts**, not raw rows: the same failed sign-in as a 4625 and a 4771 is
one match, and the address of a DC's `::ffff:` form is compared as IPv4. A lone 4776 (no address)
cannot match. No blocked twin: Windows logs no refused connection.

Measured: W4 found by WIN-MAL-1 (every beacon connection), W2 by WIN-INTEL-2 with the test feed;
OneDrive's two-hourly sync (a timer over an hour) not flagged. With 5a-5c every incident W1-W9
of the quarter is found by at least one rule and no plain or look-alike event is flagged; W3
(low-and-slow) only by WIN-BRUTE-3's chance overlap with W9. Parity: no entry moved.

Check: `tests/check_windows_rules.py`.
