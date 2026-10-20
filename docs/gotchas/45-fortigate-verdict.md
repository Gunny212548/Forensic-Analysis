# Gotcha #45

**45. A FortiGate session that ended normally is an allowed session
(2026-10-14, IAI-32).** `decode._forti_verdict`: the traffic-log `action`
values of an allowed session - `accept`, and the session-end values
`close`, `timeout`, `client-rst`, `server-rst`, plus `start` - become
`allow` (FortiOS Log Message Reference, traffic log fields). Before, only
`accept` did, so the allow-based rules (R3000, R3001, R2004, R2007 where it
filters) did not see the rest. Other values keep their spelling.

Real files: `D:/Trafficlog/` - a FortiGate-200F's traffic logs (`tlog`
only, 46 files, 45.8 GB; the zips hold more of the same plus network-
diagram PDFs). The header carries `device_id=`, not `devid=`.
- 23 MB file (25,876 rows): allow 5,955 -> 8,027; R2004 251 -> 512, every
  other rule equal; plain / .gz / .zip identical; 0 lines unrecognised.
- 931 MB file (1,003,143 rows): R2004 9,477 -> 14,700, all else equal;
  41 s = 22.6 MB/s on the Python path (gotcha #18's ~21 MB/s), so a 10 GB
  file is ~7-8 minutes.
- No FortiGate file is in the corpus, so parity (67 + Check Point +
  gen_usecase + samples) is unchanged by construction.
