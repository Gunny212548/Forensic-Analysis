# Gotcha #70

**70. The blind test: a sprayer's own computer account, and a beacon the whole fleet makes**

Story 5e of `specs/windows_rules.md` (2026-10-26, Q98 yes, Q99 a). The user wrote a blind Windows
quarter (`D:\logtest\blind-windows`, `gen_windows_blind.py` seed 20260401: Kinnaree Textiles, K1-K15,
an answer key "not to be shown to whoever writes or tunes the rules") and uploaded it to 8091. Scored
once with the rules unchanged: 59,143 rows flagged, **43,523 of them not attacks**.

**Read before re-testing: the kinnaree quarter is no longer blind.** Its answer key was read to score
it, and the two fixes below came from that reading. A result on it measures the fixes; a fair test of
the rule set needs a quarter whose key was not read (another seed).

**WIN-AUTH-1 and the sprayer's machine account (W-D10).** The spray branch flags a success for *any*
account from a source WIN-BRUTE-2 decided a sprayer. The sprayer was WEB01 (after K1's web shell), and
`web01$` signs in from WEB01's address all day: 231 rows, the finding itself saying "likely the owner".
The spray branch now leaves out computer accounts (`...$`, Microsoft 4769), as WIN-BRUTE-3 does; the
same-account branch is unchanged.

**WIN-MAL-1 and a fleet's timer (W-D11).** 40,725 rows (69% of everything flagged) were ESET's
`ekrn.exe` checking in with one address on a timer - on 40 of the 43 hosts with Sysmon network events.
The analytics ask for beacons to *rare* destinations (AN0076 "rare domains", AN0761 "rare external
hosts") and none defines rare. A (process, destination) beaconing on more than half of those hosts is
now left out and named on the line record (`lines["WIN-MAL-1"]`, method `fleet-wide`) - "more than
half" is an internal method, stated: the evidence has no legitimate beacons to draw a D16 line over.
The risk is said on the rule: one implant on more than half the machines, calling one address, is on
the line record and not flagged. The real beacons were one host each (K7, K15, Mekong's W4).

Measured on the blind quarter after the fixes: flagged 59,143 -> 18,187; not-attack rows 43,523 ->
**2,567** - the deployment look-alikes the answer key labels false positives (a backup helper and PDQ
pushed through ADMIN$, 2,560 rows on WIN-LAT-2 / -4) and 7 admin RDP rows from the jump host. Every
incident found as before: K2 636/640, K3 100/108, K7 5,408/5,416, K13 9,582/9,654, K14 18/21, K15
83/101; partial K4, K5, K10, K12; missed K1 (web shell), K6 (WMI), K8 (DCSync, 4662), K9 (pass-the-hash
for an account with no Kerberos in the evidence - WIN-LAT-3's stated blind spot), K11 (FILE01's
Security log cleared). Suggestions 567 -> 526: K13's internet sprayers are one each.

Mekong unchanged; parity: samples 11, `Logtest` 67 exact, `D:/logtest`'s 59 exact (its 3 new files are
the blind folder's `ground_truth.csv`, `incidents.csv` and `COLLECTION.txt` - not logs, not added to the
baseline; its `.xml` evidence is not a parity suffix).

The case page's line table names the methods it now has: CUSUM over the site, fleet-wide timers.

Check: `tests/check_windows_rules.py` (story 5e capture).
