# Gotcha #78

**78. Public Windows data: WIN-HOST-2 never read the access; the dev image could not read .evtx**

2026-10-29, at the user's request ("หา Log จาก internet มาเทส"): data the rules were not built on, kept
outside the repo in `D:/logtest/internet/` - `evtx-attack-samples/` (sbousseaden's EVTX-ATTACK-SAMPLES,
GPL-3.0, 278 .evtx) and `otrf/` (OTRF Security-Datasets, MIT, the 91 Windows host datasets of lateral
movement, credential access and defense evasion; the network ones are pcaps). Each file run through the
pipeline on its own and listed with the rules it fired.

**What fired, all of it right but one rule:** WIN-LAT-2 on Empire PsExec, Empire smbexec, Covenant
SharpSC create and an ATSVC remote task; WIN-BRUTE-2 + WIN-AUTH-1 on a Kerberos spray (4771); WIN-BRUTE-2
+ WIN-HOST-1 on PurpleSharp's AD playbook; WIN-MAL-2 on Atomic Red Team's Defender detections;
WIN-HOST-2 on procdump, Dumpert / AndrewSpecial, powerdump and the RDP Task Manager dump. Most EVTX
samples are one event or a short capture and fire nothing - single events wait for SigmaHQ (W-D1).

**WIN-HOST-2 (W-D17, Q123).** It also fired on 6 OTRF datasets that are no dump - `svchost.exe`, the
Prefetch writer, opening lsass.exe with GrantedAccess `0x3000` and then writing a `.pf`. The rule joined
the access to a file write and never read the access. A dump needs PROCESS_VM_READ (Microsoft
MiniDumpWriteDump: "PROCESS_QUERY_INFORMATION and PROCESS_VM_READ"; ReadProcessMemory needs VM_READ,
0x0010); AN1030's AccessMask "can be scoped down". Now `GrantedAccess & 0x10`. The 6 datasets fire
nothing, every dump is kept, the quarters (Lotus, Mekong, Kinnaree) are unchanged - Mekong's W7 is
0x1fffff and its Defender look-alike (0x1010) writes no file. OTRF's PowerShell-remoting `wsmprovhost.exe`
(0x1410 / 0x1f3fff) is still flagged: it can read the memory.

**The dev image had no `evtx` library.** `docker compose -p forensic-dev ... up -d` without `--build`
reused an image older than W2, so on 8092 every .evtx was identified and read as one row with
`reader_errors: cannot import name 'PyEvtxParser'`. The 8091 image had it. Rebuild the dev image after
any `requirements.txt` change - CLAUDE.md says so, and nothing warns when it was not done. Parity on the
dev container never noticed: no .evtx was under `D:/logtest` at the time.

**Do not run a script from a folder beside a data folder named like a library.** The first run put its
script in `/tmp/inet/` next to `/tmp/inet/evtx/` (the samples): Python put the script's folder on
`sys.path` and imported the data folder as the `evtx` package - the same error as above, for a different
reason. Scripts and downloaded data live in separate folders.

**The baseline's EVTX-ATTACK-SAMPLES entries were taken at W2** (2026-10-20), before any Windows rule,
and the folder was gone by story 5a - so 5a-5f were never checked against them. Re-run 2026-10-29:
exactly 5 files drift, each a rule firing as designed (the list above minus PsExec / smbexec, which are
OTRF zips and no parity suffix); `--update` run on `D:/logtest/internet` only (0 added, 5 updated, 387
untouched), so the blind folder's answer-key files never enter the baseline.

**43 of the 91 OTRF datasets are not analysed**: a flat JSON (`TimeCreated`, `SourceName`, `Hostname`,
`Message`, the event's items at the top level) with no documented reader - kept as evidence, nothing
guessed (gotcha #53). Supporting it needs that export's documentation first.
