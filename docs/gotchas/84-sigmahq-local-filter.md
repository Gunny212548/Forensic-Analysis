# Gotcha #84

**84. SigmaHQ's noise on a real workstation, and a filter of ours on a SigmaHQ rule**

Noise round 2 and story 6e (`docs/specs/sigma_windows.md`, Q138, 2026-11-10). Until then SigmaHQ's
Sysmon rules - 2,253 of the 2,878 - had only been run on synthetic quarters and public attack samples.

Measured: this PC's Sysmon log (Sysmon 15.22, SwiftOnSecurity configuration), 410,251 events over
eight days, one workstation, a developer running AI coding agents. 17 SigmaHQ rules fired, 17
suggestions, 12,375 events, none an attack; every match was the rule as written, none the dialect's.

1. **One filter gap was 93% of it.** *System File Execution Location Anomaly* (e4a6b256) leaves out
   PowerShell 7 under `Program Files\PowerShell\7` and the Store's `Microsoft.PowerShellPreview`
   package, not the Store's release package `C:\Program Files\WindowsApps\Microsoft.PowerShell_...` -
   11,479 events. SigmaHQ's master of the same day had the same text: a new pin fixes nothing, so
   read master before proposing one.
2. **A filter of ours is kept apart, and narrow** (`sigma.LOCAL_FILTERS`, S-D14). SigmaHQ's bundle
   is not edited; the filter is appended in `sigma.condition`, named on the rule's card and on the
   case's SigmaHQ record. Only where the rule's own filter states the intent and misses a case
   measured benign - each one the user's decision. Ours leaves out the package directory under
   `Program Files\WindowsApps` only: the per-user alias under `AppData\Local\Microsoft\WindowsApps`
   is user-writable, and SigmaHQ's Preview filter allowing it is no reason to copy it.
3. **The rest is what the rules look for.** An agent's `bash -c` / `pwsh -EncodedCommand` line holding
   a whole script (curl with `-o` and `&`, base64, emoji and `→` in text, `irm ... | iex`), Discord's
   clock sync to `time.cloudflare.com`, Logitech's updater as SYSTEM with `/minidump/` in a URL: 16
   rules, 897 events (re-run with the filter: 16 suggestions, 897 events, marks unchanged). The event alone does not tell them from an attack, so they stay suggestions
   for the analyst. Lowering a loud rule to a mark was refused: one customer's noise set on every
   other (D10-D16).
4. **Tooling traps.** Windows Defender refuses to let one of SigmaHQ's regression `.json` files be
   read, which breaks `docker cp` of `regression_data` half way - `check_sigma.py` needs only the
   `.evtx` and `info.yml`, so copy with `tar --exclude='*.json'`. A Python heredoc that writes a
   Windows path into a source file turns `\7` into a BEL character and drops other backslashes
   (gotcha #51's scripted-edit traps again): use the Edit tool for anything holding a backslash.
5. **What it cost.** 320 s for the 1 GB log (one run, 410,251 events); marks on 9.5% of the events.
