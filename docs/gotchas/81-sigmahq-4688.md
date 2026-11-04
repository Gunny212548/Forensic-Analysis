# Gotcha #81

**81. SigmaHQ's process creation rules on Security 4688: SigmaHQ's own map, unknown is NULL, Sysmon first**

Story 6d (`docs/specs/sigma_windows.md`, Q134-Q137, 2026-11-02). The Sigma taxonomy maps `process_creation`
to Sysmon 1 only, so until 6d a host that audits process creation (4688) and runs no Sysmon - the usual
customer export - had none of SigmaHQ's 1,425 process creation rules. They now also read 4688
(`sigma.py`: `MAP_4688`, `scope_4688`, the temp table `sigma_4688`).

Measured (prototype, then the pipeline): Kinnaree with its Sysmon logs left out - 32 SigmaHQ
suggestions from 4688, every one on an attack event (K1, K4, K5, K10, K12, K15); Mekong the same way
- W4, W7, W10, nothing on a plain or look-alike event (`tests/check_windows_rules.py`); this PC's
Security - 25 4688s, no command line, nothing. With Sysmon present every quarter is unchanged: its
4688s are left to Sysmon.

The traps:

1. **The map is SigmaHQ's, not the taxonomy's.** The taxonomy never names 4688; SigmaHQ's own
   `tests/thor.yml` (the THOR / SPARK config, in the pinned commit) maps `Image` <- `NewProcessName`,
   `ParentImage` <- `ParentProcessName`. `CommandLine` is the same item name. Nothing else is mapped
   or translated: `MandatoryLabel` is a SID, not Sysmon's `IntegrityLevel` word; ids are hex.
2. **An empty command line is unknown, not empty.** 4688's `CommandLine` is empty unless a policy
   is on (Microsoft's page). Read as `''`, every `NOT ... CommandLine LIKE` filter passes and the
   rule fires; `nullif(..., '')` makes it unknown.
3. **Unknown fields are safe only in three-valued logic.** With the fields 4688 lacks as NULL, a
   condition of `=`, `ILIKE`, `regexp_matches`, AND / OR / NOT is true only when it would be true
   whatever their values (DuckDB's truth tables) - it can miss, never invent. The dialect writes a
   Sigma filter as `NOT COALESCE(filter, FALSE)`, where an unknown filter field lets the event
   through: such a rule judges only a 4688 that holds every field it uses. "Uncommon Svchost Parent
   Process" would mark every svchost under svchost on a host whose command line is not audited
   (`tests/check_windows.py` shows it). 1,220 rules run on 4688; 205 need a field 4688 never has and
   are listed on the case (`sigma.security_4688.not_run`).
4. **One process, one event.** Where Sysmon 1 covers the host at that time (its first to its last
   Sysmon 1 in the case), the 4688 is not read. Reading both doubled the rows, and 945 of Kinnaree's
   7,641 pairs - every SYSTEM process - name a different account (4688 the computer account
   `APP01$`, Sysmon `NT AUTHORITY\SYSTEM`), which would open a second suggestion for one process.
5. **The rows are a temp table built once per connection** (`prepare_4688`), before the first rule
   that reads them - `rules_sigma.PREPARE` for the suggestions, `apply_marks` for the marks. A test
   that changes `win_events` and runs the rules again on the same connection sees the old rows.
