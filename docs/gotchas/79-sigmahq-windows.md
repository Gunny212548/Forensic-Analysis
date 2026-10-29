# Gotcha #79

**79. SigmaHQ on Windows: converted at build, high / critical suggest, the rest mark; five traps**

Story 6 (`specs/sigma_windows.md`, Q124-Q133, 2026-10-29). SigmaHQ's Windows rules run beside ours on
`win_events`: the image's `sigma` build stage converts a pinned commit (`05d1031f`) with pySigma
2.0.1 through ADR-006's DuckDB dialect into `/opt/sigma/windows_rules.json`; the app runs the SQL and
never imports pySigma. High / critical rules of `rules` and `rules-emerging-threats` are product rules
(`rules_sigma.py`, `SIGMA-<uuid>`) and go through review, the AI and the graph like ours; every other
rule, and the six twins of WIN-MAL-2 / WIN-HOST-3, marks events (`sigma_marks`) on the timeline.

Measured: SigmaHQ's own regression samples 439 of 445 exact through the pipeline (the six named in
`tests/check_sigma.py`); Kinnaree 80 SigmaHQ suggestions, 0 events on a look-alike, K1 / K6 / K8 /
K9 / K11 found (the in-house rules miss them); Mekong no look-alike flagged; this PC's own logs 0
suggestions (no Security log, no Sysmon - that noise is not measured).

The traps, each paid for once:

1. **pySigma's Windows / Sysmon pipelines pin `pysigma<2`.** Unusable with ADR-006's pin; the
   logsource map (category -> Sysmon event id, service -> channel) is the Sigma taxonomy appendix
   v2.1.0's own table, in `tools/sigma_build.py`.
2. **A boolean is `'true' OR 1` to the SQLite backend**; against a VARCHAR item DuckDB casts every
   value to an integer and fails on `'false'`. The dialect compares `'1'` as text. Found by the spike;
   the build's self-test now includes the form.
3. **Rule ids are not unique on 8 hex** (nor 12): SigmaHQ authors copy UUIDs. The rid is the whole UUID.
4. **A field called `Data` is win_events' `data` column** to DuckDB (identifiers ignore case): a rule's
   condition runs inside a CTE holding only its own fields, host and account under `__fa_` names.
5. **One SigmaHQ rule's error must not fail the case** - `apply_rules(failures=)` lists it and goes on;
   one of ours still fails it.

Also: the dev compose mounts `./app` over `/app/app`, so the bundle lives in `/opt/sigma`; a dev image
not rebuilt after this change has no bundle and SigmaHQ reports "not run". Fetching SigmaHQ by git hash
in BuildKit failed mid-transfer after 9 minutes - the archive is fetched with `ADD --checksum`. The rule
card fetches one rule at a time: the rule list grew by 1,492. Parity keeps SigmaHQ's counts in a
`sigma` section of each entry; `flagged` there is ours (`flagged_by_origin`).
