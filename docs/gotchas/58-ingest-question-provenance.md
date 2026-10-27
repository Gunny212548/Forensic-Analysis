# Gotcha #58

**58. Ingest records the question, each file's provenance and the method; a declared time
applies only on re-process (story 3, 2026-10-21).** Design: `specs/story3_ingest.md`.

- **Question** (`investigation.py`): on the *project* - one investigation, D6 - with every
  change in its own hash-chained `projects/<pj>.log.jsonl`; a case with no project keeps it
  on its manifest and logs changes to its custody log. `investigation.get(manifest)` hides
  which. Not a gate here: D8 makes it required before the *report* (story 8).
- **Provenance** (`provenance.py`): `manifest["provenance"]` maps *evidence item* -> fields,
  where an item is the uploaded file's name or a zip member's name. Every change is a custody
  line `provenance` with `{field: [old, new]}`; the manifest holds only the current values.
- **Declared time** (D10): a zone (`+HH:MM` only, Q35 - no tzdata in the image, gotcha #21)
  moves the events whose `ts_raw` states **no** offset by `7 h - zone`; a clock offset moves
  every event of the item. `pipeline._apply_declared_time` does it in SQL after ingest and
  **before** intel / rules / profiles, so every window sees corrected times. "States an
  offset" is `db.TZ_MARKER_PATTERN` in both SQL and Python - the same test as the
  `timezone-unconfirmed` flag, now `timezone-declared` where a zone was applied.
  `raw_events` is rebuilt from `raw/` every run, so clearing the settings and re-processing
  gives back the first run's times exactly (`check_ingest.py` asserts it).
- **Saving a zone does nothing to the times until the analyst re-processes** - the Ingest
  step says so and offers the button; `manifest["time_applied"]` records what the last run
  applied and `provenance.reprocess_needed()` compares the two. No automatic re-process
  (memory: keep UX simple).
- **Re-process** `POST /api/cases/{id}/reprocess`: refused while queued / processing; review
  decisions survive because they are keyed by finding (#19). It is also how old cases get
  behaviour profiles (#57) and a method record.
- **Method** (`repro.py`): every `processed` custody line carries `method` - SHA-256 of the
  app's `.py` files (the image has no `.git`, so a code digest, not a commit), of the rule set
  (id + SQL + level), the profiles used, each intel feed file's SHA-256, DuckDB version, the
  time settings applied. Two runs of the same code give the same record.
- **Duplicates** (D11): an upload whose SHA-256 matches an earlier case **of the same
  customer** gets `duplicate_of` and a warning; other customers' stores are never searched
  (#40). Not counting it twice on the timeline is story 4's.
- The dev store needs the intel feeds copied in, or R3003-R3006 drift in parity (as #56 says).
- Parity unchanged with no provenance declared: 67 corpus files + the Check Point benchmark
  exact on 2026-10-21. `nightfall-firewall-nested.jsonl.gz` from `gen_usecase.py` reports a
  new md5 on every generation - its gzip header carries a timestamp; pre-existing, not a drift.

**2026-10-27: the screen keeps only the source time.** The user found the Provenance section
too complex and cluttered and chose to keep only the time zone and clock offset, as a "Source time"
line per item. Source system, export method, exported by / at and note left the screen, and so did
the "provenance not recorded" warning. `PUT /provenance` still accepts every field and values
already recorded stay on the manifest and in the custody log. ACPO 5.10.3 (provenance) is no longer
cited by the Ingest step: nothing on it asks how the evidence came to be there. Lost with it: the
export method that would say a filtered export silenced a rule (gotcha #9) - ask the customer instead.
