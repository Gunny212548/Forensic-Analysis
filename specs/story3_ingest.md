# Story 3 - Ingest finished: question, provenance, declared time, reproducibility

Status: **approved 2026-10-21** - Q33-Q36 all as proposed (question on the project; SigmaHQ
its own story; zone as `+HH:MM` only; provenance on the Ingest step only). The user: "ทำลำดับแรกให้เสร็จก่อน
คือขั้นตอนการ Ingest". Builds what `case_flow_design.md` revision 6, step 1 lists as missing
(1.1 question, 1.4 provenance, 1.9 reproducibility record, D10 declared time zone, D11
duplicate evidence), on top of what Ingest already does (1.2-1.3, 1.5-1.7, all built).
Sub-process 1.8 (SigmaHQ rules) is **not** in this story - Q34.

## Requirement (restated)

| # | When / what | Then | Standard |
|---|---|---|---|
| I1 | An investigation is opened, or any time after | The analyst can record the question it answers, its time window and known leads (addresses, accounts, hosts); every change is a hash-chained line with who and when | ACPO 5.5 tasking; SP 800-86 §3.3, §6.4.1 (event of interest); Diamond Model §8.2 "define the question" (method) |
| I2 | No question recorded | The Ingest step says so as a **warning**, never a block (D8: required before the *report* is approved - story 8 enforces it) | D8 |
| I3 | Any time after upload | The analyst can record each evidence item's provenance: source system, how it was exported (method, query / filter), exported by, exported at, the source's time zone, a known clock offset, a note. Every field optional; each change is a custody line with old and new value | RFC 3227 §4.1; ACPO 5.10.3; SP 800-86 §3.1.2 |
| I4 | A provenance field is empty | Listed as a warning on the Ingest step (and, in story 8, in the report's limitations) | D9 |
| I5 | A source time zone is declared | On re-process, every event whose **source text states no offset** is converted from that zone into GMT+7 instead of being taken as GMT+7; events whose text states an offset are untouched; those events stop being `timezone-unconfirmed` and are marked `timezone-declared` | RFC 3227 §2 ("indicate whether UTC or local time is used"); D10 |
| I6 | A clock offset is declared | On re-process, every event of that item is shifted by it, whatever its text says; the event keeps `ts_raw` verbatim | SP 800-92 fn 24 ("add or subtract times ... out-of-sync sources"); RFC 3227 §3.2; Casey 2002 §2.3 (method) |
| I7 | Zone or offset changed, or cleared | The change is recorded, the case is re-processed (the analyst confirms first), and clearing it returns exactly to the previous times - reversible | D10 |
| I8 | Any case, any time | The analyst can re-process it from the preserved original; review decisions survive (they are keyed by finding, gotcha #19) | ACPO P3 (a third party can achieve the same result) |
| I9 | Every processing run | The custody "processed" line carries a reproducibility record: digest of the application code, digest of the rule set (SQL + levels), the log source profile(s) used, each intel feed file with its SHA-256, DuckDB version, and the declared zone / offset applied | RFC 3227 §3.1 (transparent and reproducible); SP 800-86 §3.1.2 ("information about each tool used"); ACPO P3 |
| I10 | An upload's SHA-256 equals an earlier case of the same customer | It is accepted as its own evidence item (receiving it twice is a custody fact), with a warning naming the earlier case(s); never a case of another customer | D11; gotcha #40 |
| I11 | Ingest step | Done when processed with custody intact (as today); the warnings of I2, I4, I10 and any `timezone-unconfirmed` source are listed under it | revision 6 step 1 |

## Design

### Where things live

- **Question and leads** (Q33): on the **project** - one investigation (D6) - in
  `customers/<id>/projects/<pj>.json`, with every change appended to a hash-chained
  `projects/<pj>.log.jsonl` (`hashchain.py`, as the review and custody logs). A case with no
  project is a one-item investigation (D6): its question goes on its manifest and its changes
  on its custody log. One helper, `investigation.py`, hides which of the two it is.
- **Provenance**: on the manifest (`provenance: {...}`, current values) and as custody lines
  `provenance` with `{field: [old, new]}` - the custody log is already hash-chained and per
  evidence item, which is exactly what a provenance change is about.
- **Reproducibility record**: inside the existing custody `processed` line, as `method: {...}`.
  Nothing new to store.

### Declared time (I5-I7)

In `pipeline.process_case`, after ingest and before the rules (so every rule, window and
profile sees the corrected times), one SQL statement per item:

```sql
UPDATE raw_events SET ts = ts
  + CASE WHEN NOT regexp_matches(ts_raw, <the _TZ_MARKER pattern>) THEN <7h - declared zone> ELSE 0 END
  - <declared clock offset>
WHERE row_id BETWEEN <item's first> AND <item's last> AND ts IS NOT NULL
```

`raw_events` is derived and rebuilt on every run (`db.drop` first), so this changes no
evidence; `ts_raw` and `raw/` are untouched. The `_TZ_MARKER` test is the one `db._flags`
already uses for `timezone-unconfirmed`, so "states an offset" means the same everywhere.
A zip case has one provenance per member (`members[i].provenance`), applied to that member's
`row_id` range. A zone is given as a UTC offset (`+00:00`, `-05:00`); named zones with DST are
not accepted here (the Python side has no tzdata, gotcha #21) - Q35.

### Re-process (I8)

`POST /api/cases/{id}/reprocess` - authz action `reprocess`, custody line `reprocess
requested` with the reason (zone changed, offset changed, analyst request), then
`jobs.submit` as an upload does. Refused (409) while the case is queued or processing.
Decisions survive because they are keyed by `rid|srcip|username`; a finding that no longer
appears after a re-process keeps its decisions in the log, and the case page lists it as
"no longer raised" rather than dropping it silently. Also the way to give the 15 cases on
8091 their behaviour profiles.

### Reproducibility record (I9)

`repro.py`: SHA-256 over `app/**/*.py` (sorted relative paths + bytes) - the image has no
`.git`, so a code digest, computed once at start; SHA-256 over every rule's id + SQL + level;
the mapping profile id(s) from the manifest; `intel/` feed files used, name + SHA-256;
`duckdb.__version__`; the zone / offset applied per item. Two runs of the same code on the
same file give the same record - that is the test.

### Duplicate evidence (I10)

In `routers/upload.py`, after the digest is known: the customer's manifests with the same
`evidence.sha256` (`storage.list_manifests(company_id)`) -> `duplicate_of: [{case_id,
original_filename, project_name}]` on the manifest and on the custody `acquired` line. The
timeline's "not counted twice" half of D11 belongs to story 4 (the timeline across items).

### API

| Route | What |
|---|---|
| `GET / PUT /api/companies/{cid}/projects/{pj}/question` | question, window, leads; PUT appends to the project log |
| `PUT /api/cases/{id}/question` | the same for a case with no project (409 if it has one) |
| `PUT /api/cases/{id}/provenance` (`member=` for a zip) | provenance fields; response says whether a re-process is needed |
| `POST /api/cases/{id}/reprocess` | as above |
| `GET /api/cases/{id}/flow` | Ingest step gains `warnings: [...]` |

### UI (Ingest step of `CaseFlow.jsx`)

Top to bottom, all on the Ingest step, nothing on the Upload page (Q36): **Question** (text,
window, leads - edit in place, shows who changed it last); **Evidence and provenance** - per
item the digest and custody (as today) and a provenance form; saving a zone or offset shows
"re-process to apply" with the button, nothing re-processes on its own (memory: no automatic
switching); **Method** - the reproducibility record of the last run; **Warnings** - the I11
list; then the events table as today.

### Files

`services/investigation.py` (new), `services/repro.py` (new), `storage.py` (project question),
`pipeline.py` (declared time, method on custody), `routers/cases.py`, `routers/companies.py`,
`routers/upload.py`, `case_flow.py` (warnings), `authz.py` (`reprocess`), `mcp_server.py`
(`get_case` serves question, provenance, method - read-only as ever); frontend `api.js`,
`CaseFlow.jsx`, `components/Question.jsx`, `components/Provenance.jsx`; docs gotcha #58,
`docs/STANDARDS.md` Ingest row, CLAUDE.md one line.

### Tests

- `tests/check_ingest.py` (new, TestClient, throwaway store): question on project and on a
  project-less case, each change chained; provenance save -> custody line with old / new, chain
  still verifies; a declared `+00:00` zone moves only the rows without an offset by +7 h and
  leaves offset-bearing rows alone; a clock offset moves every row; clearing both restores the
  first run's `ts` exactly; re-process keeps decisions, refuses while processing; method record
  identical on two runs; duplicate named within a customer and **never** across customers.
- `check_parity.py` on the corpus (pipeline changed: with no provenance nothing may move),
  `check_customer_isolation.py`, `check_case_flow.py`, `check_workflow.py`, `check_mcp.py`,
  `check_authz.py`, `npm run build`, the page checked in the dev container (8092).

### Risks

- Re-processing changes counts (windowed rules see new times) - intended, recorded in custody.
- A declared zone on a source that mixes offset and no-offset lines converts only the
  no-offset ones - correct per I5, and the warning list says how many of each.
- 10 GB files: the UPDATE is one pass over the item's rows; measured before merge.

## Questions

- **Q33 - where the question lives.** Proposed: on the project (D6), on the case only when
  there is no project. Or on every case, moved to the project in story 2.
- **Q34 - SigmaHQ (1.8) not in this story.** It waits on ADR-006 Q10-Q13. Proposed: its own
  story after this one.
- **Q35 - zone as an offset only.** Proposed: `+HH:MM` only in this story (no DST, no tzdata).
  A source in a DST zone needs tzdata in the image - a later story if one turns up.
- **Q36 - provenance only on the Ingest step**, not the Upload form, so the upload stays one
  short form (D9 allows "at upload or later"). Or also on the Upload form.
