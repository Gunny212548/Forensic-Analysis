# Deleting a case (Admin) - design (draft)

Status: **Draft 2026-10-22.** Answered the same day: Q72 (a) delete at once; Q73 no reason;
Q74 keep only the report; Q75 Admin and Manager (and Admin may now do everything); Q76 a PDF.
Open: Q77 (how the PDF is made).
**Built 2026-10-22 without the report** (the user: delete first, the report later): `DELETE
/api/cases/{id}`, `case_delete.py`, the header's *Delete case* with the case id typed back.
Requirement (the user, 2026-10-22): "Role Admin สามารถลบ Case ได้" - an administrator can
delete a case.

## Today

- Nothing in the app deletes a case (CLAUDE.md, *Scale notes*); `tools/prune_cases.py` removes
  byte-identical duplicates from a shell, dry run by default.
- IAI-14 (Q56) made Admin "accounts + read only". This adds one action to Admin: `DELETE_CASE`.
- A case lives in its customer's store (gotcha #40): `cases/` manifest, `db/` DuckDB, `raw/` the
  evidence as received, `analysis/` AI output, `review/` analyst decisions (hash-chained),
  `custody/` chain of custody (hash-chained), `jobs/`. Its FD ids are lines in the customer's
  hash-chained registry `findings/ids.jsonl`; a merged case has its own copy of the raw data,
  so deleting a source never breaks a merge.

## Proposed

1. `DELETE /api/cases/{id}` - `authz.require(DELETE_CASE)`, Admin only; a second confirmation in
   the UI (type the case id) and a **reason** (Q73).
2. Removes the case's files from every sub-directory above (`storage.case_dir`), and nothing of
   any other case or customer (customer isolation, gotcha #40).
3. **The deletion itself is recorded and survives the case**: one line in a hash-chained log
   *outside* the case - who, when, why, the case id, file name, customer, the evidence's
   SHA-256 from acquisition, rows / findings, and the FD ids it held. The custody log goes with
   the case, so this line is the chain of custody's last entry (its disposal). The FD-id
   registry is append-only: an id is never re-used; a `deleted` line is appended for each.
4. Refused while the case is processing (a job is running on it).
5. Every route that lists cases, the Overview, Findings and the MCP server simply no longer see
   it; a link to it answers 404.

## Questions

- **Q72 - delete for good, or hide first?** (a) delete the files at once (recommended - the
  record of point 3 remains); (b) move to a "deleted" state, restorable for N days, then purge.
- **Q73 - a reason, from a list?** Proposed: required - duplicate upload / uploaded in error /
  test data / retention period ended / other (written).
- **Q74 - a case with analyst work on it** (review decisions, findings in the workflow not
  Resolved): (a) refuse until they are Resolved; (b) allow, the confirmation saying what is lost
  (recommended - the deletion record lists them).
- **Q75 - Admin only**, or Manager too? The requirement names Admin.

## Answers (the user, 2026-10-22)

- Q72: (a) - the files go at once; the deletion record stays.
- Q73: no reason asked.
- Q74: "ให้เก็บแต่ตัว Report ไว้" - keep only the report; everything else of the case goes.
- Q75: Admin **and Manager** may delete.

- **Q76 - what "the report" is.** No report feature exists yet (IAI-55); what the app has is the
  case's Reports tab (the AI narrative, if one was run) and the exports (STIX, VERIS, ATT&CK
  layer). Proposed: a **snapshot taken at deletion** - case facts (file, customer, project,
  SHA-256, period, rows), every finding with its FD id, status, analyst decision and
  confidence, the AI narrative if one exists, and who deleted it when - kept read-only under the
  customer as "Deleted cases".

- **Q76 answered 2026-10-22: a PDF.** At deletion the server writes the case's report as a PDF and
  keeps it; everything else of the case goes.

## The PDF (proposed)

Contents, in English like the UI: the case (id, file name, customer, project, uploader, upload
time), the evidence (SHA-256 at acquisition, size, log source, the period each file covers),
counts (rows, flagged), every finding (FD id, rule and its label, entity, events, severity,
workflow status, analyst decision, confidence), the AI narrative if one was run, the custody
log's entries, and the deletion (who, when). Kept at `customers/<id>/deleted/<case_id>.pdf`; its
SHA-256 goes on the deletion record (hash-chained `customers/<id>/deleted/log.jsonl`), so a
changed PDF shows. Listed on the customer page as *Deleted cases*, downloadable by every role.

- **Q77 - how the PDF is made.** The container has no browser (the measurement PDF is printed by
  Chrome on the host). Proposed: **fpdf2** (pure Python, pinned in requirements.txt) with **Noto
  Sans and Noto Sans Thai** TTF fonts (SIL OFL) copied into the image at build - Thai customer
  names and file names must print. Needs the user's approval to download the package and the
  two font files.
