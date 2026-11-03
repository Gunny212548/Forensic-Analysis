# Forensic report (step 6 Report) - design draft

Status: **every question answered (Q-R1..Q-R10), 2026-11-03 - waiting for the user's approval
of the whole design.** Nothing is built; the skeleton exists only as a preview outside the repo.
Requirement: the user's report template (a PDF supplied 2026-11-03, kept outside the repo and
**not to be copied into it or used for anything but its layout** - the user's instruction).
This spec names its parts by structure only; no text, name or figure of it is reproduced.
Builds on `specs/case_flow_design.md` revision 6 step 6 and `docs/standards/forensic-process.md`
§3.5. Replaces the "final written report is not built yet (IAI-72, IAI-73)" line of the Report step.

## What the template is

A Thai document on the provider's letterhead, in two parts:

| Part | Pages | Content | Where it comes from |
|---|---|---|---|
| Cover | 1 | provider letterhead, report title + customer name, version, date (Buddhist era), prepared by | fixed + project |
| About the document | ก | confidentiality notice (fixed text); **change log** table (date, editor, version, details); three people tables: author, reviewer / approver, project coordinator (name + position) | fixed + report record |
| Foreword | ข | fixed text (the sample's is a pen-test proposal's, highlighted as a placeholder) | fixed - forensic text needed |
| Contents | ค | headings with page numbers | generated |
| Body | 1.. | numbered sections; page header: system, customer, version, classification "internal use only", the customer's logo; footer: provider address | per report |

Front matter is numbered ก ข ค, the body 1 2 3. The sample body has only *1. Executive Summary*
(for executives, legal and insurers, no IT background; incident, companies, period, what this
version changes, how long the attacker was in, what happened in plain words, the root cause,
what is new) and a pen-test section 3 - so the body sections below are proposed, not copied.

## The .docx (supplied 2026-11-03, read for structure only)

The Word original is the provider's pen-test **proposal** document with the forensic cover
and an Executive Summary pasted in - most of its body is proposal material. Measured with a
stdlib zip/XML reader (no copy kept outside the scratch folder):

| Part | What is there | For the draft |
|---|---|---|
| Section 1 - cover | title page; first-page header = letterhead (logo, contact), first-page footer; default / even headers carry a **"ฉบับร่าง" (draft) watermark** | keep; the watermark suits R-D0 - the analyst removes it for the final |
| Section 2 - front matter, page numbers in Thai letters from ก | about the document, the change-log and three people tables, foreword (placeholder text highlighted yellow), contents | keep; fill the tables; foreword per Q-R5; yellow highlight = "to be written" - kept as the draft's convention for text the analyst must write |
| Contents | a real `TOC` field with `PAGEREF`s, but its cached entries and page numbers are stale | keep the field, set `updateFields` so Word rebuilds it on open |
| Section 3 (body), numbers from 1 | header with page number, the system's name, the customer's name, version, classification and **another customer's logo**, all typed in | page number, project and customer filled per project; the version / classification line removed from both headers (the user, 2026-11-03); the other customer's logo removed (Q-R4) |
| Body content | Executive Summary - **every paragraph styled Heading 1**; then pen-test standards and tools, process, schedule, personnel with CVs, project management, site references, company profile, certificate scans (personal data) | dropped; the body is generated (sections below). Body text in Normal, only section titles in Heading 1 / 2, or the contents lists every paragraph |
| Linked pictures | the heading bars sit inside three `INCLUDEPICTURE` fields linking to pictures on other organisations' websites; the cover's default footer carries another customer's logo beside the provider's | **found by the user in the first skeleton (2026-11-03)**: with `updateFields` on, Word downloaded the linked pictures and showed them in place of the bars. Every `INCLUDEPICTURE` is unlinked (the embedded picture stays), the foreign logo removed; the build fails if a field or relationship still points outside the file |
| Unused | a first-page header with English placeholders (`<level>`, `<TOPIC>`) on a section without a first page | dropped |
| Styles | Thai fonts named (TH SarabunPSK, Angsana / Cordia New, Tahoma) | kept by name; Word renders them on the analyst's PC - nothing to install on the server |

**Template preparation (one-time, per provider template).** A skeleton is made from the user's
file: sections 1-3 and their headers / footers kept, the body emptied, placeholders put where
the project's values go (`{{ customer }}`, `{{ system }}`, `{{ version }}`, `{{ date_be }}`,
the change-log and people rows) and the body's sections laid out in the skeleton itself, each
with its tags - table rows as `{%tr for ... %}` loops, lists as `{%p for ... %}`, the attack
path as an image tag (`docxtpl` tags, which a person can also type in Word). Laid out in the
skeleton rather than generated as one block, so the provider restyles a section in Word.
Proposal material (Q-R9: the user, 2026-11-03 - "ตัดส่วนเสนอโครงการออกทั้งหมด") and every
picture only it used are removed from the package, as are the document properties' names and
pictures' alt text (one named a person's desktop path). **Measured on the first build:** a
child element written out of ECMA-376's order (`w:b` before `w:rFonts`, `w:highlight` after
`w:cs`) makes Word stop on a repair dialog - a hidden Word left waiting; the build checks every
`w:rPr` / `w:pPr` order before it writes. Afterwards the provider can change letterhead,
fonts or wording in Word without a code change, as long as the tags stay. A check refuses a
skeleton missing a required tag, naming it.

## Decisions proposed

- **R-D0 - the system writes a draft; the analyst finishes it** (the user, 2026-11-03: "Report
  ที่ออกมานี้ต้องเป็นฉบับร่างเพื่อให้ Analyst แก้ไขต่อได้ ต้องเป็นไฟล์ที่แก้ได้"). What the
  system produces is always a draft in an editable file; the final report is the analyst's,
  made outside the system. Every heading below says "draft" where it said "issue".
- **R-D1 - one report per project** (D6: a project is one investigation). The sample covers
  several companies over months in one document, which is a project here.
- **R-D2 - a draft only when the gate is open**: every suggestion of every case in the project
  decided (gotcha #10, the user 2026-10-28). No draft before that - an undecided suggestion is
  not proven, and a draft gets forwarded. Confirmed by the user 2026-11-03 (Q-R8: "ไม่ได้
  ต้องตัดสินครบก่อน"). The project's question is **not** part of the gate (the user, 2026-11-03,
  after the first test on 8091: "ไม่จำเป็นใส่"): a draft without one shows "-" where it goes.
- **R-D3 - the draft is a Word file (.docx)** - editable, as R-D0 requires. Built from the
  user's own .docx template when there is one, so the letterhead, styles, header, footer and
  page numbering are exactly theirs; otherwise the layout is rebuilt in `python-docx` from the
  PDF's structure. Text the system writes is ordinary Word text (no locked fields, no content
  controls), tables are Word tables, the attack path an inline picture - every part can be
  edited, moved or deleted. The analyst edits, signs and makes the PDF in Word (rev 6:
  "Analyst edits, approves, signs"). One pinned dependency (`docxtpl` on `python-docx`). A PDF
  from the server is not made - it is not editable and would need LibreOffice in the image.
- **R-D4 - every draft is recorded**: version, SHA-256, who, when, the gate state and the
  reproducibility record go on the project's hash-chained log; the file is kept in the
  customer's store (`customers/<id>/reports/<pj>/<version>-draft.docx`). A new draft is a new
  version, never an overwrite (RFC 3227 §4; ACPO principle 3). **The analyst's final is not
  the system's file**: it **may** be uploaded back to the project, never required (Q-R7, the
  user 2026-11-03: "อัปโหลดได้แต่ไม่บังคับ"). Accepted as .docx or .pdf (the signed PDF is the
  usual final), by anyone who may work on the case (analyst and up), also while the project
  is Closed - it is a record of what was issued, not new evidence. Kept beside the drafts
  (`<version>-final.<ext>`), never read or analysed; its SHA-256, who, when and the draft
  version it says it came from (chosen on upload) go on the project's hash-chained log. A
  second final for the same version is kept too, never replacing the first. The Report step
  lists drafts and finals with their SHA-256 and downloads; a project with no final uploaded
  is not flagged.
- **R-D5 - the change log table is pre-filled with the drafts made so far**: date, account
  name, version, and the "details" line the analyst types when asking for the draft (required
  from version 1.1). The analyst adds the final's own line in Word.
- **R-D6 - people tables**: author = the account making the draft; reviewer / approver and
  coordinator = chosen from the accounts (manager / admin for the approver) on the draft form,
  or left blank for the analyst to fill in Word; position typed there and remembered per
  account. No new role.
- **R-D7 - fact and opinion apart** (ACPO 6.5.4): every factual line cites its FD id / event;
  text the AI drafted is marked "AI draft - reviewed by <analyst>" until edited; the analyst's
  own conclusions are under headings that say they are opinion.
- **R-D9 - the only picture the system inserts is the attack path** (the user, 2026-11-03: "รูป
  ลูกค้าผมไปใส่เอง ผมให้คุณใส่แค่ Attack path"). The provider's letterhead, logo and heading
  bars are already in the skeleton; the customer's logo is put in by the analyst in Word (the
  other customer's logo the template carried is removed, no tag left). Pictures may be JPEG,
  PNG or SVG. The attack path is drawn by React (`AttackGraph.jsx`), not on the server, so
  when the analyst asks for a draft the page sends the graph it shows as SVG + a PNG drawn on a
  canvas - no rasteriser on the server. It goes in as SVG with the PNG as fallback, the way
  Word stores one: Word 2016+ / 365 shows the SVG, older Word and LibreOffice the PNG
  (`python-docx` inserts only raster pictures, so the `asvg:svgBlip` extension is written by
  us). Its SHA-256 goes on the draft's log line. To check when built: the canvas has no web
  font unless the SVG embeds it - Plex must be inlined or the labels fall back to a system font.
- **R-D10 - the AI drafts the Executive Summary** (Q-R3, the user 2026-11-03: "AI ร่าง"). In
  Thai, for executives, legal and insurers with no IT background (the template's audience),
  from the **confirmed groups only** - the same input as the attack timeline and path, never
  an undecided or rejected suggestion (gotcha #10). The local model (`OLLAMA_MODEL`), decoded
  inside a JSON schema (a list of short paragraphs, each with the FD ids it rests on) and
  grounding-checked the way the narrative is (gotcha #37): every FD id cited exists and is
  confirmed, every time, address, host and account named appears in the cited groups. It
  states what the analyst confirmed - what happened, when, from where to where, how long -
  and what the evidence does not show; it never decides or grades (gotcha #72), and it says
  nothing about cause unless a confirmed group shows it. In the draft every paragraph is
  highlighted yellow under a line naming the model and saying the analyst must edit it
  (R-D7); the analyst removes both. A failed or refused draft leaves the section's yellow
  "to be written" line and says why - the draft is still made. A paragraph the check refuses
  is shown in the draft as a yellow note with its reason and its text, so the analyst can
  correct it rather than rewrite it.
  **Measured 2026-11-03** (`tests/bench_report_summary.py`, qwen3.5:9b, the bruteforce-pivot
  project in the live store: 13 confirmed groups, 3 edges): ~12 s and 453 completion tokens a
  draft (22 s cold), runs byte-identical. Plain, readable Thai. Found and fixed on the way:
  (1) the model turned a SigmaHQ rule's Persistence tag into a motive ("to keep access") -
  tactics are no longer handed over; (2) a correct opening paragraph citing only F1 was
  refused for naming the end time - the whole span is a fact `S` of its own and its ends are
  always accepted, a minute either side for rounding; (3) "10.20.0.40" read as the times
  10:20 / 00:40 - addresses are removed before times are checked; (4) the model wrote
  "adm.hu" for adm.hd - dotted account names are now checked, and that paragraph is refused.
  **Not caught by any check:** one kept paragraph ends with an inference ("which confirms the
  attacker had full control of the system") - gotcha #13 says prompt wording does not fix
  this; the yellow highlight and the analyst's edit are what cover it. Final: 3 of 4
  paragraphs kept, 1 refused with its reason.
- **R-D11 - the skeleton is uploaded on the Settings page** (Q-R2, the user 2026-11-03), by an
  admin, never committed to git - it carries the provider's letterhead and the repo is pushed.
  Kept in the shared part of `DATA_DIR` (`report/`, beside `intel/`: provider configuration,
  no customer's data), every version kept as `<sha256>.docx` with a hash-chained
  `report/log.jsonl` line (who, when, SHA-256, file name). The newest is used; each draft's
  log line names the skeleton's SHA-256 it was built from (ACPO P3 - the draft can be
  rebuilt). An upload is refused, naming what is wrong, when: it is not a .docx (zip with
  `word/document.xml`), over 20 MB, a required tag is missing (the list is shown on the page),
  a tag does not parse, it holds an `INCLUDEPICTURE` / `INCLUDETEXT` / `LINK` field or an
  external relationship, or a test render with sample data fails. The page shows the current
  skeleton (who / when / SHA-256), a download of it to edit in Word, and the tag list. No
  skeleton uploaded = the Report step says so and no draft can be made. The first skeleton is
  the one built from the user's template (shown 2026-11-03); the build script is not shipped -
  later changes are made in Word and uploaded.
- **R-D8 - Thai text, English technical terms** (as the template); event times GMT+7
  `YYYY-MM-DD HH:MM:SS`, document dates in Buddhist era as the template writes them.

## Body sections (approved by the user, 2026-11-03)

Each section names its source in the system and the standard it answers (all marked read in
`docs/standards/SOURCES.md`).

| # | Section (Thai heading in the file) | Filled from | Standard |
|---|---|---|---|
| 1 | Executive Summary | AI draft in Thai from the confirmed groups (R-D10), then a table of figures: the question, first / last confirmed event, dwell time, confirmed of suggested, tactics reached | SP 800-86 §3.4 (audience); AI 600-1 (confabulation) |
| 2 | Scope and question | project question; customer; cases and evidence items; period each covers and its silent days (`period.py`) | SP 800-86 §3.1 |
| 3 | Standards and method | the standards of `docs/STANDARDS.md` that the steps used; the tool: app commit, log source profiles, in-house rule set, SigmaHQ commit, intel feed hashes, AI model - the reproducibility record | ACPO P3; SP 800-86 §3 |
| 4 | Evidence and chain of custody | per item: file name, size, SHA-256 at acquisition, last verification, identified as, rows read / not read | RFC 3227 §4; ACPO P1 |
| 5 | Attack timeline | confirmed groups in time order by ATT&CK tactic, gaps with their duration (`projects.timeline`) | SP 800-86 §3.3, §6.4.3 |
| 6 | Attack path | the graph as an image (the same SVG, rasterised) + a table of edges: from, to, technique, account, events (`projects.graph`) | SP 800-86 §6.4.4 |
| 7 | Findings | per confirmed group: FD id, rule (in-house or SigmaHQ with author), level, entity, first / last event, event count, Admiralty grade, the analyst's decision and note; rejected groups listed with their reason | ACPO 6.5.4; Sigma 2.1.0 |
| 8 | Limitations | files not analysed and why; rules n/a per product; coverage gaps; inferred times (`year-inferred`, `timezone-unconfirmed`); conversions (zone, profile mapping); silent periods; missing provenance | ACPO 6.3, 6.5.3 |
| 9 | Recommendations | analyst-written, with the AI narrative's list as a starting draft; a "logging improvements" sub-list seeded from Limitations | SP 800-86 §3.4, §6.5 |
| App. ก | Evidence register | every item, full SHA-256, custody log lines | RFC 3227 §4 |
| App. ข | Rules that ran | id, title, level, source (in-house / SigmaHQ commit), techniques | Sigma 2.1.0 |
| App. ค | Decision log | every decision: time, account, group, decision, reason | review log, gotcha #31 |

Not in this version: alternative hypotheses (step 4's notes are not built - `case_flow.py`
"gaps and hypotheses come in story 6"); Casey levels (Q31 open). Section 8 says so.

## Questions for the user

- ~~Q-R1 - the .docx original~~ - answered: supplied 2026-11-03 (section above).
- ~~Q-R9~~ - answered 2026-11-03: every proposal section dropped.
- ~~Q-R10~~ - answered 2026-11-03: a script makes the skeleton, shown to the user first
  (built in the session's scratch folder, not in the repo, until Q-R2 is decided).
- ~~Q-R7~~ - answered 2026-11-03: the final may be uploaded, not required (R-D4).
- ~~Q-R8~~ - answered 2026-11-03: no - every suggestion decided first (R-D2 confirmed).
- ~~Q-R2~~ - answered 2026-11-03: uploaded on the Settings page (R-D11).
- ~~Q-R3~~ - answered 2026-11-03: the AI drafts it (R-D10).
- ~~Q-R4~~ - answered 2026-11-03: the analyst puts the customer's logo in by hand (R-D9).
- **Q-R5 - foreword text.** The sample's is a pen-test proposal's. Supply the forensic one, or
  approve a draft.
- ~~Q-R6~~ - answered 2026-11-03: the nine sections and three appendices as proposed (as laid
  out in the skeleton shown to the user).

## Done when (once approved)

- An admin uploads the skeleton on Settings; a non-admin is refused (403); each refusal case
  of R-D11 is refused with its reason; the previous version stays and is still downloadable.
- Make a draft on a project whose gate is open; refused with the reason when it is not.
- Upload a final (.docx / .pdf) against a draft version, also on a Closed project; any other
  type refused; its SHA-256 on the project log; a second final keeps the first; a project
  without a final works exactly as one with.
- Every paragraph, table and picture of the draft can be edited and deleted in Word (and
  LibreOffice Writer); nothing is protected.
- The attack path appears in the draft; its SVG is sharp in Word 365 and its PNG fallback
  shows in LibreOffice; its labels are in the UI's font. No other picture is added.
- Nothing in the draft is fetched when it is opened: no `INCLUDEPICTURE` / `INCLUDETEXT` /
  `LINK` field, no external relationship; and no picture or name of anyone but the provider
  and the project's own customer (checked on every build, listing what it found).
- The file opens in Word with the template's letterhead, header, footer, ก-ค / 1.. numbering
  and a contents table Word updates on open.
- Every figure in the file equals the same figure on the project page (say a figure once, and
  the same everywhere).
- Version, SHA-256 and reproducibility record on the project log, chain verified.
- `tests/check_report.py`: gate refusals, every section filled from a seeded project, the
  hash-chain line, a second draft makes 1.1 and keeps 1.0, no other customer's data in the file.
