# Story 1 - the case page follows the revised flow

Status: **approved and built** (2026-10-20; Q22 and Q23 as proposed). Branch `case-flow-steps` off `main`.
Source of the requirement: `specs/case_flow_design.md` revisions 2-3 (built since only as
design) and the user, 2026-10-20: "why does Triage still have an assignee dropdown, and
why is Respond still there?"

## Requirement

The case page (`#/case/<id>/<step>`, IAI-89) still shows revision 1's six steps - Ingest,
Triage, Investigate, **Respond**, Analyse, Report - and Triage embeds the finding status
workflow with its **assignee dropdown** (`ReviewPanel` -> `Lifecycle`). Revisions 2 and 3
decided otherwise:

- no assignee dropdown - the owner is the signed-in account (rev 2);
- Respond removed: no Contained / Resolved tracking, no MTTC (rev 3);
- the separate Analyse step goes - the AI suggests and drafts the report (rev 2);
- the steps are Ingest -> Timeline -> Attack events -> Attack timeline -> Attack path /
  graph -> Report (rev 3).

Story 1 makes the case page say that, **with the parts that exist today**. Each step that
is not built yet says so and names the story that builds it - nothing is faked.

## The six steps, as story 1 builds them

| Step (id) | Phase (SP 800-86) | Shows in story 1 | Done when | Built fully in |
|---|---|---|---|---|
| Ingest (`ingest`) | Collection | as today: identification, coverage, evidence and custody, events table (layer A event type, layer C context) | processed, custody intact | story 3 adds question, provenance, reproducibility |
| Timeline (`timeline`) | Examination | the case's events **in time order** (the same table, ordered by event time, then row) | never blocks - a view | story 4: across files, pivot, silent periods |
| Attack events (`attack-events`) | Analysis | the review list (confirm = accept / modify, reject) per finding group, **without** status or assignee | no finding group left undecided | story 5: exclude / add single events, AI suggestions |
| Attack timeline (`attack-timeline`) | Analysis | the **confirmed** groups (accepted / modified) in time order of their first event | - (not built) | story 6: gaps, assumptions, hypotheses |
| Attack path (`attack-path`) | Analysis | the attack graph and risk ranking as today (still from all findings) | - | story 7: confirmed events only, Attack Flow export |
| Report (`report`) | Reporting | the gate, VERIS, STIX / Navigator exports, and the **AI narrative** (moved from Analyse) | gate open | story 8: the written report |

Old step addresses redirect: `triage` -> `attack-events`, `investigate` -> `attack-path`,
`respond` -> `attack-events`, `analyse` -> `report`; the older `#/reports/...` links follow
the same table (App.jsx).

## What is taken out, and what is not

Taken out of the **case page and the finding page**: the Respond step, the Investigate
step's status / assignee table, the MTTC line, and `Lifecycle` (assignee dropdown and
status buttons) from `ReviewPanel`. Removing `Lifecycle` from `ReviewPanel` removes it from
both pages, because both use it.

**Not** in story 1 (Q22): the Findings page's status filters and assignee column, the
Overview's MTTC KPI and "unassigned" urgent list, the Customers page's open / closed count,
and the backend (`lifecycle.py`, its route, FD ids) - they need a new meaning of "open"
first. Nothing is deleted: the lifecycle log stays readable, as an audit record.

## Changes

| File | Change |
|---|---|
| `app/services/case_flow.py` | `STEPS` becomes the six steps above, each citing read standards (SP 800-86 phases; SP 800-92 §3.2 and IR 8354 §4.7.1 for the timeline; FIRST 5.2 and CSF RS.MA-02 for attack events; SP 800-86 §6.4.3 for the attack timeline; SP 800-86 §3.3 and ATT&CK for the path; SP 800-86 Reporting, ACPO 6.3-6.5, STIX, Navigator, VERIS, AI 600-1 for the report). States from the same records as today; Respond and Investigate logic removed. |
| `app/services/db.py`, `routers/cases.py` | `list_raw(..., order="time")` for the Timeline step: `ORDER BY ts NULLS LAST, row_id` |
| `frontend/src/pages/CaseFlow.jsx` | `StepBody` for the six ids; Analyse's narrative moves into Report; Respond / TrackedFindings removed |
| `frontend/src/components/ReviewPanel.jsx` | `Lifecycle` no longer rendered |
| `frontend/src/components/EventsTable.jsx` | an `order` prop |
| `frontend/src/App.jsx` | the step redirects above |
| `tests/check_case_flow.py` | the new step ids and states; old step addresses still resolve |

## Questions

- **Q22 - Respond outside the case page.** Story 1 removes it from the case and finding
  pages only; the Findings page, Overview and Customers keep their status-based figures
  until a story that defines "open" without Resolved. Proposed: yes - and that story
  next, with "open = the case still has finding groups no one has decided".
- **Q23 - the Attack timeline step in story 1.** Show the confirmed groups in time order
  now (small, real), or only a "built in story 6" note. Proposed: the list.
