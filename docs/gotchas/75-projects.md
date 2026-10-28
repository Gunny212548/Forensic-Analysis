# Gotcha #75

**75. A project is one investigation of one customer (2026-10-28, the user: "ลูกค้า 1 ราย
อาจมีการใช้งาน Forensic หลายครั้งจะจัดการยังไง"; design `specs/projects.md`, Q110-Q113 answered
(a) each).** Built in four stories, P1-P4; this file grows with each.

## P1 - status, and every new case in a project

- **Required in the API, not only on the page.** `POST /api/upload` refuses an upload naming no
  project (400) - and asks *before* a new customer named on the same form is created, or a
  refused upload would leave the customer behind. Every script that uploads names one now:
  `check_parity.py` sends project "Parity check" beside customer "Parity check", `check_authz`
  defaults to an "Existing project" the analyst may upload into (an analyst may not create one),
  `bench_llm`, `check_mcp`, `check_case_flow`, `check_workflow`, `check_ingest`,
  `check_customer_isolation` likewise. A case from before stays in "No project" (Q112);
  `check_ingest` makes one by clearing a case's project to keep testing a case-scoped question.
- **Open / Closed.** A project without `status` (written before 2026-10-28) is Open
  (`storage.project_status`). Close is refused (409) while a case of it is not processed
  (queued, processing, failed) or a suggestion of it is not decided - the report gate (Q110,
  gotcha #73); the project list says what blocks it (`close_blocker`). Reopen at any time.
  Manager and admin, `customer:manage` (Q113). Each change is a line in the project's own
  hash-chained log beside its question's history.
- **One lock for the project file.** The question (investigation.py) and the status
  (projects.py) both read, change and write the project JSON; they share
  `storage.PROJECT_LOCK`, or a question saved during a close would drop one of the two.
- **A Closed project takes nothing new** (Q111): upload by id or by name, and merge, are 409.
- **Merge across projects is refused** (it used to give a case in no project, which P1 no longer
  allows); `check_customer_isolation` asserts the 409 now.
- `GET /api/companies/{id}/projects` returns `projects.summary` - status, opened / closed, cases,
  suggestions and those not decided, the worst not decided, `can_close` - Open first, then the
  newest. It reads cached case facts (`overview._case_facts`).
