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

## P2 - a dashboard per project

- `#/dashboard/<co>/<pj>`, `GET /api/overview?company_id=&project_id=` and
  `GET /api/findings?company_id=&project_id=`: the same code paths with the manifests filtered by
  project, so a project's Overview counts exactly what its cases hold. A `project_id` without its
  customer, or of another customer, is 404.
- The customer's own Overview (no project chosen) opens with **Projects** - one row each, Open
  first, opened / closed, cases, not decided of all, the worst not decided, and a "No project"
  line for cases from before - the By customer pattern one level down; the customer's sections
  follow it, all projects together. A project select sits beside the customer select.
- `overview.build` gets the project rows from `projects.summary`, imported inside the function:
  `projects` imports `overview` (for `_case_facts`), so a module-level import would be circular.
- Findings has a project select once a customer is chosen; changing the customer clears it.

## P3 - managing projects

- **Rename** (`PUT /api/companies/{co}/projects/{pj}`, manager / admin): the name is on the
  project *and* copied onto every case's manifest (`project_name`), so both are rewritten; a
  name another project of the customer has is refused (409) - upload finds a project by name.
- **Move a case** (`POST /api/companies/{co}/projects/{pj}/cases {"case_id"}`, manager / admin):
  into an Open project of the same customer only; refused out of a Closed project, into one, and
  while the case is queued or processing. A `moved` line goes on the case's chain of custody (from,
  to, names) and `case_moved_out` / `case_moved_in` into both projects' logs. On the customer
  page, each case's Project cell is the select. A case from before a project was required is
  moved into one this way (Q112). `custody.record` takes the case id itself - passing `case_id`
  again in its details raised a TypeError on the first run of the check.
- **Delete a project** (`GET .../deletion`, `DELETE /api/companies/{co}/projects/{pj}`,
  `customer:delete`): every case goes as a deleted case does (`case_delete.delete`, a
  `case_deleted` line each in the customer's `deleted/log.jsonl`), then one `project_deleted`
  line carrying the project's own log and question, then the project file and its log. Refused,
  with nothing deleted, while a case is busy - `case_delete.busy()` is now the one rule for
  customer and project deletion (it was `customer_delete._busy`). An empty project creates the
  `deleted/` folder itself.

## P4 - the whole investigation

- On the project page, under its cases: **Attack timeline of the project**
  (`GET .../projects/{pj}/timeline`) - every confirmed group (accepted or modified) of every case,
  in the order its first event happened, each naming its case and file, with the ATT&CK stages
  over all of them and the count of suggestions not decided yet - and **Attack path of the
  project** (`GET .../projects/{pj}/graph`) - each case's `db.build_graph` joined: the same two
  entities in several cases are one edge listing each case and the union of their rules, a host
  or an account is one node (one customer, one network), the most severe 24 edges kept; the risk
  ranking summed over the cases, as the Overview sums it per customer. Read-only for every role:
  decisions stay in each case's Attack events. Correlation rules still run per case.
- **Cases are named by id, not file name**, in the joined graph: the first check gave one case
  for two because both were `t.log` - and real exports share names too (`log_30_.csv`).
- The case page's timeline display moved to `components/AttackTimelineView.jsx`, shared by the
  case's Attack timeline step and the project's (`showCase` adds the Case column).
- Like the case page, the project graph still draws every suggestion, not only confirmed ones,
  until story 7 of case_flow_design; its subtitle says so.
