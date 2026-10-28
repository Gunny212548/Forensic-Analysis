# Projects: one customer, many investigations - design (draft)

Status: **Approved 2026-10-28** - Q110-Q113 answered (a) each, below.
Requirement (the user, 2026-10-28): "ลูกค้า 1 รายอาจมีการใช้งาน Forensic หลายครั้งจะจัดการยังไง" -
a customer may engage us for forensics many times. The user chose all four parts: status and a
required project (P1), a dashboard per project (P2), managing projects (P3), and analysis across
the cases of a project (P4).

## Today (since 2026-10-15, CLAUDE.md *Projects*)

- Customer -> project -> case. A project is chosen (or created by name) on the Upload page and is
  **optional**; a case without one is "No project". Stored in the customer's store,
  `projects/<pj-id>.json`: id, name, created_at, created_by, and the investigation's question
  (hash-chained `projects/<pj-id>.log.jsonl`, gotcha #58).
- A case copies `project_id` and `project_name` onto its manifest. A merge keeps the project only
  if every source is in it. The project page `#/customers/<co>/projects/<pj>` lists its cases.
- Not there: a status, a dashboard of its own, a filter on Findings, renaming, moving a case,
  deleting a project, and any analysis wider than one case - Attack events, Attack timeline,
  Attack path and the graph are all per case (case_flow.py, `db.build_graph`).

## The idea

**A project is one investigation** - the unit an engagement is opened, worked and closed in.
Cases are its evidence; a customer's projects are its history of engagements.

## P1 - status, and every new case in a project

- A project has `status` **Open** / **Closed**, `created_at` (its opening), `closed_at`,
  `closed_by`; every change is a line in the project's own hash-chained log (as its question).
- **Close** (Q110): only when every suggestion in its cases is decided - the report gate a case
  already has (gotcha #73), so a closed investigation has no open question left. **Reopen**
  at any time, recorded.
- **Upload requires a project**: the Upload page's project select becomes required (an existing
  Open project, or "+ Add new project..."). Uploading into a Closed project (Q111).
- Cases from before, in no project (Q112).
- The customer profile lists projects Open first, then Closed, with opened / closed dates, cases,
  suggestions not decided.

## P2 - a dashboard per project

- The Overview scoped to one customer gains a project select beside the customer select:
  `#/dashboard/<co>/<pj>`, `GET /api/overview?company_id=&project_id=`. Every section then counts
  that project's cases only (the same code path - `list_manifests` filtered by project).
- The customer's own Overview (no project chosen) shows, above its sections, its projects as
  rows - Open first: status, opened, cases, not decided, highest not decided - as the All
  customers view shows customers (By customer). One pattern at both levels.
- Findings gains a project filter (`project_id=`), and its rows already name their project.

## P3 - managing projects

- **Rename**: the name lives on the project and is copied onto each case's manifest
  (`project_name`); a rename rewrites both, recorded in the project's log.
- **Move a case** to another project of the same customer (or out of "No project"): the
  manifest's `project_id` / `project_name` change; a line goes to the case's chain of custody
  ("moved from project A to B, by, when") and to both projects' logs. Never across customers
  (gotcha #40: a case cannot leave its customer's store). Refused while the case is busy.
- **Delete a project** with every case in it, as a customer is deleted (specs/customer_delete.md):
  confirmation from the server, the project's name typed back, refused while a case is busy;
  the record - each case's evidence digest and FD ids, and the project's log - goes to the
  customer's own hash-chained `deleted/log.jsonl` (the customer remains, so its log does too).
- Who (Q113).

## P4 - analysis across the cases of a project

The analyst still decides suggestions per case (Attack events stays a step of the case: the
evidence and its events are per case). What the project adds is the picture of the whole
investigation, read-only, built from those decisions:

- **Attack timeline of the project**: every confirmed group (accepted or modified) of every case,
  in the order its first event happened, each naming its case and source file; the ATT&CK
  tactic chevrons over all of them - the case page's Attack timeline, project-wide.
- **Attack path / graph of the project**: the per-case graphs (`db.build_graph`) joined - a host
  or an account is the **same node in every case of one customer** (one network), so an attacker
  who appears in the firewall export and in the Windows logs is one node with both cases' edges;
  each edge names its case. Edges of suggestions not decided are drawn as they are on the case
  page until story 7 (case_flow_design), and the page says so.
- **Gate**: the project's report gate is every case's - the project can close (P1) once nothing
  in it is undecided.
- On the project page, as three steps: Cases (with each case's flow state) -> Attack timeline ->
  Attack path. Each case's own six steps stay as they are.
- Correlation rules still run per case (a rule needs one DuckDB); evidence that must be
  correlated by rules is uploaded as one zip or merged (`/merge`) - unchanged.

## Order

P1 -> P2 -> P3 -> P4, each its own branch, tests and deploy. P1 first because P2-P4 assume every
case is in a project.

## Questions

- **Q110 - when can a project close?** (a) only when every suggestion in its cases is decided
  (recommended: the report gate, so "Closed" means finished); (b) at any time, the analyst's call.
- **Q111 - uploading into a Closed project**: (a) refused - reopen it first (recommended: a closed
  investigation stays as it was reported); (b) allowed, and the project reopens by itself.
- **Q112 - cases in no project today**: (a) stay "No project", listed on the customer page, and
  can be moved into a project (P3) (recommended); (b) each customer's are put in a project
  "Unfiled" automatically.
- **Q113 - who**: (a) close / reopen / rename / move / delete a project: manager and admin;
  creating one on upload stays as now (recommended - as customers, `customer:manage`, and
  deletion as `customer:delete`); (b) analysts may close and move too.

## Answers (the user, 2026-10-28)

- Q110 (a): a project closes only when every suggestion in its cases is decided.
- Q111 (a): uploading into a Closed project is refused - reopen it first.
- Q112 (a): cases in no project stay "No project", listed on the customer page, movable (P3).
- Q113 (a): close / reopen / rename / move / delete - manager and admin.
