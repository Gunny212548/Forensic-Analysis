# Gotcha #52

**52. The case page is six steps, and each step's state comes from the server
(2026-10-20, IAI-89; branch `IAI-89-case-flow-shell`, not merged).**

- **Branches.** `sprint/4` (worktree `D:/forensic-analyzer-s4`) merges Sprint 3's two
  sibling branches, `IAI-fd-detail` and `arch/split-routers`. The only conflict was
  `app/routers/cases.py`, a whole-file conflict because ADR-4 had turned its CRLF into LF;
  resolved by taking split-routers' file and re-applying fd-detail's 3-line change
  (finding events open on an integrity-refused case). IAI-89 and IAI-92 are stacked on it.
- **`app/services/case_flow.py`** - `STEPS` (id, title, standards) and
  `build(case_id, manifest)`: per step `state` (done / active / blocked / not_started /
  optional), `remaining`, `total`, `reason`; `recommended` = the first step not done or
  optional. Computed from manifest, custody, review log, registry and analysis cache only;
  it writes nothing. `GET /api/cases/{id}/flow`.
- **`GET /api/cases/{id}/graph`** - `db.build_graph` + `db.risk_scores` without the AI, so
  the graph no longer waits for an analysis.
- **`custody.problem()`** - the Overview's "evidence problem" test, shared with the
  Ingest step.
- **Frontend** - `pages/CaseFlow.jsx` (replaces `CaseView.jsx`), `components/StepBar.jsx`
  (one Next step button, never switches the page by itself), `pages/Cases.jsx`; menu Work:
  Overview, Upload, Cases, Findings / Manage: Customers, Settings. `#/reports/<id>[/<tab>]`,
  `#/timeline/<id>`, `#/attack-graph/<id>` and `#/result/...` redirect to
  `#/case/<id>[/<step>]` with `location.replace`. `ReviewPanel` takes `onChanged` so the
  step bar re-counts after a decision.
- **Test** - `tests/check_case_flow.py` (33 checks): the step order, every step citing a
  standard marked read in `docs/standards/SOURCES.md` (parsed from its "## Read" table),
  states from a fresh case to resolved, a rejected finding waiting in Respond, an evidence
  problem blocking Ingest, `/graph` without the AI.
- **Verified** on the host (no container, Docker was down): check_case_flow, check_workflow,
  check_customer_isolation, check_authz, check_jobs, check_rule_meta; in a browser at
  `127.0.0.1:8097` - Cases page, Triage counts updating, Investigate graph, every redirect,
  no console errors. Not yet: container run, check_mcp, phone width.
- **Superseded in part by #54**: the steps are to become Ingest -> Timeline -> Attack
  events -> Attack timeline -> Attack path -> Report (no Respond, no separate Analyse).
