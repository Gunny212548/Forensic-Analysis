---
name: case-api
description: Every /api route of the forensic analyzer and what it returns, the case manifest's keys, and login / sessions / roles (RBAC) / Sign in with Google. Load before adding or changing a route or router (app/routers/), reading or writing a manifest key, or touching auth.py, authz.py, users.py or the Google sign-in.
---

# Case API, manifest and login

Moved out of `CLAUDE.md` on 2026-11-04, word for word; `CLAUDE.md` keeps the one-line rules and the gotcha index. **Before changing code a gotcha names, read `docs/gotchas/NN-*.md`.** If this file and the code disagree, the code is the fact - fix this file (doc-keeper).

## Routes

The routers are `app/routers/*.py`; the session middleware is in `app/main.py`. Check this list against them when it matters.

```
POST /api/auth/login | logout, GET /me        session cookie (see *Login* below);
GET  /api/auth/google/start | callback       Sign in with Google (gotcha #82), open
                                             without a session, answer with redirects;
GET  /api/auth/config                        login + config + health are the
                                             only routes open without a session
GET  /api/upload/check?size=                 FR-2.2 pre-flight: 413/507 before
                                             a byte is sent (gotcha #25)
GET/POST /api/companies                      customers (FR-2.1 requires one)
GET  /api/companies/summary                  Customers page: open/closed cases,
                                             highest open severity, last
                                             activity (overview.customers())
GET  /api/companies/{id}/projects            the customer's projects with status and
                                             what each holds, Open first (projects.py)
POST .../projects/{pj}/close | reopen        manager / admin; close only when every
                                             case is processed and every suggestion
                                             decided (gotcha #75)
PUT  .../projects/{pj}                       rename (on the project and every case)
POST .../projects/{pj}/cases {case_id}       move a case into this project
GET  .../projects/{pj}/deletion, DELETE ...  delete the project with its cases
GET  .../projects/{pj}/timeline | graph      the investigation across its cases:
                                             confirmed groups in time order; the
                                             cases' graphs and risk joined (P4);
                                             both empty, with `undecided`, while any
                                             suggestion of its cases is not decided
GET  .../projects/{pj}/report                the report gate, drafts and finals with
                                             their SHA-256 (docs/specs/forensic_report.md)
POST .../projects/{pj}/report/draft          a Word draft (case:analyze): only when every
                                             suggestion is decided (the question is not
                                             required); the AI's Thai summary, the attack
                                             path PNG + SVG the page sends (gotcha #83)
POST .../projects/{pj}/report/final          the analyst's final back (.docx / .pdf),
                                             never required, also on a Closed project
GET  .../projects/{pj}/report/files/{name}   download a draft or a final
GET  /api/reports                            every draft and final of every project,
                                             newest first - the Reports menu page
GET/POST /api/settings/report-skeleton[/{sha}] admin: the Word skeleton drafts are filled
                                             into; refused if it links outside the file
GET  /api/cases[?company_id=] | /{id}        the case list (manifests) | one manifest
GET  /api/cases/{id}/flow                    the six steps and each one's state,
                                             computed on the server (gotcha #52)
POST /api/cases/merge                        several line-log cases into one new case
                                             (services/ingest/merge.py; refused across
                                             customers or projects)
GET  /api/cases/{id}/analysis                poll point for the narrative job
GET  /api/cases/{id}/profiles/{kind}[/{value}] behaviour profiles, layer C facts
                                             (gotcha #57)
GET/POST /api/users, PATCH|DELETE /{email},  admin: accounts (routers/users.py),
POST /{email}/password, GET /audit           hash-chained audit (IAI-14)
GET  /api/cases/{id}/events?limit=&offset=   paginated SQL
GET  /api/cases/{id}/findings                collapsed findings + computed
                                             confidence + review status + FD id +
                                             related findings (gotcha #49) + the
                                             AI's advice + ATT&CK tactics + detection
                                             area (the area list in its order too)
DELETE /api/cases/{id}                       admin / manager: every file of the
                                             case, recorded in the customer's
                                             deleted/log.jsonl (docs/specs/case_delete.md)
GET  /api/companies/{id}/deletion            admin / manager: what deleting the
DELETE /api/companies/{id}                   customer removes, then the customer with
                                             every case, recorded in the shared
                                             deleted/customers.jsonl (gotcha #74)
GET  /api/cases/{id}/findings/events?key=    the events behind one finding, each
                                             with its source file (gotcha #49)
GET  /api/findings[?company_id=[&project_id=]] the Findings page: workflow findings
                                             across cases, counts, open_count;
                                             decision= / undecided_count (the badge,
                                             #73); status=open = not Resolved (#51)
POST /api/cases/{id}/review                  one analyst decision (appended)
GET  /api/cases/{id}/review-log              full decision history
GET  /api/cases/{id}/custody                 evidence digest + chain of custody,
                                             hash chain checked on read
POST /api/cases/{id}/verify                  re-hash the raw file now, log it
GET  /api/cases/{id}/ingest                  question, provenance, method, warnings
PUT  /api/cases/{id}/question | provenance   the investigation's question; one
                                             item's provenance (gotcha #58)
POST /api/cases/{id}/reprocess               run the pipeline again from raw/
POST /api/cases/{id}/ai-review               "Review again": send the suggestions with no AI
                                             advice yet to the model (gotcha #71)
POST /api/cases/{id}/lifecycle               one status change / assignment on a
                                             tracked finding (lifecycle.py)
GET  /api/cases/{id}/stix                    STIX 2.1 bundle download; ready only
GET  /api/cases/{id}/veris                   VERIS 1.4 record download; 409 if no
                                             high/critical finding
GET  /api/cases/{id}/attack-layer            ATT&CK Navigator layer (format 4.5)
                                             download; 409 unless ready
GET  /api/rules[/{rid}]                      rule metadata: Sigma fields + ADS
                                             documentation (rule_meta.py)
GET  /api/cases/{id}/graph                   the Attack path step: db.build_graph +
                                             risk_scores of the confirmed groups;
                                             empty, with `undecided`, until every
                                             suggestion is decided (gotcha #10);
                                             edges to the computer reached (#80)
POST /api/cases/{id}/analyze                 db.build_graph (SQL) of the confirmed
                                             groups + SQL top-N distinct → the
                                             LLM (Ollama now) for the narrative,
                                             decoded inside a per-case JSON
                                             schema + grounding check (#37)
MCP (stdio, read-only)                       app/mcp_server.py - 19 tools over the
                                             same views; every call hash-chain
                                             logged to mcp/access.jsonl (#38);
                                             never assigns FD ids (#51)
GET  /api/overview[?company_id=[&project_id=]] one customer, one project of it (#75),
                                             or all; KPIs, detection areas (every suggestion,
                                             undecided, the case holding most),
                                             attention, suggestions by first-event
                                             day, top entities (an account with its
                                             computers and source addresses), urgent
                                             findings (high / critical not decided),
                                             activity, by_customer / by_project (each
                                             one's own figures, areas and evidence),
                                             coverage + attention_files, tactics (all
                                             15), top_rules (10, with decisions);
                                             MTTC still returned, not shown
                                             (services/case/overview.py; per-case facts
                                             cached on a fingerprint of DuckDB, review
                                             log, custody log and id registry;
                                             gotchas #50, #51, #73)
```

## The manifest

A manifest now carries more than the upload: `company_id`/`company_name`
(always set since FR-2.1), `project_id`/`project_name` (only when the case
was uploaded into a project), `compression` (`gz`/`zip`/null), `size_bytes` (as
uploaded) vs `uncompressed_bytes` (what the 10 GB limit is measured on),
`members`/`skipped_members` for a zip (with each member's `row_id` range),
`progress` while processing, `evidence` (SHA-256 of the raw file at
acquisition, gotcha #28), `mapping` (gotcha #27) and `escalations`
(gotcha #26). Cases uploaded before these existed simply lack the keys -
read them with `.get()`.

## Login

**Login (FR-1, IAI-13).** Every `/api/*` route needs a signed-in session except
`/api/health`, `/api/auth/login` and `/api/auth/config` - enforced by one
middleware in `app/main.py`, so a new router is protected without doing
anything. The page and its bundle stay public; they hold no data.
- Accounts are made by an administrator with `tools/create_user.py`
  (add / list / remove) and kept in `AUTH_DIR/users.json`, apart from
  customer data (gotcha #41); there is no sign-up page on purpose. Passwords are
  stdlib `scrypt`, so auth added no dependency.
- The session is an HMAC-signed cookie (`fa_session`, HttpOnly, 12h), not
  server state. Every request re-reads the account, so **removing a user
  ends their sessions at once**; what logout cannot do is revoke a copy of
  the cookie taken before it expires - but a password reset does end them (gotcha #47).
  Failed sign-ins are throttled and every sign-in event is audit-logged (gotcha #47).
- **Roles since IAI-14 (2026-10-22, `docs/specs/IAI-14_rbac.md`):** admin (everything the others may, plus
  accounts - Q56's "accounts + read only" superseded by the user the same day),
  manager (case work + customers and projects - create, close / reopen, rename, move a case -,
  merge, assign, close / reopen findings, delete a case, a project or a customer), analyst (case
  work, uploading into an existing project). One table,
  `authz.PERMISSIONS`; deny by default; a route asks `authz.require`, the UI reads the same table
  through `/api/auth/me` (`frontend/src/permissions.js`) but the server is the gate. Accounts are
  managed on the Users page (admin only, `routers/users.py`), every change hash-chained to
  `AUTH_DIR/audit/accounts.jsonl`; the last admin cannot be removed or demoted.
- **Sign in with Google since 2026-11-02 (`docs/specs/google_login.md`, gotcha #82)**, beside the
  password, not instead of it: OpenID Connect code flow + PKCE run by the server (stdlib, no
  dependency, nothing loaded from Google by the page). Anyone whose ID token's `hd` claim is in
  `GOOGLE_ALLOWED_DOMAINS` may sign in, and gets an analyst account (no password) the first time -
  the user's choice, so **disable, not remove**, keeps someone out. Off unless `GOOGLE_CLIENT_ID`,
  `GOOGLE_CLIENT_SECRET`, `GOOGLE_ALLOWED_DOMAINS` and `PUBLIC_URL` are all set (`.env.example`).
- **The review actor comes from the session, not the request body.** It used
  to be whatever name the browser sent (typed once, kept in localStorage as
  `analyst-name`), which let any client write any name into an audit log
  (FR-7.6). Decisions recorded since carry the account's email; older ones
  keep the name that was typed.
