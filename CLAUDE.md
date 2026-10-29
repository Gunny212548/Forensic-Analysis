# CLAUDE.md

Guidance for Claude Code when working in this repo.

## What this is

A standalone forensic log analysis tool — **no Wazuh dependency**. Upload any
log file (syslog/auth.log style text, CSV firewall exports, JSON), the app's
own decoder + rule engine extracts structured fields and flags
security-relevant events with MITRE ATT&CK technique IDs. The attack timeline
and graph are then built in SQL from the findings the analyst confirmed, once every
suggestion is decided (gotcha #10), and an LLM (a local Ollama
model since 2026-10-12; Groq before) writes the
narrative around it — case summary, attack chain, timeline,
recommendations.

**Where it is going (the user, 2026-10-20 - read this first; gotcha #54).**
The purpose is *forensic reconstruction from log files*, not SIEM alert grading:
identify what each log is, put every event on one timeline, let the analyst
confirm the attack events (the system and the AI only suggest), then - only once every
suggestion is decided, from the confirmed ones (the user, 2026-10-28: a suggestion not
decided is not proven) - build the attack timeline, the attack path and a graph of what the attacker did - which
command, from which host, to which host. Flow: **Ingest -> Timeline -> Attack
events -> Attack timeline -> Attack path / graph -> Report**; the Respond step
(lifecycle, MTTC) is to be removed. **Detection rules are per product since 2026-10-22**
(`specs/per_product_rules.md`, D10-D16; gotchas #61-#63): logs are Firewall or OS, each
product has its own rules over six areas, every rule names its behaviour and the document
saying why it is a finding, and its line comes from the case's own evidence (legitimate
members only) or TRW - no number set on one customer applied to another. Palo Alto and Check
Point have theirs, Windows its sign-in, lateral-movement, host, beaconing and feed rules (gotchas
#65-#70, `specs/windows_rules.md` stories 5a-5e) and Microsoft Defender's own verdicts (gotcha #76,
`specs/windows_defender_rules.md` story 5f - a product's verdict is an in-house rule, any other single
event waits for SigmaHQ); the generic R-rules still run on every other product's rows. A suggestion is keyed on the entity its rule decided on (gotcha #69). **The AI
explains every suggestion and never decides** (gotcha #72), **no cap** - in the background once the case is ready (gotchas #64,
#71; the user, 2026-10-26: "ทุก Finding ที่เจอต้องได้รับการ review จาก AI"). **Every step must cite a
standard that was actually read** (`docs/standards/SOURCES.md`). Design: `specs/case_flow_design.md`
revisions 1-4 on branch `IAI-92-identify-logsource`; most of what follows still
describes the code before that direction.

Formats exercised against real data so far: VMware ESXi `auth.log`,
Palo Alto CSV exports, Check Point SmartLog CSV exports, Check Point Log Exporter
records in a ManageEngine EventLog Analyzer export (gotcha #59), Windows Security and
Sysmon event XML, .evtx, Splunk WinEventLog text and Winlogbeat / NXLog JSON (lab captures, gotcha #60), Entra ID sign-in
CSV exports and their Azure Monitor JSON export (gotcha #39). Every file is
identified before it is read (gotcha #53, IAI-92 - on its branch): a documented
format is read through its profile, anything else is kept as evidence and not
analysed - **nothing is guessed**. On `main` the decoder still guesses columns a
file has no profile for (gotcha #7 shows what that costs).

It started as a spinoff of a separate project (`D:\Wazuh\wazuh-docker`'s
`forensic-webapp`, which fed uploaded logs through a real Wazuh manager).
That hit a hard limit: Wazuh has no decoder for arbitrary CSV exports, and
even for formats it does support, real-world testing found it silently
*missed* genuine attack events this project's own rule engine caught.

## Architecture

```
POST /api/upload
  → size + disk refused from Content-Length first (gotcha #25)
  → stream file to disk in 1MB chunks (never held in memory)
    .gz / .zip kept compressed in raw/ (services/archive.py, FR-2.3)
  → manifest status=queued, return case_id immediately
  → jobs.submit(): a job file + a bounded worker pool run pipeline.process_case
    (services/jobs.py, gotcha #48; queued work survives a restart)

pipeline.process_case  (services/pipeline.py)
  CSV  → fast path: DuckDB reads + decodes the file itself. The column
         mapping is resolved once from the header - from a log source
         profile when one matches (logsources.py, gotcha #27), else guessed by
         decode.match_column - and baked into one INSERT ... SELECT
         read_csv(...). No row ever crosses into Python. The manifest's
         `mapping` says which, and the case page shows it.
  else → Python path: parsers.iter_rows() generator → decode.decode() →
         staging CSV → DuckDB bulk-loads it (needed for .log regex
         decoding and JSON; also the fallback if a CSV header maps to
         nothing).
  .gz  → either path, read through gzip as a stream - never extracted.
  .zip → each log member, one at a time, through the paths above into
         the SAME raw_events (row ids continue), so rules correlate
         across files. Member → row_id ranges go on the manifest
         (`members`, `skipped_members`); after ingest each row gets its
         `product` (gotcha #61).
  progress → manifest `progress: {stage, pct, estimated}` about once a
         second (FR-2.5; ingest 0-90, intel 90-92, rules 92-99). Measured
         for line logs/JSON (bytes read), zip members and rules. The CSV fast
         path is ONE DuckDB statement and 1.1.3 (now 2.0.0) had no query_progress(), so
         its share is an elapsed-time estimate at ~60 MB/s, held at 95% of
         the file, flagged `estimated` (the UI prefixes "~"). Manifests are
         now written tmp-then-rename, since they are rewritten while polled.
  then → products.mark + period per evidence item (gotcha #61)
       → rules.apply_rules() = SQL INSERT ... SELECT per rule; a product
         rule reads its product's rows, a line-drawing rule takes its line
         from lines.py and the manifest keeps it (`lines`, gotcha #62)
       → escalations, profiles, FD ids
       → status=ready (or failed + error/traceback on the manifest)
       → triage.enqueue: the AI reviews every suggestion in the background, one
         case at a time; the count on the manifest's `ai_review: {status, done,
         total, failed, model}` (gotchas #64, #71)

data/customers/{company_id}/db/{case_id}.duckdb   (gotcha #40)
  raw_events  every row, canonical typed columns
  findings    rule matches, joined back via row_id; lvl = Sigma level
              weight (gotcha #26)
  escalations findings an attack-path pattern raised, and which pattern

POST /api/auth/login | logout, GET /me        session cookie (see *Login*);
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
GET  /api/cases/{id}/events?limit=&offset=   paginated SQL
GET  /api/cases/{id}/findings                collapsed findings + computed
                                             confidence + review status + FD id +
                                             related findings (gotcha #49) + the
                                             AI's advice + ATT&CK tactics + detection
                                             area (the area list in its order too)
DELETE /api/cases/{id}                       admin / manager: every file of the
                                             case, recorded in the customer's
                                             deleted/log.jsonl (specs/case_delete.md)
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
                                             suggestion is decided (gotcha #10)
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
                                             (services/overview.py; per-case facts
                                             cached on a fingerprint of DuckDB, review
                                             log, custody log and id registry;
                                             gotchas #50, #51, #73)
```

**The Overview has three levels since 2026-10-28 (the user, gotchas #50, #75)** -
`#/dashboard` (every customer), `#/dashboard/<co>` (one customer), `#/dashboard/<co>/<pj>`
(one project). The first two are **overviews and nothing more**: three tiles (open cases of
N, to review, customers - or the customer's open projects of N), the attention banner when
something waits, and one table - **By customer**, or the customer's **Projects** - a row each
with its suggestions per area, not decided of all, the worst not decided, (open) cases and an
Evidence column (log source and period, days without events); a row opens the level below.
Only a project's Overview has the details: the summary card, Evidence coverage, the
detection areas, ATT&CK tactics reached (all 15), severity, top affected, Top rules (with the
analysts' decisions), urgent findings, activity - the SIEM-style sections the user chose on
2026-10-28; EPS, MTTx, a geo map and compliance were left out on purpose (gotcha #50). Cases
in "No project" have no detail page: move them into one. What follows is the detail level:

The Overview was redesigned on 2026-10-19 (gotcha #50) - an attention banner,
a KPI strip (since 2026-10-27 the summary card's right column, SOCRadar layout), the
detection-area cards (eight since 2026-10-26 - the host areas, gotcha #66), a per-day
chart, top affected, urgent findings and recent activity. **Since 2026-10-27 it counts
as the case page counts** (the user: the dashboard must match what a case shows):
the big total is the suggestions not decided, an area card every suggestion in the
area (and how many are not decided) and opens the case holding most of them, the
chart suggestions by the day their first event happened over the whole span, the
urgent list the high / critical findings not decided; no MTTC (gotchas #50, #73). The
case table is no longer on it. No figure is a placeholder. "Top affected"
ranks by accumulated risk score, not by case count: ranked by count, the
benign admin account seen in every seeded case came out first (gotcha #16
again). **The page always says whose data it shows (2026-10-15, the
user's requirement):** the header names the customer, or every customer
when unscoped; each top-affected row and activity line carries its
customer; and top-affected is aggregated *per customer* - the same address
in two customers' cases is two hosts, and used to add up into one row.
A technique card stays *one* card and lists every customer it was seen in:
the same technique is the same behaviour whoever it happened to. **An account on
Top affected names where it was seen** (2026-10-27): "on" the computers whose logs
hold its flagged events and "from" the source addresses - `NT AUTHORITY\SYSTEM` or a
local `Administrator` is a different account on every computer (`db.account_origins`,
a query of its own because `risk_scores()` feeds the narrative's prompt).

Storage layout under `DATA_DIR` (`/data`) - **one store per customer**
since 2026-10-14 (gotcha #40). `customers/<company_id>/` holds everything
of that customer and nothing of anyone else's: `customer.json` the customer
record · `projects/` its projects, one JSON each and its hash-chained `.log.jsonl` (question, status, renames, moves) · `cases/` manifests (small JSON) · `db/` per-case DuckDB · `raw/`
original uploaded files, compressed ones kept compressed (audit trail) ·
`analysis/` cached AI output and the AI's review of the suggestions (`<case>.triage.json`) ·
`deleted/log.jsonl` hash-chained record of every case and project deleted · `jobs/` one file per unfinished case (gotcha #48) ·
`findings/ids.jsonl` the hash-chained FD-id registry (gotcha #49) · `review/` append-only analyst decision logs,
one JSONL per case (see gotcha #19) · `custody/` hash-chained
chain-of-custody logs, one JSONL per case (gotcha #28). Where older gotchas
say `review/{case_id}.jsonl`, `raw/<case_id>.csv` and so on, read them as
inside the case's customer store. Shared, because none of it is customer
data: `intel/` threat-intel feed files (see gotcha #17) · `tmp/` staging ·
`mcp/access.jsonl` hash-chained log of every MCP tool call (gotcha #38) ·
`deleted/customers.jsonl` hash-chained record of every customer deleted - metadata only,
because the customer's own store went with it (gotcha #74).
**Login accounts are not in `DATA_DIR` at all** (gotcha #41): `users.json` +
`session_secret` live in `AUTH_DIR` (`/auth`, its own Docker volume
`forensic-auth`; see *Login* below).

A manifest now carries more than the upload: `company_id`/`company_name`
(always set since FR-2.1), `project_id`/`project_name` (only when the case
was uploaded into a project), `compression` (`gz`/`zip`/null), `size_bytes` (as
uploaded) vs `uncompressed_bytes` (what the 10 GB limit is measured on),
`members`/`skipped_members` for a zip (with each member's `row_id` range),
`progress` while processing, `evidence` (SHA-256 of the raw file at
acquisition, gotcha #28), `mapping` (gotcha #27) and `escalations`
(gotcha #26). Cases uploaded before these existed simply lack the keys -
read them with `.get()`.

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
- **Roles since IAI-14 (2026-10-22, `specs/IAI-14_rbac.md`):** admin (everything the others may, plus
  accounts - Q56's "accounts + read only" superseded by the user the same day),
  manager (case work + customers and projects - create, close / reopen, rename, move a case -,
  merge, assign, close / reopen findings, delete a case, a project or a customer), analyst (case
  work, uploading into an existing project). One table,
  `authz.PERMISSIONS`; deny by default; a route asks `authz.require`, the UI reads the same table
  through `/api/auth/me` (`frontend/src/permissions.js`) but the server is the gate. Accounts are
  managed on the Users page (admin only, `routers/users.py`), every change hash-chained to
  `AUTH_DIR/audit/accounts.jsonl`; the last admin cannot be removed or demoted.
- **The review actor comes from the session, not the request body.** It used
  to be whatever name the browser sent (typed once, kept in localStorage as
  `analyst-name`), which let any client write any name into an audit log
  (FR-7.6). Decisions recorded since carry the account's email; older ones
  keep the name that was typed.

**Why DuckDB and not Elasticsearch:** this is batch forensic analysis for one
analyst, not a real-time multi-tenant SIEM. DuckDB is embedded (no server to
operate), columnar (a 65k-row Palo Alto CSV costs a few MB), and its
GROUP BY/HAVING is exactly what the correlation rules need. An ES cluster
would be heavy operational baggage for zero benefit at this scale. The version is
**2.0.0** since 2026-10-29 (pinned in `requirements.txt`; 1.5.6 from 2026-10-14, 1.1.3
before) - a gotcha or comment that names 1.1.3 or 1.5.6 was measured on an old one. 2.0
opens the 1.5.6 case files and keeps their storage version. By default it would write new
ones as storage version 69, which no 1.x opens, so `db.connect` passes
`storage_compatibility_version: v1.5.0` (`db.DB_CONFIG`) and a case 2.0 writes still opens
in 1.5.6 (checked: a Check Point case processed on 2.0, read back by 1.5.6) - going back
strands nothing. Every check and the parity baseline gave the same answers on 2.0.

The UI is a **Vite + React** app whose source is `frontend/` and whose build
output is `static/` — which is generated, gitignored, and never edited by
hand. `app/main.py` serves `static/index.html` at `/` and the bundle through
the `/static` mount, so `vite.config.js` sets `base: '/static/'` to match.

```
frontend/src/
  App.jsx              session gate + hash router (#/dashboard, #/upload,
                       #/finding/<case>/<key>, #/reports|attack-graph|timeline
                       [/<case>[/<tab>]], and the menu routes of Sidebar.jsx);
                       the old #/result/<case>[/<key>] redirects (gotcha #51);
                       signed out -> #/login, and signing in always
                       lands on the Overview (the user's call, 2026-10-16)
  api.js               every call the UI makes, and nothing else
  format.js            fmtBytes/fmtTime/shortTs + the status & severity maps
  theme.js             light / dark, kept per browser in localStorage fa_theme
  pages/               Overview (#/dashboard[/<co>[/<pj>]], three levels) ·
                       Upload · Cases · CaseFlow (one
                       case as six steps, #/case/<id>/<step>, gotcha #52) ·
                       Findings · FindingDetail · Customers (Delete per row) ·
                       CustomerDetail (also a project's page: close / reopen,
                       rename, delete, move a case, timeline and path) ·
                       Users (the Settings menu item, admin) · Login ·
                       Placeholder (a menu page not built yet - none today)
  components/          Sidebar (app shell, FR-0, theme button) · StepBar
                       cards.jsx (summary card, area card, stat tile, folding
                       section) · icons.jsx (stroke icons, inline SVG)
                       EventsTable · ReviewPanel (Attack events, by area and
                       rule) · AiReview · FindingEvents · RuleCard (Sigma/ADS)
                       Evidence (custody) · Mapping (how each file was read) ·
                       Period · Question · Reprocess · ProfilePanel · Veris ·
                       DeleteCase · DeleteCustomer · AttackGraph ·
                       AttackTimelineView (a case's and a project's) · analysis.jsx (chain/timeline/
                       risk/meta, grounding warnings) · common.jsx (severity
                       pill, status badge, MITRE tags). Workspace.jsx (left
                       over from #/result) was removed on 2026-10-29; Lifecycle.jsx
                       went with the status workflow's buttons (gotcha #73)
```

It replaced a hand-written 1,212-line `static/index.html`, whose URLs were
kept unchanged so pasted case links survived the rewrite. Neither of its
localStorage keys is read any more: `analyst-name` (the reviewer is the
signed-in account, see *Login*) and `fa_recent_uploads` (since IAI-28 the
Upload page's "My recent uploads" are the cases whose `evidence.recorded_by`
is the signed-in account, from `GET /api/cases` - they follow the analyst
across browsers, and a case that no longer exists cannot linger). The
original was kept as `legacy/index.html.orig` until 2026-10-29; it is in git
history now (`git show fb61af5:legacy/index.html.orig`).

**What "no external JS" now means.** The old page took it literally: no build
step and no dependency, because a vis-network CDN import had been removed
after a physics simulation added interactivity nobody needed and read worse in
a report. The constraint that actually matters is **nothing fetched at
runtime**, and Vite satisfies it - every asset is bundled locally, so a case
is still workable air-gapped (gotcha #17). The build needs the network; an
analysis never does. Dependencies are pinned exactly and the Dockerfile builds
the bundle in its own `node:22-slim` stage rather than copying the host's
`static/`, so an image can never ship a stale bundle and the output stays
reproducible - which matters because the output is evidence. Verified: the
in-image build produced a byte-identical bundle hash to the host build.

**Look and feel follow the SENTRY-IR Figma (since 2026-09-29).** The palette
in `styles.css` `:root` was sampled from the rendered frames (light
`#EEF0F3` page, white panels, amber `#B36B00` as the only action colour - red since 2026-10-27, below), and
the type is IBM Plex Sans / Plex Sans Thai / Plex Mono, bundled via
`@fontsource` so the nothing-fetched-at-runtime rule above still holds.
Plex Sans has no Thai glyphs, and most UI text is Thai, which is why the Thai
cut is there too. Severity, review-status and job colours kept their meanings
and were only re-mapped onto the Figma tokens. Exception: the attack graph
keeps a dark canvas (`--graph-bg`), because the colours in `AttackGraph.jsx`
are drawn for it; it gets the Figma treatment in its own story (IAI-61). The
whole UI is in English, as the Figma is (since 2026-10-12, see *Decisions*).

**The SOCRadar layout, light and dark (2026-10-27, the user's request).** The
user asked for the whole app to look like SOCRadar's dark-web report and
approved a mockup (claude.ai artifact "SENTRY-IR redesign"); it is built in
steps: 1 tokens + theme button + menu, 2 shared summary card / area card /
stat tile / collapsible section (`components/cards.jsx`, icons in `icons.jsx`),
3 Overview, 4 the case page (all four done: a summary card above the steps -
suggestions by the day their first event happened, how many the AI explained
and the analyst decided - the steps as six boxes, and Attack events as one
folding section per detection area with a block per rule, each suggestion
keeping its whole card), 5 the other pages (Findings, Cases and Customers open
on a row of stat tiles - Findings' critical / high tiles are its severity
filter - and every panel and list head is the cards' shape). All five done
2026-10-27. A section folds only when the analyst clicks; its head keeps its
counts. Then, at the user's word ("too much"), the Ingest step became folding
sections: Files read (a file whose reading needs attention - not analysed,
columns guessed or missing, rows not loaded, time unreadable - is always shown,
`Mapping.needsAttention`; the others fold under one line), question, custody and
method open; periods, rules per product, lines and the events table folded
(`lazy`: not fetched until opened). Attack events dropped its "N not decided",
"final report cannot be issued" and "AI explaining N of M" lines, Ingest its
"events read, digest verified" line - the summary card (polled while the AI
runs) and the step box say it; the AI line returns only when explanations are
missing, with Review again. **Say a figure once on a page** (the user). Light stays the default; dark is `[data-theme=dark]` on
`<html>`, set by the button beside the brand (`theme.js`) and kept per browser
in localStorage `fa_theme` - the OS setting is deliberately not followed (no
look the analyst did not ask for). The action colour is red now (`--accent`,
the user's choice over blue, knowing it sits near critical), so **`--accent`
means "act here" only**: amber high severity and warnings, which used to share
it, are `--warn` - give any new severity or warning colour `--warn`, never
`--accent`, or every high reads as a button. A colour belongs in a token with a
value under both themes; a literal hex in a rule is wrong in one of them.

The attack graph is still a **static SVG** with no library
(`components/AttackGraph.jsx`), and its geometry is deliberately the same
arithmetic the old page used, because these diagrams get screenshotted into
reports: nodes in columns by role (pure sources left, pure sinks right,
anything with both in/out in the middle), and edge labels anchored just past
the *source* node rather than at the edge midpoint — these graphs are usually
many sources converging on one target, so every midpoint lands in the same
spot and the labels pile up on top of each other.

Two things the rewrite changed on purpose:
- **`escapeHtml()` is gone.** The old page concatenated `innerHTML`, so every
  filename, company name and rule description had to be escaped by hand. The
  discipline was actually held - audited before porting, no gaps - but JSX
  escapes text nodes for us, so the class of mistake is removed rather than
  guarded.
- **No `window.prompt()`/`alert()`.** Choosing a rejection reason used to mean
  typing a number 1-N into a browser prompt, and the analyst name was another
  prompt. Both are now inline: `reason_code` is a `<select>` fed by the API's
  own `reason_codes`, with the confirm button disabled until one is chosen, so
  FR-4.6 is enforced in the UI instead of discovered as a 400.

**Never gate a form's submit button on React state that autofill feeds.**
Chrome fills a saved account into the login fields without firing input
events, so `Login.jsx`'s button - disabled until `email`/`password` state was
non-empty - sat greyed out beside two visibly filled fields, and the analyst
could not sign in (found 2026-10-05). The inputs are now uncontrolled and
`submit()` reads `form.elements` at click time, which is after Chrome releases
the autofilled values; an empty field is reported as an error instead.

`npm run dev` in `frontend/` serves the UI with hot reload and proxies `/api`
to the container on 8091, so the UI can be worked on against real cases.

**Two instances on one machine log each other out.** Browsers do not scope
cookies by port, so a host-run copy (`uvicorn` on e.g. 8097 with its own
`DATA_DIR`) and the container on 8091 share one `fa_session` cookie on
`localhost`. Signing in to either overwrites it with a token the other's
secret rejects, and the other bounces to the login page on its next request -
which looks exactly like a session bug and is not one (2026-10-05: the
"logged out ~7s after login" was a sign-in on 8091 in another tab). Test the
host copy on `127.0.0.1:<port>` instead, a different host name with its own
cookie jar, or stop the container.

## Known gotchas (discovered the hard way — don't re-debug these)

Each gotcha is a file of its own in `docs/gotchas/`, numbered as they were
written (`docs/gotchas/23-*.md` is "gotcha #23" wherever the docs cite one).
The line below is the rule; the file is the measurement, the history and what
was tried and rejected. **Before changing code a gotcha names, read its file** -
most of them were paid for with a silent wrong answer. A new gotcha gets the
next number, a file, and one line here - not its evidence: they were moved out
on 2026-10-20 because this file had passed Claude Code's 150k-character limit.

**Ingest and decoding** (`decode.py`, `parsers.py`, `pipeline.py`, `logsources.py`)
- #1 Never bulk-insert with DuckDB `executemany()` (~300 rows/s): stage a CSV and bulk-load it in one statement.
- #2 Exact column-name matches beat substring matches (`Action` vs `Log Action`), or every firewall rule silently stops matching.
- #3 ESXi syslog has no hostname; `_split_host_prog()` reads token by token instead of one greedy regex.
- #4 `Connection from X port N` is the client's *source* port; never set `dstport` from SSH captures.
- #7 "ready with 0 findings" on a firewall export means a mapping problem: count the non-NULL canonical columns first.
- #8 Check Point has no port column; R2003 counts services instead. Check a field exists across log sources before a rule depends on it.
- #9 A source- or action-filtered export silences correlation rules; ask what filter produced the file.
- #11 Auth outcome on CSV: only the auth vocabulary translates (never allow/deny), and a username is required on the row.
- #12 "Resource" contains "source": check what else in a real header contains a candidate substring (`_AVOID_SUBSTRINGS`).
- #22 Sniff the delimiter once and hand it to all three readers; a TSV read as CSV produces plausible garbage findings.
- #25 Starlette spools the whole upload before the handler: size/disk refusals run from Content-Length in middleware.
- #27 Columns come from a documented log source profile when one exists; a guess is labelled one. Say "log source", not "vendor".
- #39 JSON is streamed, flattened to dotted keys and mapped like a CSV header; a guessed Entra JSON mapping found nothing.
- #42 ESXi `auth.log` is read line by line; "observed" (real file, no published format) is its own honesty level.
- #43 Check Point SmartConsole profile; every case reports coverage (rows not loaded, per-field counts).
- #44 Syslog envelope per RFC 5424 / 3164; an RFC 3164 year is inferred and flagged `year-inferred`.
- #45 A FortiGate session that ended normally (`close`, `timeout`, ...) is `allow`.
- #46 A UTF-16 "Unicode Text" PAN-OS export: encoding from the BOM; a `.txt` with a documented header is read as that table.
- #76 Defender's own verdicts (story 5f, `specs/windows_defender_rules.md`): a product's verdict is an in-house rule (Q114, beside W-D1); WIN-MAL-2 one detection per host + Detection ID, medium when remediated, no technique, no generic twin (R3002 would make it a Downloader); WIN-HOST-3 turned off / tampered (T1685); item names differ per event - read the provider's templates; a rule may write a *lower* `lvl` (`least`).
- #70 The user's blind Windows quarter (`D:\logtest\blind-windows`, now read - no longer blind): WIN-AUTH-1's spray branch leaves out computer accounts (the sprayer's own `web01$`), WIN-MAL-1 leaves out a (process, destination) beaconing on more than half the Sysmon hosts, named on the line record (ESET's timer, 40,725 rows) - only from 20 hosts up, else one host's evidence hid every beacon (Q105); not-attack rows 43,523 -> 2,567; K1 / K6 / K8 / K9 / K11 still missed.
- #78 Public Windows data (`D:/logtest/internet`: EVTX-ATTACK-SAMPLES, OTRF): WIN-HOST-2 needs PROCESS_VM_READ (`GrantedAccess & 0x10`, W-D17) - svchost's 0x3000 Prefetch write fired on 6 datasets; the dev image without `--build` had no `evtx` library (every .evtx one row); never run a script beside a data folder named like a library; 43 OTRF flat-JSON datasets have no reader.
- #77 Story 5g: WIN-LAT-2 / -4 flag a (source, account, service / task / file) seen on one day of the evidence only - two days or more is expected (AN1468 UserContext, AN1185 allowlists; Veeam / PDQ 2,560 rows -> 8, attacks kept); join the day count with `IS NOT DISTINCT FROM`; lower `%SystemRoot%` before replacing it - a 4697 never matched the written file.
- #68 Windows story 5d: WIN-BRUTE-4 (B5) is Javed & Paxson's CUSUM and saw nothing until the normal was cleaned as the paper cleans it (pointwise brute-forcers out, §5's automation test) and Z counted in quarter failures (`lines.CUSUM_SCALE`) - W3 156 of 246; 4768 0x6 a failed attempt; a 4778 reconnect carries the session's own id (WIN-LAT-1, OTRF found); ADMIN$ / C$ in WIN-LAT-2, WIN-LAT-4 file copied then run; 7045 untyped.
- #67 Windows beaconing and feeds (WIN-MAL-1, WIN-INTEL-1..2): R2007's method per (host, process, destination) with silences over an hour left out - R2007 missed a working-hours beacon; supersede R2007 / R3003-R3005 on Windows rows; documentation ranges never reach a feed.
- #66 Windows lateral movement / host rules: steps linked by the session (TargetLogonId -> SubjectLogonId, Sysmon ProcessGuid; ASOF to the latest 4624), no window; WIN-LAT-1 = an RDP pair seen on one day of the evidence (the user's choice); WIN-LAT-3 compares an account with its own Kerberos; two areas, eight Overview cards; the OTRF reconnect (4624 type 7) and a dump with no Sysmon 10 are missed.
- #65 Windows sign-in rules (`rules_windows.py`): one attempt however many events record it - a DC's 4771 / 4776 within 1 s of a host's 4625 joins it, its address kept; 4771 / 4776 counted (Q84 reverses Q41); WIN-BRUTE-1..3 / WIN-AUTH-1 supersede R2000 / R2005 / R2006 / R2008 / R2009 on Windows rows; measured on `tests/gen_windows_domain.py`.
- #63 Generic rules are superseded per product (`RULE_SUPERSEDED`: not on Palo Alto / Check Point rows, nor the sign-in, beaconing and feed rules on Windows rows (#65, #67); still on FortiGate, ESXi, sshd, Entra); escalations and VERIS count behaviours via `RULE_EQUIVALENT` / `generic_sql`; baseline re-taken (668 entries).
- #62 Firewall rules (`rules_firewall.py` shared, `rules_paloalto.py`, `rules_checkpoint.py`): lines from the legitimate members only (TRW-benign sources) or TRW (`lines.py`) - a percentile over everyone is raised by the attackers; rule ids are `RULE_ID_PATTERN`, families `RULE_FAMILY`; both rule sets run until story 4 - do not deploy story 2 alone.
- #61 Every row carries its product (`products.py`, written after ingest - readers insert positionally); a product rule (`rules.RULE_PRODUCT`) reads `product_events` only; n/a per product and area with its reason; the period each evidence item covers (`period.py`). Story 1 of `specs/per_product_rules.md`.
- #60 Windows events (`winevent.py`): event XML read whole (an event spans lines), the event as written in `win_events` (MAP of its own item names, for SigmaHQ), the timeline row in `raw_events`; 4625/4624 feed the sign-in rules. W2 .evtx via the `evtx` library: records counted against the chunk headers (it drops damage silently), GUID/FILETIME/SYSTEMTIME values put in Windows' form from the record's Binary XML types; W3 Splunk WinEventLog text: items named from Windows' own message templates (`app/data/windows`, `tools/export_win_templates.ps1`), values as rendered. W4 Winlogbeat / NXLog JSON (`json_shape`): Winlogbeat writes rendered values and leaves out empty items; NXLog's own fields set aside by its documented list, but a template-named item always kept.
- #59 Check Point Log Exporter records inside a ManageEngine EventLog Analyzer search export (`checkpoint_le.py`): record documented, wrapper observed; fields via `regexp_extract_all`; update logs sharing a `loguid` are `log_update` rows with no verdict; epoch `time` states its zone.
- #53 Every file is identified before it is read, in Sigma logsource terms (`identify.py`); no column is guessed; a format without a reader, or none, is kept as evidence and not analysed. A file's name proves nothing - JSON-lines arrive as `.log`, exports start with a blank line.

**Time**
- #21 Every timestamp is normalised to GMT+7 (offset converted, no offset assumed GMT+7). A re-process is required after any change; old cases do not say they are stale.

**Rules and severity** (`rules.py`, `severity.py`, `rule_meta.py`, `intel.py`)
- #6 A row can match several rules; `flagged_count` counts `DISTINCT row_id`.
- #14 Per-source counters miss spread attacks: R2005 spray (one account, many sources), R2006 multi-source logins in one hour.
- #15 Beaconing (R2007) is a regularity test (jitter < 0.6) and only on public egress - internal traffic is periodic by nature.
- #16 Risk ranking needs diminishing returns: `sum(lvl * (1 + ln(n)))` per distinct rule, or it ranks by volume.
- #17 Threat intel is offline feed files JOINed per case; a feed refresh moves R3003-R3006 by design - re-take the baseline and say so.
- #23 A correlation rule needs an outer `WHERE` on the evidence rows, not just a threshold (R2002/R2003 deny-restricted).
- #24 Why the workflow threshold is not "high or 2 families" (183 items opened); measured on the old scale - see #33.
- #26 Severity is a Sigma level; a refused row is capped at medium; escalation patterns (credential-compromise high, compromised-host critical). `findings.lvl` stores weights.
- #29 Every rule carries Sigma + ADS metadata; status is earned (no rule is `stable`); `tests/check_rule_meta.py`.
- #35 Intel feeds may be STIX 2.1 bundles; only pure IP-equality indicators are taken.
- #57 Behaviour profiles (`profiles.py`): per-source and per-account facts in SQL at ingest, ranked against the same evidence (none under 20), windows `[t, t+W]` for 1/10/60 min, n/a not 0; never a finding. ESXi logs one failed PAM attempt twice (pam_unix + sshd): only the sshd line is auth_failed (fixed, R2000 35->32 on auth.log).
- #56 A rule only answers "known attack pattern?" (layer B); event type is layer A, context facts layer C (`db.list_raw`). R1000-R1004 / R2001 / R3000 / R3006 left the rule set (metadata `deprecated`); R2008 login-after-brute-force, R2009 measured spray; R2005 renamed (branch `rules-layers`). Parity needs the intel feeds or R3003-R3006 read 0.

**Findings, review and workflow** (`review.py`, `lifecycle.py`, `confidence.py`, `finding_ids.py`, `related.py`)
- #19 Review state lives outside the case DuckDB, append-only, keyed by the collapsed finding `rid|srcip|username`.
- #69 The key's source / account is the entity the rule decided on when it names one (`findings.entity_src` / `entity_user`, `RULE_ENTITY`, read through `db.entity_sql`), else the row's; insert into `findings` with named columns; the Windows quarter 517 -> 26 suggestions; a DC's `::ffff:` address is IPv4 in the timeline; the account's history is an AI fact (wrong rejects 8 of 76 -> 2 of 22).
- #20 Confidence counts rule *families*, not ids; `timezone-unconfirmed` is tested on the source text, never on `ts`.
- #30 Confidence is an Admiralty grade (reliability letter + credibility number).
- #31 The review log is hash-chained; old unchained decisions are sealed, not rewritten.
- #33 Finding lifecycle Open -> Investigating -> Contained -> Resolved; only Sigma high/critical enter it. Off the screens since #73.
- #49 FD ids per customer per year, written before `ready`; source events; related findings via pivot hosts; the Findings page.
- #50 The Overview redesign, and the designs the user rejected - **do not re-propose them**.
- #51 `#/result` retired (Reports / Attack Graph / Timeline / finding page); Sprint 3 review fixes; ADR-3/4; branches and worktrees; testing in a container; scripted-edit traps.
- #73 The analyst's decision replaced the status workflow on screen (the user, 2026-10-27): its buttons left with Respond, so every status stayed Open; Findings filters and counts by decision (badge = high / critical not decided), no assignee, no MTTC on the Overview; a case is open while a suggestion is not decided (the report gate). `lifecycle.py` and its API stay for the audit trail.
- #74 A customer is deleted with every case (admin / manager, the Customers page, specs/customer_delete.md): its store is renamed out of `customers/` in one step, then removed; the record goes to the shared hash-chained `deleted/customers.jsonl`, carrying its earlier case deletions; refused while a case is busy. A case without a `product` column must not break the Overview.
- #75 A project is one investigation (specs/projects.md, Q110-Q113): every new case is in one (the API refuses none - check_parity, check_authz and every upload script name one); Open / Closed, closing gated on every case processed and every suggestion decided, a Closed project refused for upload and merge; status changes in the project's hash-chained log, written under `storage.PROJECT_LOCK` with its question; a merge across projects is refused. `tests/check_projects.py`.
- #52 The case page is six steps at `#/case/<id>/<step>` (IAI-89); `GET /flow` computes each step's state on the server and names its standards; old case links redirect. `sprint/4` merges Sprint 3's two branches.

**Evidence, storage, jobs and access** (`custody.py`, `storage.py`, `jobs.py`, `auth.py`, `mcp_server.py`)
- #28 Evidence is SHA-256 hashed on arrival and re-hashed before every run; custody log hash-chained.
- #38 Read-only MCP server over stdio; every call hash-chain logged; no write tool, no free SQL, no port.
- #40 One store per customer under `customers/<id>/`; `case_dir()` is the only answer to "where is this case"; cross-customer merge is 409.
- #41 Login accounts live in `AUTH_DIR`, apart from customer data; docker-compose deliberately does not set it.
- #47 Sign-in throttled per account (not per address), audit-logged, and bound to the password hash.
- #48 Work is queued, durable and bounded (`jobs.py`); manifests are written atomically. **One process only.**
- #58 Ingest: question on the project (hash-chained log), provenance / declared time off the screen since 2026-10-27 (the user: too much, then not needed; `PUT /provenance` still takes them), a declared zone / clock offset applied only on re-process (`POST /reprocess`), a method record on every `processed` line, duplicates named within a customer.

**AI narrative** (`analysis.py`, `llm.py`, `grounding.py`, `veris.py`)
- #72 The AI explains and never decides (the user, 2026-10-27): no accept / reject / "likely attack" - what happened, why it fired, facts for an attack and for an ordinary cause, what is not shown, check next (Heuer ACH); log values quoted; the review line keeps only model + time; old advice replaced by Review again; one schema per suggestion (a batch-wide enum let 13 of 113 name another rule's false positive), the attack side `minItems: 1` (optional, 16 of 94 attacks came back empty); ~14 s a suggestion.
- #71 Every suggestion is reviewed by the AI itself, no cap (the user's requirement): the case is ready after the rules and the review runs on in the background (`triage.enqueue`, one worker, resumed at start-up), every rule first, a failed batch retried then sent one by one, what is left listed with "Review again" (`POST /ai-review`); batch size measured (`TRIAGE_BATCH`).
- #64 The AI reviews every suggestion while the case is processed (`triage.py`; since #71 after it is ready): facts computed in SQL (a destination's popularity among internal hosts, the rule's documented false positives), a schema, an address check; advice under each suggestion, kept on the review line; the Upload page counts the suggestions reviewed; `TRIAGE_ENABLED=0` in every rule check and in dev.
- #5 Groq's output-token limits and the measured sweeps (events 15, max_tokens 950); schema key order is the priority list. Groq only - not the local model.
- #10 The attack graph is SQL (`db.build_graph()`), not AI - don't hand it back to the model. Since 2026-10-28 it, its risk ranking and the attack timeline (case and project) take only the confirmed groups (`keys=`, `case_views.decided`) and stay empty until every suggestion is decided - MCP's `get_attack_graph` / `get_risk_ranking` too (`case_views.attack_path`); keys go in as one JSON string (a bound list cost 0.43 s a query).
- #13 Every wrong narrative was missing input, never reasoning: compute the discriminating fact in SQL and hand it over; prompt hardening was measured to do nothing.
- #36 VERIS 1.4 classification is computed, then handed to the model.
- #37 The narrative is decoded inside a per-case JSON schema and grounding-checked; every query feeding the prompt needs a total `ORDER BY` tiebreak; citations `F<n>`.

**Exports**
- #32 ATT&CK Navigator layer (format 4.5).
- #34 STIX 2.1 bundle (and why `stix2-validator` rejects every bundle).

**Method**
- #18 Measure before optimising: time a stage first; corpus wall-clock spread is host I/O.
- #54 The product direction of 2026-10-20 - forensic reconstruction, Respond removed, in-house rules kept with SigmaHQ rules added beside them (the retirement was reversed after ADR-006: SigmaHQ has no correlation or failed-login rule, no firewall-traffic rule). **Read before designing anything.**
- #55 A standard is cited only from a document actually read (`docs/standards/SOURCES.md`); PDFs are read with `pdftotext` (the web fetcher returns compressed streams); ISO pages refuse automated access.

**`docs/STANDARDS.md` is the one-page map** of every pipeline step to its
standard (or "internal method", with the nearest framework named and the
method written out - risk ranking, TP/BTP/FP, rule validation, escalation
patterns). The user's requirement since 2026-10-12 is that every step cite
one; update that table whenever a step changes.

## SENTRY-IR console (requirements Sept 2026, being built)

The target UI is `figma-export/` (10 screens: login, Upload, Overview,
Incidents (= the Findings page, see *Decisions*), Timeline, Customers,
Attack-graph, Attck-map, Reports, Settings).
Its text is **outlined to paths**, so `grep` finds nothing; render each SVG
with headless Chrome (`--screenshot --window-size=1728,<height>`) and read the
image. Use the SVG's own height - `Overview.svg` is 2346px tall and a
1117px window silently cuts off its bottom half. On Windows pass the output
and `file:///` paths with forward slashes (`cygpath -m`); backslashes are
eaten on the way to Chrome and it renders "file couldn't be accessed". The
agreed functional spec is `AI-Incident-Analysis-Reporting-FR.pdf`
in the repo root (59 items, FR-0..FR-12); its HTML source was generated, not
kept in the repo.

**Work is tracked in Jira**, project `IAI` at
https://titlenattapat.atlassian.net (epics = spec areas, stories labelled
`IAT-FR-x.y`, six two-week sprints from 2026-09-29). Work the active sprint
in rank order. When a story needs something a later sprint builds, split the
dependent criterion into its own story in that sprint rather than leaving
the story open: IAI-12's open-findings badge became **IAI-78** (Sprint 3) that way.

Built in Sprint 1 (verified in Docker, 2026-09-29):
- **IAI-12 app shell / IAI-13 login** - grouped sidebar, user + role +
  logout, English per the Figma. Roles since IAI-14 (see *Login*).
- **IAI-22/23/25/27 upload** - customer required, 10 GB after
  decompression, 2.5x disk check, `.gz` streamed, `.zip` → one case,
  separate upload / processing percentages.
- **IAI-20 case list** - was the table on the Overview; since 2026-10-19 the Overview has
  no case table (gotcha #50) and cases are reached from Customers or Findings. The Jira
  story still says Overview.
- **IAI-18/19 Customers** - a customer is added on the Upload page only
  (see *Decisions*); the Customers page's one action is deleting a customer
  (admin / manager, gotcha #74) and it shows, per
  customer, open cases of total / closed /
  highest open severity / last activity. FR-6.1 defines "open": since
  2026-10-27 a case is open while a suggestion in it is not decided (gotcha #73;
  from Sprint 3 it was "a high or critical finding not Resolved", IAI-79). Cases without a customer (pre-FR-2.1) are a "No customer" row
  so the totals add up. A customer's name opens its **profile page**
  (`#/customers/<id>`, `CustomerDetail.jsx`, 2026-10-15 at the user's
  request, no story; laid out as a customer profile - header card, Profile
  column, At a glance + cases - which the user chose over KPI tiles and
  over a report-style page): onboarded date (`created_at`, i.e. the first
  upload for it), uploaders, the log sources its files were read as, cases /
  findings / flagged events / highest severity / AI analyses, and every
  case. Frontend only - it reads
  `/api/overview?company_id=` and `/api/cases?company_id=`. "Reports" is
  shown as **AI analyses** on purpose: no report feature exists yet (IAI-55).
- **Projects (2026-10-15, the user's request, no story).** A project is one
  investigation of one customer, grouping the cases uploaded for it
  (customer -> project -> case). Chosen on the Upload page under the
  customer ("+ Add new project..." creates one, idempotent by name within
  the customer, like customers); **required since 2026-10-28** (gotcha #75,
  specs/projects.md P1 - the API refuses an upload naming none, so every
  script names one); cases from before stay "No project". Stored in the customer's own store
  (`customers/<id>/projects/<pj-id>.json`), so a project can only hold that
  customer's cases: an upload naming another customer's project id is 409
  and creates nothing. A merge keeps the project; sources of different
  projects are refused. **Open / Closed** (P1): closes only when every case is
  processed and every suggestion decided, reopens at any time (manager, admin),
  takes no new case while Closed. Shown on the customer profile (Projects panel + a Project column),
  on its own page `#/customers/<id>/projects/<pj-id>`, on the case header
  and under the customer in the Overview / recent-uploads tables. Also
  (specs/projects.md, gotcha #75): an Overview and a Findings filter per project
  (P2), rename / move a case / delete a project (P3), and on the project page the
  attack timeline and attack path across its cases (P4).
- Not yet: **IAI-24 resumable chunked
  upload** (Sprint 6). The upload is one request, so a dropped connection
  restarts a 10 GB file from zero.

Pages whose story has not come up render `pages/Placeholder.jsx` and appear
dimmed in the menu (`ready: false` in `components/Sidebar.jsx`). Flip the flag
when a page is built. Timeline, Attack Graph and Reports were flipped when `#/result`
was retired (gotcha #51) and are steps of a case now; Settings is the Users page
(IAI-14). No menu item is a placeholder today.

Decisions the user made, which the Figma does not show:
- **There is no "incident" - the finding is the only unit (2026-10-05).**
  The spec and Figma had incidents as groups of findings; they were merged
  into one concept. The unit is the collapsed finding of gotcha #19
  (`rid|srcip|username`): it carries the review decision *and* the status
  workflow. Grouping survives only as **related findings** (IAI-43/44), and
  the old opening threshold decides which findings enter the workflow
  (IAI-42). The brand line is "Finding Response Console"; ids are
  `FD-YYYY-seq`. File names that say Incident (`figma-export/Incidents.svg`,
  the FR PDF) are left as they are.
- **Every datum comes from an upload.** No "New finding" button, no live
  feed, no EDR/SIEM/email integrations, no ingest API key. The Figma's
  source column (CrowdStrike, Splunk, Proofpoint...) becomes the log type.
- **A customer is added only on the Upload page (2026-10-05)** - the
  "+ Add new customer..." option of its customer select. The Customers page
  has no "Add customer" button, although the Figma gives it one (its only
  action is Delete, 2026-10-28). The
  `POST /api/companies` route predates Sprint 1 and is kept; no page calls it.
- Uploads up to **10 GB per file, measured after decompression**, with `.gz`
  and `.zip` (a multi-file zip becomes one case, even with mixed formats),
  resumable chunked upload, and percentage progress. All built except the
  resumable upload (IAI-24). A `.gz` *inside* a zip is skipped and listed,
  because its decompressed size could not be held to the budget. Known gap:
  `/merge` looks for `raw/<id>.log`, so a line-log case uploaded as `.log.gz`
  cannot be merged ("Raw file missing").
- Alerts, Threat Intel, Playbooks and Assets pages are cut.
- **All UI text is English (2026-10-05; done 2026-10-12)** - the last Thai
  strings (case page, review panel, analysis panel, events table, upload
  history, `format.js`, `api.js`, the review reason codes) were translated,
  not kept alongside. The only Thai left is `Sidebar.jsx`'s initials helper,
  which skips Thai leading vowels in *users'* names. Times the app itself
  records (upload, review, custody) render as `YYYY-MM-DD HH:MM:SS +07:00`
  via `format.fmtTime` - they used to be a Thai-calendar date in the
  browser's own zone. Code comments were always English.
- Findings: created by the rule engine, related and admitted to the
  workflow per gotcha #24, no time window (the whole case).
- **Finding lifecycle (FR-4.1, 4.5, 4.7, 4.8)** - the rules below still hold in
  `lifecycle.py` and its API, but **no screen moves a status or sets an assignee
  since the Respond step went**; the pages follow the analyst's decision instead
  (2026-10-27, gotcha #73). The Figma has status only
  (Open → Investigating → Contained → Resolved) and nothing stopped an analyst
  closing a finding without looking at it. The spec now requires:
  - A new finding starts **Open with no assignee** - the system created it.
  - To close: an assignee, and **the finding reviewed** (accept / modify /
    reject). This reuses `review.py`
    decisions keyed by `finding_key` (gotcha #19); it is not a second review
    store.
  - At close: a classification - true positive / benign true positive /
    false positive - plus a written summary.
  - A true positive must pass through Contained, with the containment actions
    recorded. False and benign positives may close straight from
    Investigating and are **excluded from MTTC**. Forcing them through
    Contained would record a containment that never happened and skew the
    metric.
  - Every status change is timestamped. MTTC is creation → Contained.

What the data forced onto the Figma, measured on the same corpus:
- **ATT&CK map:** ~98% of findings are `T1071` (C2, 65,774) and `T1595`
  (Reconnaissance, 28,889) - neither is among the Figma's 9 tactic columns,
  nor is Discovery (`T1046`). Show the tactics actually found, out of the
  Enterprise tactics (15 since ATT&CK v20). The Attack timeline step does exactly that since
  2026-10-22: a row of chevrons, one per tactic its confirmed groups reach, in ATT&CK's order
  (`rule_meta.TACTIC_ORDER`, `tactics_of`), each filtering the time-ordered list.
- **Timeline "last 24h" is always empty:** uploaded events are months old
  (Dec 2025 - Jun 2026 in the corpus). Timelines use the case's event-time
  range. The Overview's chart counts suggestions by the day their first event
  happened, over the whole span, as the case page does (2026-10-27; it was
  findings by *creation* time, high / critical only).
- **No asset inventory exists**, so "affected segments" and node roles such
  as "domain controller" become risk-ranked hosts/accounts (`risk_scores()`)
  and internal / external / IOC labels.
- Most of the Figma's sample findings (PsExec, Kerberoasting, AMSI bypass,
  web shell, phishing, OAuth consent, S3, USB) need EDR / Windows / mail /
  cloud logs that no decoder reads.
- The Figma has **no case-detail or review screen**, though both exist in the
  app today (events, findings, AI narrative, review + export gate). The spec
  keeps them as FR-11/FR-12; they need designing.

## Environment / secrets

**Ollama must be running on the host** (`ollama serve`, or the Ollama app) for the AI review of
suggestions (gotcha #64) and the narrative; without it a case is still processed, with the
reason recorded. On 2026-10-22 it was not running, and when started from a Claude Code shell it
was later stopped for low memory - qwen3.5:9b, the 8091 container and the dev container together
are a lot for this PC; stop the dev container when not in use. `TRIAGE_ENABLED=0` turns the AI
review off (every rule check sets it; the dev container has it off unless `DEV_TRIAGE_ENABLED=1`).

**What the model costs on this PC (measured 2026-10-26, gotcha #71).** RTX 5050 Laptop, 8 GB VRAM:
qwen3.5:9b loads 30 of 33 layers on the GPU (4.4 GB, KV 512 MB for one 16,384-token slot,
`n_slots = 1`), ~35 tokens/s. The AI review writes ~300 tokens a suggestion: **~9 s a suggestion at
`TRIAGE_BATCH` 5** - Mekong 61 in ~10 min, the blind quarter's 526 in ~80 min. A batch of 10 or 15
is cut off at the 3,000-token cap and falls back to single calls (~32 s a suggestion) - keep 5. A
single batch-5 call is ~1,500 tokens for one suggestion; running two requests at once
(`OLLAMA_NUM_PARALLEL`) is proposed, not measured - it changes the user's Ollama settings, so ask.

**The narrative LLM is local now (2026-10-12): `LLM_PROVIDER=ollama`,
`OLLAMA_MODEL=qwen2.5:7b-instruct`, then `qwen3.5:9b` from 2026-10-14 (see
below)** on the host's Ollama
(`host.docker.internal:11434`). Settings in force (`.env` overrides; the
`docker-compose.yml` defaults are still the qwen2.5 ones):
`OLLAMA_MAX_EVENTS_FOR_ANALYSIS` 50, `OLLAMA_MAX_COMPLETION_TOKENS` 3000,
`OLLAMA_MAP_COMPLETION_TOKENS` 1200, `OLLAMA_TEMPERATURE` 0 and
`OLLAMA_SEED` 42 (config defaults - gotcha #37); `config.py` swaps these in
for the Groq values. Also pulled on the host: `gemma4:12b-it-qat`,
`gemma4:e4b`, `qwen2.5:7b-instruct`. Consequences:
- **Gotcha #5's limits are Groq's** (1000 OTPM, 950 max_tokens, one
  analysis a minute, 429 + Retry-After). They do not bind a local model.
  The local settings are graded by `tests/bench_llm.py` against
  gen_usecase's ground truth (below and #37), but the events / token
  numbers were **not** swept the way #5 swept Groq's - that is still open.
- A 7B model is weaker: on the ESXi case it wrote an attack chain with
  Execution / Defense Evasion / Discovery stages no finding supports.
- **Thinking models need `"think": false`** (`analysis._to_ollama`).
  qwen3.5 and gemma4 reason before answering and that reasoning counts
  against `num_predict`: gemma4:12b spent all 2400 tokens thinking and
  returned empty content (502, finish `length`) on both runs. The prompt's
  `/no_think` is a Qwen convention the others ignore. Non-thinking models
  accept the flag (checked on qwen2.5).

**Local model benchmark (2026-10-12, `tests/bench_llm.py`, 3 runs each,
thinking off).** gen_usecase's two files zipped into one case, graded
against tests/README.md's ground truth:

| model | ok | avg s | expected stages hit (of 6) | unsupported stages | invented ATT&CK ids |
|---|---|---|---|---|---|
| qwen2.5:7b-instruct (in use until 2026-10-14) | 3/3 | 21 | 2.0 | 5 | 3 |
| **qwen3.5:9b** | 3/3 | 54 | 3.0 | **0** | **0** |
| gemma4:e4b | 3/3 | 19 | **4.3** | 3 | 4 (T1021.001 RDP) |
| gemma4:12b-it-qat | 3/3 | 93 | 3.7 | 1 | 2 (T1073.003) |

All named the four planted entities every run and none put the benign
10.10.1.9 into the chain. qwen3.5:9b never invented a stage or a technique
*in these three runs* - but it overruns the 6-entry timeline cap (up to 13)
and used up to 2,164 of the 2,400 completion tokens. n=3 on one synthetic
case: a lead, not a verdict - see the re-run below.

**Switched to qwen3.5:9b on 2026-10-14** (`.env`: `OLLAMA_MODEL=qwen3.5:9b`,
`OLLAMA_MAX_COMPLETION_TOKENS=3000`, `OLLAMA_MAP_COMPLETION_TOKENS=1200`;
docker-compose's own defaults still say qwen2.5 / 2400 / 600). Measured
after the switch:
- **Re-run of the benchmark (3 more runs): 1 unsupported stage
  (Execution) and 5 invented ids** (T1076 - a deprecated RDP id -,
  T1552.004, T1059), all completions under 1,900 tokens. So over 6 runs
  qwen3.5 is clearly better on *stages* than qwen2.5 but not on technique
  ids. The likely cause is the schema itself: `"mitre": [... REQUIRED, infer
  from context if the underlying events didn't already have one]` asks the
  model to invent. **Fixed the same day (gotcha #37):** the schema now
  allows only the ids and stages the evidence carries, and the re-run gave
  0 unsupported stages, 0 invented ids and three byte-identical runs in
  33 s.
- Three real cases, single call: all `stop`, 1,282-1,488 tokens, 42-49 s,
  no unsupported stage; on ESXi it called 10.9.3.91 a legitimate internal
  host (source profiles at work); on the monsoon zip it called 10.8.1.50 an
  "external actor" (the RFC1918 soft spot of #5, still there).
- **Map-reduce needs the bigger map cap.** The Palo Alto case (1,516
  groups) runs 5 batches + 1 reduce. At the old 600 map tokens 3 of 5
  batches ended `length` and the final chain gained Collection / Defense
  Evasion; at 1,200 every batch ended `stop` (529-631 tokens each - just
  over 600) and the chain was Reconnaissance / C2 / Exfiltration. 154 s
  for the whole case.
- Case data no longer leaves the machine for the narrative - which also
  settles the confidentiality question NIST AI RMF GOVERN raises.

`.env` (gitignored) holds `LLM_PROVIDER`, `OLLAMA_MODEL`, and for the Groq
path `GROQ_API_KEY`, `GROQ_MODEL` (`qwen/qwen3.8-27b`) and optionally
`MAX_EVENTS_FOR_ANALYSIS` (15 - set by measurement, see the sweep table in
gotcha #5). Copy `.env.example` to start. `docker compose` auto-loads it for
`${VAR}` substitution in `docker-compose.yml`.

## Common commands

```bash
docker compose up -d --build --force-recreate      # rebuild + restart
                                                   # (also rebuilds the UI)
docker exec forensic-analyzer-forensic-analyzer-1 python tools/refresh_intel.py
docker exec forensic-analyzer-forensic-analyzer-1 python tools/backfill_custody.py   # dry run; --apply
docker exec forensic-analyzer-forensic-analyzer-1 python tools/migrate_to_customers.py   # dry run; --apply (gotcha #40)
python tools/build_measurement_doc.py   # docs/measurement-method-th.pdf (Thai), rule tables
                                        # read from the code - rebuild after changing a rule/level
docker exec -it forensic-analyzer-forensic-analyzer-1 \
    python tools/create_user.py add you@example.com --name "..." --role analyst
docker logs forensic-analyzer-forensic-analyzer-1 --tail 50

# read-only MCP server for an MCP client (gotcha #38); every call is logged
docker exec -i forensic-analyzer-forensic-analyzer-1 \
    python -m app.mcp_server --actor you@example.com

cd frontend && npm ci && npm run build   # UI only, straight into ../static
cd frontend && npm run dev               # hot reload, /api proxied to 8091

# dev container: app/ tools/ tests/ mounted, uvicorn --reload (~1 s after a save),
# its own store and port - never the 8091 data. Open 127.0.0.1:8092, not localhost.
# --build only after requirements.txt / Dockerfile change. Needs its own account.
docker compose -p forensic-dev -f docker-compose.yml -f docker-compose.dev.yml up -d --build
docker exec -it forensic-dev-forensic-analyzer-1 python tools/create_user.py add you@example.com --name "..."
docker exec -w /app forensic-dev-forensic-analyzer-1 python tests/check_mcp.py /tmp/mcp --repo /app
cd frontend && FA_API=http://127.0.0.1:8092 npm run dev   # UI hot reload against it

# every /api call needs a session cookie now
curl -s -c /tmp/fa.jar -H 'Content-Type: application/json' \
    -d '{"email":"you@example.com","password":"..."}' http://localhost:8091/api/auth/login
curl -s -b /tmp/fa.jar "http://localhost:8091/api/cases/{id}/events?limit=100&offset=0"
curl -s -b /tmp/fa.jar -X POST "http://localhost:8091/api/cases/{id}/analyze?force=true"

# poke a case's DuckDB directly
docker exec forensic-analyzer-forensic-analyzer-1 python -c "
import duckdb; con=duckdb.connect('/data/db/{case_id}.duckdb', read_only=True)
print(con.execute('SELECT rid, count(*) FROM findings GROUP BY rid').fetchall())"
```

Runs on host port **8091** (the older Wazuh-based `forensic-webapp` uses
8090 — don't collide if both are up). On Windows/git-bash, absolute
Unix-style paths in `docker exec`/`docker cp` need `MSYS_NO_PATHCONV=1`.

## Validating changes

`tests/gen_usecase.py` generates a synthetic attack scenario whose every rule hit is
known in advance (see `tests/README.md` for the expected counts). Run it
after touching `decode.py`, `rules.py`, or the ingest pipeline - it catches
both missed detections and false positives, and it is how the R2001 MITRE
mis-tag below was found.

Real JSON captures live in `tests/samples/` (Entra sign-ins from Splunk
attack_data, Apache-2.0, with a README of what each must produce);
`python tests/check_parity.py tests/samples` checks them (gotcha #39).

Two more checks, each for its own layer:
- **Narrative** - `python tests/bench_llm.py <scratch> qwen3.5:9b --runs 3`
  (needs Ollama on localhost:11434): grades the AI narrative against the
  same ground truth - expected stages, unsupported stages, invented ATT&CK
  ids, grounding warnings. Run it after touching `analysis.py`,
  `grounding.py` or anything that feeds the prompt; with the schema and
  seed in place the three runs should be byte-identical (gotcha #37).
- **MCP server** - `tests/check_mcp.py` (all 19 tools, pivots, refusals, access log), run in the container
  as its docstring shows, because the concurrent-writer check needs Linux
  `flock` (gotcha #38).
- **Job queue and manifests** - `tests/check_jobs.py` (45 checks, no DuckDB) and
  `tests/check_manifest_atomic.py` (gotcha #48); run in the container or on the host.
- **Finding workflow and Overview** - `tests/check_workflow.py <scratch> --repo /app`
  (~110 checks: threshold, ids, source events, related findings, the Findings page
  and its decision filter, every refusal and both close paths of the lifecycle API,
  Customers - open while a suggestion is not decided -, the Overview figures against
  the cases (undecided, the case a card opens, the whole-span trend, an account's
  computers and sources), a forged custody log); needs the container (`static/`).
  Run it in a throwaway container with `AUTH_DIR` on a scratch path - in the live
  one its test accounts land in the real `users.json`. Gotchas #49 / #50 / #73.
- **Authorisation** - `tests/check_authz.py [repo]` (ADR-3, gotcha #51, IAI-14): the permission
  table per role, every case route answering 403 exactly where `authz.can` says no, the Users
  routes, wrong-typed account changes refused; deleting a case and a customer (gotcha #74).
- **Projects** - `tests/check_projects.py [repo] [--scratch DIR]` (gotcha #75): a project required
  on upload, close / reopen and its gate, a Closed project refused for upload and merge, the
  Overview and Findings per project, the customer's project rows against each project's own
  Overview, rename / move / delete, the timeline and the joined graph across cases (empty while
  a suggestion is not decided, the rejected one left out once all are).
- **Customer isolation** - `tests/check_customer_isolation.py <scratch>
  --repo /app` (31 checks, gotchas #40/#41, and projects); run it in the container the same
  way as check_mcp. Run it after touching `storage.py`, any path helper or
  a route that lists or merges cases.
- **Log identification** - `tests/check_identify.py [--corpus]` (gotcha #53, branch
  IAI-92): each sample identified as its log source and no other, negatives
  unrecognised; `--corpus` adds the real customer files. No store, no network.
- **Behaviour profiles** - `tests/check_profiles.py [--repo DIR]` (gotcha #57): windows and their
  edges, ranks and the 20-address floor, n/a, bytes to public addresses; duckdb only.
- **Windows event logs** - `tests/check_windows.py <scratch> --repo /app [--evtx D:/logtest/windows]`
  (gotcha #60): event XML from the committed samples; with `--evtx` (lab folder outside the repo,
  copied into the container) every .evtx record counted against its chunk header and compared item
  by item with Windows' own `.ToXml()` rendering. Check Point Log Exporter: `tests/check_checkpoint_le.py`.
- **Detection accuracy** - `tests/gen_checkpoint_quarter.py <outdir>` (seeded): three months of
  Check Point Log Exporter records with attacks I1-I6 buried in an office's traffic and a
  `ground_truth.csv` for every non-benign row. Upload the zip, then score findings and the AI's
  advice per incident against the ground truth (gotchas #62, #64). In git since 2026-10-26; the
  scoring scripts are not.
- **Firewall rules** - `tests/check_firewall_rules.py` (gotcha #62): Palo Alto and Check Point -
  TRW, the measured line and the no-line case, each behaviour's non-events, service names where a
  log has no port, Detect as neither verdict, no product's rule on another product's rows.
- **Windows sign-in rules** - `tests/check_windows_rules.py <scratch>` (gotcha #65): one attempt per
  4625 + 4771 / 4776, then `tests/gen_windows_domain.py` (seeded: a domain's three months, incidents
  W1-W11 and look-alikes, `ground_truth.csv`) scored per incident - no plain or look-alike row may be
  flagged - and the real PurpleSharp spray; the lateral-movement and host rules (gotcha #66) on the same
  quarter and the real OTRF RDP / LSASS capture; story 5d (gotcha #68): W3 / W10 / W11, the CUSUM on a
  known series, 4768 0x6, the OTRF reconnect; one suggestion per behaviour (gotcha #69); story 5e
  (gotcha #70): a sprayer's own `...$`, a fleet-wide beacon; story 5f (gotcha #76): Defender detections
  and their outcome (medium only when remediated), a lone 1011, turned off / back on, tamper protection,
  exclusions vs a routine 5007; story 5g (gotcha #77): a deployment tool's two-day service not flagged - and with `--winevents "D:/logtest/window test/WinEvents.log"` the
  user's file (3 suggestions, nothing else).
- **The user's blind Windows quarter** - `D:\logtest\blind-windows` (`gen_windows_blind.py`, seed
  20260401, Kinnaree Textiles, K1-K15, `out/answer_key/`). **Its key has been read** (gotcha #70): it
  measures fixes now, not the rule set; a fair blind test needs another seed whose key nobody reads.
  Its `answer_key/*.csv` and `evidence/COLLECTION.txt` show as NEW in the `D:/logtest` parity run -
  not logs, never `--update` them.
- **AI review of suggestions** - `tests/check_triage.py <scratch>` (gotchas #64, #71): the facts, the
  schema's enums, the address and cross-citation checks, a model that cannot be reached; no cap (90
  suggestions), every rule first, retry then one by one, Review again, the background queue; a fake
  model, no Ollama - run it with `TRIAGE_ENABLED=1`.
- **Products and periods** - `tests/check_products.py <scratch>` (gotcha #61): product per row, a
  product rule on its rows only, periods and gaps, the n/a matrix, findings unchanged end to end.
- **Case flow** - `tests/check_case_flow.py <scratch>` (gotcha #52): step states (Attack timeline
  and Attack path wait for every decision; `/graph` empty until then, never a rejected group), and
  every step citing a standard marked read in `docs/standards/SOURCES.md`.

**`tests/check_parity.py` asserts it, so nobody has to read a table.** Until
2026-09-15 every ingest change was validated by uploading files, curling
`/api/cases` and eyeballing the counts - which is why the R2002/R2003 defect
of gotcha #23 sat in plain sight in the anchor numbers for months. The script
uploads, polls, and diffs per-file `rows / flagged / per-rule` counts against
`tests/baseline.json`, printing every drift and exiting non-zero:

```bash
export FA_EMAIL=you@example.com FA_PASSWORD=...          # an account, see Login
# uploads go to customer "Parity check" - FR-2.1 refuses a case without one
python tests/gen_usecase.py /tmp/usecase
python tests/check_parity.py /tmp/usecase                  # ground truth, ~5s
python tests/check_parity.py "D:/forensic system/Logtest"  # full corpus, ~3min
python tests/check_parity.py <dir> --update                # accept the change
```

stdlib only, so it runs without the app's dependencies. Three details worth
keeping, each of which was a bug in the checker before it was a feature:

- 0-byte files are reported as notes, not failures - the API rejects them
  with 400 by design.
- Results are keyed **name -> list of variants matched by md5**, because the
  corpus contains two different files both called `log_30_.csv`. Keying by
  name alone silently dropped one of them, so the first "PARITY OK" printed
  was one file short. **When a run claims everything matches, reconcile its
  totals against the previous number before believing it** - a 102-row
  discrepancy is how that was caught.
- `--update` **merges** and prints what it added, changed and left alone.
  The first version rewrote the file from whatever the run covered, so a
  `--update` pointed at one directory took the baseline from 70 entries to
  67 and silently deleted the ground-truth pair and the Check Point
  benchmark. A tool whose job is catching silent drift must not be able to
  cause it; if `--update` ever reports 0 left untouched on a partial run,
  something is wrong.

The Check Point benchmark is in the baseline but is not under `Logtest`;
check it with `python tests/check_parity.py D:/logtest` (gotcha #43).
Since W2 that run also covers `D:/logtest/windows` (gotcha #60): `.evtx` is a parity suffix,
and the 278 EVTX-ATTACK-SAMPLES files (GPL-3.0, so outside the repo) plus two exports from this
PC are in the baseline - 279 names, 127,519 rows, 0 flagged at W2, before any Windows rule. That
folder is gone; since 2026-10-29 the samples are re-cloned at `D:/logtest/internet/evtx-attack-samples`
beside OTRF's host datasets (`otrf/`, zips - no parity suffix), and 5 of them flag now, as the Windows
rules intend (gotcha #78). The clone's stray `.log` / `.txt` / `.json` files
came in with them. W3 added `splunk-text/` (attack_data's account_lockout, 9,245 rows, R2000 24 /
R2006 177 / R2008 3, and 54 files of the lab's Security events rendered in Splunk's layout by
`tests/make_splunk_text.ps1`) and, in `tests/samples`, `windows-security.log` 0 -> 4 rows plus
`windows-security-text-spray.log` (162 rows, R2000 20 / R2009 20 - since 2026-10-26 WIN-BRUTE-2
40, and `windows-security-xml-spray.log` 50 -> WIN-BRUTE-2 100: each attempt is a 4625 + a 4776,
both flagged now, gotcha #65; the lab's Windows entries were not re-run - the folder is gone;
`otrf/rdp_interactive_taskmanager_lsass_dump.json` 0 -> WIN-LAT-3 1, gotcha #66, then WIN-LAT-1 0 -> 8 -
the RDP reconnect, gotcha #68).
W4 added `winlogbeat/` (Elastic's 105 test `.evtx` and the 113 JSON files Winlogbeat wrote from
them) and `nxlog/` (7 OTRF datasets, 2 of them flat JSON kept as no_reader) - 225 entries, 0
flagged - and `tests/samples/otrf/` (283 NXLog records, 0 flagged).

**Real-world benchmark.** A Check Point export was analysed alongside the
human SOC report written from the same data ("Firewall Port Scanning &
Implied Rule Bypass", Jun 2026). The source file is **not** under
`d:\forensic system\Logtest` and searching there for it (by name, or by
grepping for `171.6.30.201`) finds nothing - it is at
`D:/logtest/Logs_Jun_24__2026_11_09_44_102_AM_Logs_Table.csv` (since the
store reset of 2026-10-14 the only copy; it used to be in the store's
`raw/` too). The benchmark is reproducible; don't conclude it is lost.

Every figure in that report reproduced
exactly: 45,209 rows, 905 distinct services, 22,617 hits on the top service,
one source IP (171.6.30.201), 42,071 drops + 135 IPS prevents + 17 rejects,
2,978 accepted, and the accepted breakdown (https 1,022 / FW1_ica_services
1,005 / http 910). `R2004` independently flagged exactly those 2,978 rows —
rediscovering the report's central finding (Check Point's Implied Rule
overriding an explicit drop) from a log-source-neutral rule that knows nothing
about Check Point.

What the tool could not produce, and a human analyst did: the OSINT pivot
(the source is a compromised MikroTik RouterOS v6.45.3 on residential 3BB
broadband, i.e. a botnet node), Check Point's own mechanism behind the bypass, and
the reading that Check Point's "Key Install" action is an IKE Phase 1
handshake rather than a successful compromise. The system quantifies and
localises; interpretation still needs an analyst.

## Extending the rule engine

**A new rule is a product rule now** (`specs/per_product_rules.md`). Firewall products share
`rules_firewall.build(product, prefix, service, unit)` - vertical / horizontal scan, allowed after
probing, beaconing, feed matches - and add their own in `rules_<product>.py` (Palo Alto's PAN-DB
category, Check Point's Threat Prevention verdict); `rules.py` appends each module's `RULES`,
`PREPARE` (lines), `LEVEL`, `LABELS`, `FAMILY` (confidence family = the generic twin's),
`EQUIVALENT` (the generic rule of the same behaviour, for escalations and VERIS) and
`SUPERSEDES` (generic rules that stop on its rows). A product rule reads `product_events`; a
line-drawing rule binds `$above` / `$minimum` / `$note` (`lines.evidence_line`, `lines.trw`); ids
follow `RULE_ID_PATTERN`. Every rule needs its behaviour's document read (D14), a `RULE_META`
entry, a place in `areas.py`, and a case in `tests/check_firewall_rules.py`.

The generic rules live in `rules.py` as `(rule_id, SQL)` pairs — each is one
`INSERT INTO findings SELECT ...` over `raw_events`. Correlation rules join
against a `GROUP BY ... HAVING` subquery. Conventions: `R1xxx` single-event
host/auth, `R2xxx` correlation, `R3xxx` network/firewall. Insert `lvl` as
`NULL`, declare the rule's Sigma level in `RULE_LEVEL` (gotcha #26), and
always populate `mitre`. Two exceptions: a rule may write a *lower* weight when the
event itself says so (`apply_rules` keeps `least(written, declared)` - WIN-MAL-2 when
Defender remediated, WIN-HOST-3's blocked change; gotcha #76), and a product's own verdict
that names no attacker behaviour carries no technique (CP-MAL-2's Anti-Virus, WIN-MAL-2).

Adding a rule needs no engine changes — append to `RULES` and it runs. Add a
`RULE_LEVEL` entry (a rule without one defaults to `low`) and a
matching short entry to `RULE_LABELS` too: that is what names the rule's
edges in the attack graph (`descr` is a full sentence with IPs in it, far too
long for an edge). A rule with no label falls back to its bare id.

**And a `RULE_META` entry in `rule_meta.py`** (gotcha #29): a fresh UUID v4,
title, Sigma `status`, the ATT&CK techniques its SQL writes, logsource
category, false positives and the ADS sections. `python
tests/check_rule_meta.py` fails until the metadata exists and its
techniques match the SQL - run it with the parity check.

Current set: **Palo Alto** PAN-SCAN-1..3, PAN-MAL-1..2, PAN-INTEL-1..3 · **Check Point**
CP-SCAN-1..3, CP-MAL-1..2, CP-INTEL-1..3 (gotcha #62) · **Windows** WIN-BRUTE-1..3,
WIN-AUTH-1 (gotcha #65), WIN-LAT-1..3, WIN-HOST-1..2 (gotcha #66), WIN-MAL-1, WIN-INTEL-1..2
(gotcha #67), WIN-BRUTE-4, WIN-LAT-4 (gotcha #68), WIN-MAL-2 Defender detection, WIN-HOST-3 Defender
turned off (gotcha #76) · **generic** (every other product's rows; superseded on Palo Alto /
Check Point rows, and the sign-in ones on Windows rows, gotcha #63): R2000 brute-force burst · R2002
port scan · R2003 service sweep · R2004 policy gap · R2005 spray (many sources, one account) ·
R2006 multi-source logins within an hour · R2007 beaconing · R2008 login after brute force ·
R2009 measured spray · R3001 large transfer (everywhere - no data-transfer rule yet) · R3002
malware category · R3003-R3005 threat-intel matches. R1000-R1004, R2001, R3000 and R3006 left
the set on 2026-10-20 (gotcha #56).

Three things worth copying when writing new correlation rules:
- **Get the MITRE tag right — it propagates.** `R2001` was originally tagged
  `T1110` (Brute Force) when it actually detects repeated *blocked*
  connections. The AI layer dutifully narrated port-scan denies as
  "brute-force attempts". Retagging it `T1595` (Active Scanning) fixed the
  narrative. The AI trusts the rule engine's labels.
- **Guard aggregates against ordinary behaviour.** `R2004` ("allowed despite
  many blocks") would fire on any user who hits a few blocked sites, so it
  requires >=20 denies *and* denies >= 3x allows. Test new correlation rules
  against `tests/gen_usecase.py`, whose benign rows exist precisely to catch
  this.
- **Write the outer `WHERE` too.** A correlation rule is a join against a
  `GROUP BY ... HAVING` subquery, and it is easy to guard the *threshold* and
  forget that without a `WHERE` on the outer query every row belonging to a
  matching entity gets flagged - its benign rows included. That is exactly
  how R2002/R2003 came to flag 18,972 allowed connections as a port scan
  (gotcha #23). Ask of every new rule: *which rows are the evidence?* and
  filter to those, not just to the entity.

## Scale notes

Verified on real customer data: 36 Palo Alto CSVs, 424,948 rows, 123,861
findings — all 36 ingested in **~7 seconds** total (60MB of DuckDB vs 289MB
of source files). The largest single file (45MB / 65,534 rows) takes ~1s.
Upload returns in ~0.25s regardless of file size.

For reference, the same workload took 3.5 minutes per large file before the
DuckDB bulk-load fix, and ~38s total while decode was still Python-per-row.

Any change to ingest or rules should be checked for **parity**, and the
baseline to check against is `tests/baseline.json`, not this file - per-file
`rows / flagged / per-rule` counts, **669 entries** since 2026-10-28 (re-taken on the dev
container for the product rules - gotcha #63; the Elastic PAN-OS samples added; the user's
WinEvents.log, 4 flagged - gotcha #76), asserted by
`tests/check_parity.py`. Run it against the dev container (`--url http://127.0.0.1:8092`) with
the AI review off there (gotcha #64) - with it on, a hundred uploads take hours. A silent drop to 0 findings
is exactly the failure mode gotcha #2 describes, and a *plausible* wrong
finding is gotcha #22.

The four anchors still worth knowing by heart, as of 2026-09-15:
`log_13_.csv` 65534/11324 · `src10-8-3-215.csv` 25579/**18888** ·
`log_22_.csv` 20530/14832 · `auth.log` 776/329. Two of those moved from the
numbers recorded before that date and both moves are deliberate:
`src10-8-3-215.csv` 25579 → 18888 from the R2002/R2003 deny restriction
(gotcha #23), `log_22_.csv` 14514 → 14838 from `R3004` (+324), the
threat-intel rule of gotcha #17, which postdates the original figure -
and since the feed refresh of 2026-10-14 it is 14832 (R3004 318).

The corpus behind the baseline: **98 cases / 988,818 rows** from
`d:\forensic system\Logtest`, plus the Check Point export (in `raw/`, see
*Real-world benchmark*) and the two `gen_usecase` files. `Logtest` holds 108
log-shaped files; the other 10 are 0-byte and the API rejects them with 400,
and 6 more are not logs at all (email headers, a placeholder, and two
artefacts the ransomware itself dropped) which ingest as 0 findings. About a
third of the corpus is duplicated content: `Data log Firewall paloalto/` (36
files) and `Virus Dec28-2025/` (33) overlap, several byte-identical, and
`log(30).csv` exists in two different versions under one name - so
**dedupe before quoting a corpus total**, and expect 98 cases from 92 usable
files. As of 2026-09-28 those folders sit under
`Logtest/2026-01/2026 SUMMITGROUP info Virus/` (with `log esxi 131/log/`
for `auth.log`), and the Azure sign-in export is
`Logtest/2026-02/KM23 ITSupport_InteractiveSignIns_2026-06-04_2026-06-11.csv`.

**Without Docker** the pipeline still runs on the host: `pip install duckdb`,
set `DATA_DIR` to a scratch folder, then `storage.create_company(...)` once
(a case needs a customer - gotcha #40), `storage.create_case(..., company_id=)` +
`pipeline.process_case(case_id, Path(file), kind)` per file. That
reproduces the baseline anchors exactly except the intel rules
(`R3003`-`R3006`), because `DATA_DIR/intel/` is empty - so `log_22_.csv`
gives 14514, not 14832. It is how gotcha #24 was measured while the Docker
daemon was down.

Zero-finding files are expected for ESXi system logs (not auth logs) and for
Palo Alto exports whose every row is `allow`; check with the gotcha #7 query
before assuming a mapping bug. The auth-on-CSV work of gotcha #11 was
validated this way (92 of 93 files byte-identical, the 93rd being the Azure
sign-in export going 0 → 79 findings), and it is what caught the Exchange
false positive.

**Timing claims need more than one run** (gotcha #18). Repeat runs of the
unchanged corpus took 52s, 60s, 67s and 74s - that spread is host I/O for a
hundred sequential uploads, not the pipeline. Re-processing all 211 cases
already in the store, which skips upload entirely, takes **53s**.

**Validating costs store space.** Since 2026-10-22 an admin or a manager can delete a case
(`DELETE /api/cases/{id}`, specs/case_delete.md); duplicates are still pruned with the tool below.
`check_parity.py` uploads the whole corpus on every run and a re-process
replaces nothing, so a handful of validation runs took one store from ~99 to
**619 cases** - 547 of them byte-identical re-uploads of 71 files, 4.8 GB on
disk and a dashboard nobody can read. `tools/prune_cases.py` is the bulk cleanup, dry-run by
default:

```bash
docker exec forensic-analyzer-forensic-analyzer-1 python tools/prune_cases.py
docker exec forensic-analyzer-forensic-analyzer-1 python tools/prune_cases.py --apply --keep-reviewed
```

It groups cases by **md5 of the preserved raw file**, not by filename - the
corpus has two different exports both called `log_30_.csv` - and keeps one
per group, preferring a case with analyst decisions, then one with a cached
analysis, then the newest. **That order matters and was learned the hard
way**: keeping merely the newest meant keeping a fresh validation duplicate
and deleting the older case that held the AI analysis, which destroyed 10
cached analyses (each a Groq call under a ~1/minute budget). A duplicate has
identical content by definition, so the copy worth keeping is the one with
work attached. Always run it without `--apply` first, and pass
`--keep-reviewed` unless you mean to delete audit logs - a case's
`review/{case_id}.jsonl` goes with it.

Remaining known ceiling: `.log`/JSON still decode in Python (~15k rows/sec).
Only worth moving to SQL `regexp_extract` if large syslog files show up;
CSV (the bulk of real data) already bypasses Python entirely. The 10 GB
upload requirement makes this real: measured on the host, CSV ran at ~77 MB/s
(45 MB in 0.59s, so ~2-3 min for 10 GB) and the Python path at ~21 MB/s on a
28 MB file (~8 min or more for 10 GB). Neither was measured on a GB-sized
file.

~~Known, not investigated: the ESXi `auth.log` has no year in its timestamps~~ -
**wrong, corrected 2026-10-14 (gotcha #42):** every line carries a full ISO
8601 UTC timestamp, and the 2014-07-02 minimum is real - 138 monthly
`vpxuser` password rotations by vCenter reach back to the host's install.
