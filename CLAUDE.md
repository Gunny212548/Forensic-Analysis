# CLAUDE.md

Guidance for Claude Code when working in this repo.

## What this is

A standalone forensic log analysis tool — **no Wazuh dependency**. Upload any
log file (syslog/auth.log style text, CSV firewall exports, JSON), the app's
own decoder + rule engine extracts structured fields and flags
security-relevant events with MITRE ATT&CK technique IDs. The attack graph
is then built straight from those findings in SQL, and an LLM (a local Ollama
model since 2026-10-12; Groq before) writes the
narrative around it — case summary, attack chain, timeline,
recommendations.

**Where it is going (the user, 2026-10-20 - read this first; gotcha #54).**
The purpose is *forensic reconstruction from log files*, not SIEM alert grading:
identify what each log is, put every event on one timeline, let the analyst
confirm the attack events (the system and the AI only suggest), then build the
attack timeline, the attack path and a graph of what the attacker did - which
command, from which host, to which host. Flow: **Ingest -> Timeline -> Attack
events -> Attack timeline -> Attack path / graph -> Report**; the Respond step
(lifecycle, MTTC) is to be removed. **The 20 in-house rules stay** and SigmaHQ
rules are added beside them (revision 5 - revision 4 had retired the in-house
rules; reversed the same day after ADR-006 measured the cost). **Every step must cite a standard that was
actually read** (`docs/standards/SOURCES.md`). Design: `specs/case_flow_design.md`
revisions 1-4 on branch `IAI-92-identify-logsource`; most of what follows still
describes the code before that direction.

Formats exercised against real data so far: VMware ESXi `auth.log`,
Palo Alto CSV exports, Check Point SmartLog CSV exports, Entra ID sign-in
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
         (`members`, `skipped_members`); raw_events has no source column.
  progress → manifest `progress: {stage, pct, estimated}` about once a
         second (FR-2.5; ingest 0-90, intel 90-92, rules 92-100). Measured
         for line logs/JSON (bytes read), zip members and rules. The CSV fast
         path is ONE DuckDB statement and 1.1.3 had no query_progress(), so
         its share is an elapsed-time estimate at ~60 MB/s, held at 95% of
         the file, flagged `estimated` (the UI prefixes "~"). Manifests are
         now written tmp-then-rename, since they are rewritten while polled.
  then → rules.apply_rules() = SQL INSERT ... SELECT per rule
       → status=ready (or failed + error/traceback on the manifest)

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
GET  /api/companies/{id}/projects            the customer's projects (storage.py)
GET  /api/cases/{id}/events?limit=&offset=   paginated SQL
GET  /api/cases/{id}/findings                collapsed findings + computed
                                             confidence + review status + FD id +
                                             related findings (gotcha #49)
GET  /api/cases/{id}/findings/events?key=    the events behind one finding, each
                                             with its source file (gotcha #49)
GET  /api/findings                           the Findings page: workflow findings
                                             across cases, counts, open_count;
                                             status=open = not Resolved (#51)
POST /api/cases/{id}/review                  one analyst decision (appended)
GET  /api/cases/{id}/review-log              full decision history
GET  /api/cases/{id}/custody                 evidence digest + chain of custody,
                                             hash chain checked on read
POST /api/cases/{id}/verify                  re-hash the raw file now, log it
POST /api/cases/{id}/lifecycle               one status change / assignment on a
                                             tracked finding (lifecycle.py)
GET  /api/cases/{id}/stix                    STIX 2.1 bundle download; ready only
GET  /api/cases/{id}/veris                   VERIS 1.4 record download; 409 if no
                                             high/critical finding
GET  /api/cases/{id}/attack-layer            ATT&CK Navigator layer (format 4.5)
                                             download; 409 unless ready
GET  /api/rules[/{rid}]                      rule metadata: Sigma fields + ADS
                                             documentation (rule_meta.py)
POST /api/cases/{id}/analyze                 db.build_graph (SQL) for the
                                             graph + SQL top-N distinct → the
                                             LLM (Ollama now) for the narrative,
                                             decoded inside a per-case JSON
                                             schema + grounding check (#37)
MCP (stdio, read-only)                       app/mcp_server.py - 19 tools over the
                                             same views; every call hash-chain
                                             logged to mcp/access.jsonl (#38);
                                             never assigns FD ids (#51)
GET  /api/overview                           KPIs, MTTC, detection areas, attention,
                                             findings per day, top entities,
                                             urgent findings, activity (services/
                                             overview.py; per-case facts cached
                                             on a fingerprint of DuckDB, review
                                             log, custody log and id registry;
                                             gotchas #50, #51)
```

**The Overview was redesigned on 2026-10-19 (gotcha #50)** - an attention banner,
a KPI strip, six detection-area cards, findings per day, top affected, urgent
findings and recent activity, in the light palette; the status workflow it needed
exists since Sprint 3 (gotcha #49). The case table is no longer on it. No figure is a
placeholder. "Top affected"
ranks by accumulated risk score, not by case count: ranked by count, the
benign admin account seen in every seeded case came out first (gotcha #16
again). **The page always says whose data it shows (2026-10-15, the
user's requirement):** the header names the customer, or every customer
when unscoped; each top-affected row and activity line carries its
customer; and top-affected is aggregated *per customer* - the same address
in two customers' cases is two hosts, and used to add up into one row.
A technique card stays *one* card and lists every customer it was seen in:
the same technique is the same behaviour whoever it happened to.

Storage layout under `DATA_DIR` (`/data`) - **one store per customer**
since 2026-10-14 (gotcha #40). `customers/<company_id>/` holds everything
of that customer and nothing of anyone else's: `customer.json` the customer
record · `projects/` its projects, one JSON each · `cases/` manifests (small JSON) · `db/` per-case DuckDB · `raw/`
original uploaded files, compressed ones kept compressed (audit trail) ·
`analysis/` cached AI output · `jobs/` one file per unfinished case (gotcha #48) ·
`findings/ids.jsonl` the hash-chained FD-id registry (gotcha #49) · `review/` append-only analyst decision logs,
one JSONL per case (see gotcha #19) · `custody/` hash-chained
chain-of-custody logs, one JSONL per case (gotcha #28). Where older gotchas
say `review/{case_id}.jsonl`, `raw/<case_id>.csv` and so on, read them as
inside the case's customer store. Shared, because none of it is customer
data: `intel/` threat-intel feed files (see gotcha #17) · `tmp/` staging ·
`mcp/access.jsonl` hash-chained log of every MCP tool call (gotcha #38).
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
- `role` is a stored display label only. Roles are undefined until IAI-14,
  so nothing is permitted or denied by it.
- **The review actor comes from the session, not the request body.** It used
  to be whatever name the browser sent (typed once, kept in localStorage as
  `analyst-name`), which let any client write any name into an audit log
  (FR-7.6). Decisions recorded since carry the account's email; older ones
  keep the name that was typed.

**Why DuckDB and not Elasticsearch:** this is batch forensic analysis for one
analyst, not a real-time multi-tenant SIEM. DuckDB is embedded (no server to
operate), columnar (a 65k-row Palo Alto CSV costs a few MB), and its
GROUP BY/HAVING is exactly what the correlation rules need. An ES cluster
would be heavy operational baggage for zero benefit at this scale.

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
  pages/               Overview (#/dashboard) · Upload · Findings · FindingDetail
                       · CaseView (Reports / Attack Graph / Timeline of one case)
                       · Customers · CustomerDetail · Login · Placeholder
                       (menu pages whose story is not built yet)
  components/          Sidebar (app shell, FR-0) · Workspace (case tabs)
                       CasePicker (a case page opened from the menu)
                       EventsTable · ReviewPanel · Lifecycle (status workflow)
                       RuleCard (Sigma/ADS) · Evidence (custody tab)
                       Mapping (log source note) · Veris
                       AttackGraph · analysis.jsx (chain/timeline/risk/meta,
                       grounding warnings)
                       common.jsx (severity pill, status badge, MITRE tags)
```

It replaced a hand-written 1,212-line `static/index.html`, whose URLs were
kept unchanged so pasted case links survived the rewrite. Neither of its
localStorage keys is read any more: `analyst-name` (the reviewer is the
signed-in account, see *Login*) and `fa_recent_uploads` (since IAI-28 the
Upload page's "My recent uploads" are the cases whose `evidence.recorded_by`
is the signed-in account, from `GET /api/cases` - they follow the analyst
across browsers, and a case that no longer exists cannot linger). The
original is preserved at `legacy/index.html.orig` — this repo is not a git
checkout, so that copy is the only history it has.

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
`#EEF0F3` page, white panels, amber `#B36B00` as the only action colour), and
the type is IBM Plex Sans / Plex Sans Thai / Plex Mono, bundled via
`@fontsource` so the nothing-fetched-at-runtime rule above still holds.
Plex Sans has no Thai glyphs, and most UI text is Thai, which is why the Thai
cut is there too. Severity, review-status and job colours kept their meanings
and were only re-mapped onto the Figma tokens. Exception: the attack graph
keeps a dark canvas (`--graph-bg`), because the colours in `AttackGraph.jsx`
are drawn for it; it gets the Figma treatment in its own story (IAI-61). The
whole UI is in English, as the Figma is (since 2026-10-12, see *Decisions*).

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
- #20 Confidence counts rule *families*, not ids; `timezone-unconfirmed` is tested on the source text, never on `ts`.
- #30 Confidence is an Admiralty grade (reliability letter + credibility number).
- #31 The review log is hash-chained; old unchained decisions are sealed, not rewritten.
- #33 Finding lifecycle Open -> Investigating -> Contained -> Resolved; only Sigma high/critical enter it.
- #49 FD ids per customer per year, written before `ready`; source events; related findings via pivot hosts; the Findings page.
- #50 The Overview redesign, and the designs the user rejected - **do not re-propose them**.
- #51 `#/result` retired (Reports / Attack Graph / Timeline / finding page); Sprint 3 review fixes; ADR-3/4; branches and worktrees; testing in a container; scripted-edit traps.
- #52 The case page is six steps at `#/case/<id>/<step>` (IAI-89); `GET /flow` computes each step's state on the server and names its standards; old case links redirect. `sprint/4` merges Sprint 3's two branches.

**Evidence, storage, jobs and access** (`custody.py`, `storage.py`, `jobs.py`, `auth.py`, `mcp_server.py`)
- #28 Evidence is SHA-256 hashed on arrival and re-hashed before every run; custody log hash-chained.
- #38 Read-only MCP server over stdio; every call hash-chain logged; no write tool, no free SQL, no port.
- #40 One store per customer under `customers/<id>/`; `case_dir()` is the only answer to "where is this case"; cross-customer merge is 409.
- #41 Login accounts live in `AUTH_DIR`, apart from customer data; docker-compose deliberately does not set it.
- #47 Sign-in throttled per account (not per address), audit-logged, and bound to the password hash.
- #48 Work is queued, durable and bounded (`jobs.py`); manifests are written atomically. **One process only.**

**AI narrative** (`analysis.py`, `llm.py`, `grounding.py`, `veris.py`)
- #5 Groq's output-token limits and the measured sweeps (events 15, max_tokens 950); schema key order is the priority list. Groq only - not the local model.
- #10 The attack graph is SQL (`db.build_graph()`), not AI - don't hand it back to the model.
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
  logout, English per the Figma. Role is a label until IAI-14 (RBAC, not yet
  in any sprint) defines roles.
- **IAI-22/23/25/27 upload** - customer required, 10 GB after
  decompression, 2.5x disk check, `.gz` streamed, `.zip` → one case,
  separate upload / processing percentages.
- **IAI-20 case list** - was the table on the Overview; since 2026-10-19 the Overview has
  no case table (gotcha #50) and cases are reached from Customers or Findings. The Jira
  story still says Overview.
- **IAI-18/19 Customers** - a customer is added on the Upload page only
  (see *Decisions*); the Customers page is read-only and shows, per
  customer, open cases of total / closed /
  highest open severity / last activity. FR-6.1 defines "open" by finding
  status: since Sprint 3 (IAI-79, gotcha #49) a case is open while a high or
  critical finding in it is not Resolved. Cases without a customer (pre-FR-2.1) are a "No customer" row
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
  the customer, like customers); **optional** - old cases, scripts and
  uploads without one are "No project". Stored in the customer's own store
  (`customers/<id>/projects/<pj-id>.json`), so a project can only hold that
  customer's cases: an upload naming another customer's project id is 409
  and creates nothing. A merge keeps the project only if every source is
  in it. Shown on the customer profile (Projects panel + a Project column),
  on its own page `#/customers/<id>/projects/<pj-id>`, on the case header
  and under the customer in the Overview / recent-uploads tables. Not yet:
  moving a case between projects, renaming / deleting a project, a project
  status.
- Not yet: **IAI-24 resumable chunked
  upload** (Sprint 6). The upload is one request, so a dropped connection
  restarts a 10 GB file from zero.

Pages whose story has not come up render `pages/Placeholder.jsx` and appear
dimmed in the menu (`ready: false` in `components/Sidebar.jsx`). Flip the flag
when a page is built. Timeline, Attack Graph and Reports were flipped when `#/result`
was retired (gotcha #51); ATT&CK Map and Settings are still placeholders.

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
  is read-only, although the Figma gives it an "Add customer" button. The
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
- **Finding lifecycle (FR-4.1, 4.5, 4.7, 4.8).** The Figma has status only
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
  14 Enterprise tactics.
- **Timeline "last 24h" is always empty:** uploaded events are months old
  (Dec 2025 - Jun 2026 in the corpus). Timelines use the case's event-time
  range; MTTC and the per-day charts use finding *creation* time.
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
  (~100 checks: threshold, ids, source events, related findings, the Findings page,
  every refusal and both close paths, Customers, the Overview figures, a forged
  custody log); needs the container (`static/`). Gotcha #49 / #50.
- **Authorisation seam** - `tests/check_authz.py [repo]` (ADR-3, gotcha #51): allows
  everything today, and a denial becomes a 403.
- **Customer isolation** - `tests/check_customer_isolation.py <scratch>
  --repo /app` (31 checks, gotchas #40/#41, and projects); run it in the container the same
  way as check_mcp. Run it after touching `storage.py`, any path helper or
  a route that lists or merges cases.
- **Log identification** - `tests/check_identify.py [--corpus]` (gotcha #53, branch
  IAI-92): each sample identified as its log source and no other, negatives
  unrecognised; `--corpus` adds the real customer files. No store, no network.
- **Behaviour profiles** - `tests/check_profiles.py [--repo DIR]` (gotcha #57): windows and their
  edges, ranks and the 20-address floor, n/a, bytes to public addresses; duckdb only.
- **Case flow** - `tests/check_case_flow.py <scratch>` (gotcha #52): step states, and
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

Rules live in `rules.py` as `(rule_id, SQL)` pairs — each is one
`INSERT INTO findings SELECT ...` over `raw_events`. Correlation rules join
against a `GROUP BY ... HAVING` subquery. Conventions: `R1xxx` single-event
host/auth, `R2xxx` correlation, `R3xxx` network/firewall. Insert `lvl` as
`NULL`, declare the rule's Sigma level in `RULE_LEVEL` (gotcha #26), and
always populate `mitre`.

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

Current set: R1000-R1004 (SSH auth failed/success/invalid user/connection,
password change) · R2000 brute-force burst · R2001 repeated blocks ·
R2002 port scan · R2003 service sweep (both deny-restricted, gotcha #23) ·
R2004 policy gap ·
R3000 high-risk app allowed · R3001 large transfer · R3002 malware category ·
R2005 password spray (many sources, one account) · R2006 multi-source logins
within an hour · R2007 beaconing (low-jitter egress intervals) ·
R3003/R3004 threat-intel match on destination / source (allowed) ·
R3005/R3006 the same matches on blocked traffic (medium / informational).

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
`rows / flagged / per-rule` counts for **75 files, 642,028 rows, 176,656
flagged** (IAI-30: `log_8_-01.txt` read correctly, gotcha #46) (2026-10-14: +4 JSON files of gotcha #39, R3004 re-taken on the
refreshed feeds - gotcha #17), asserted by `tests/check_parity.py`. A silent drop to 0 findings
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

**Validating costs store space, and nothing in the app deletes a case.**
`check_parity.py` uploads the whole corpus on every run and a re-process
replaces nothing, so a handful of validation runs took one store from ~99 to
**619 cases** - 547 of them byte-identical re-uploads of 71 files, 4.8 GB on
disk and a dashboard nobody can read. There is no DELETE endpoint;
`tools/prune_cases.py` is the cleanup, dry-run by default:

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
