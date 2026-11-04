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
#65-#70, #77, #78, `specs/windows_rules.md` stories 5a-5g) and Microsoft Defender's own verdicts (gotcha #76,
`specs/windows_defender_rules.md` story 5f - a product's verdict is an in-house rule, any other single
event is SigmaHQ's). **SigmaHQ's Windows rules run beside ours since 2026-10-29** (story 6,
`specs/sigma_windows.md`, gotcha #79): a pinned commit converted at image build, high / critical as
suggestions naming their author (DRL 1.1), the rest as marks on the timeline. The generic R-rules
still run on every other product's rows. A suggestion is keyed on the entity its rule decided on (gotcha #69). **The AI
explains every suggestion and never decides** (gotcha #72), **no cap** - in the background once the case is ready (gotchas #64,
#71; the user, 2026-10-26: "ทุก Finding ที่เจอต้องได้รับการ review จาก AI"). **Every step must cite a
standard that was actually read** (`docs/standards/SOURCES.md`). Design: `specs/case_flow_design.md`
(on `main` since IAI-92 was merged; the case page is its six steps, gotcha #52).

Formats exercised against real data so far: VMware ESXi `auth.log`,
Palo Alto CSV exports, Check Point SmartLog CSV exports, Check Point Log Exporter
records in a ManageEngine EventLog Analyzer export (gotcha #59), Windows Security and
Sysmon event XML, .evtx, Splunk WinEventLog text and Winlogbeat / NXLog JSON (lab captures, gotcha #60), Entra ID sign-in
CSV exports and their Azure Monitor JSON export (gotcha #39). Every file is
identified before it is read (gotcha #53, IAI-92, merged): a documented
format is read through its profile, anything else is kept as evidence and not
analysed - **nothing is guessed** (gotcha #7 shows what guessing columns cost).
A manifest from before IAI-92 can still say its columns were guessed.

It started as a spinoff of a separate project (`D:\Wazuh\wazuh-docker`'s
`forensic-webapp`, which fed uploaded logs through a real Wazuh manager).
That hit a hard limit: Wazuh has no decoder for arbitrary CSV exports, and
even for formats it does support, real-world testing found it silently
*missed* genuine attack events this project's own rule engine caught.


## Where things live

```
app/              FastAPI app - main.py (session middleware, static mount), config.py,
                  routers/ (one per area: auth, upload, cases, companies, findings,
                  overview, report, rules, users), services/ (pipeline, identify,
                  logsources, decode, parsers, winevent, rules + rules_<product>,
                  sigma, lines, db, triage, analysis, report, storage, jobs, ...),
                  data/windows (Windows message templates), mcp_server.py
frontend/         Vite + React source; `npm run build` writes static/ (generated)
tests/            check_*.py - one per layer; gen_*.py - seeded synthetic data with
                  ground truth; bench_*.py - the local model; baseline.json - parity;
                  samples/ - small real captures with their licences
tools/            operator scripts: create_user, refresh_intel, prune_cases,
                  backfill_custody, migrate_to_customers, sigma_build (image build),
                  build_measurement_doc, export_win_templates.ps1
docs/             gotchas/NN-*.md (one per gotcha), adr/, standards/ (SOURCES.md
                  and the documents read), STANDARDS.md (pipeline step -> standard)
specs/            one design per story, with its numbered decisions (Q.., D..);
                  spike-sigma/ holds the SigmaHQ spike's scripts (ADR-006)
figma-export/     the SENTRY-IR screens (SVG, text outlined)
.claude/agents/   subagents - each names the skills it preloads
.claude/skills/   project skills: the detail this file points to (below)
```

Not in git, on this PC only: `.env`, `static/`, `logtest/` (the Lotus Freight Check Point
quarter, `tests/gen_checkpoint_quarter.py logtest` rebuilds it byte for byte), the FR and
backlog PDFs, `.archify/`. Test corpora live outside the repo: `D:/forensic system/Logtest`,
`D:/logtest`, `D:/mockup-logs`. **Paths are not moved to tidy up**: 83 gotchas, the specs,
the tests and commit messages cite them.

**Project skills** (`.claude/skills/<name>/SKILL.md`, loaded when the task needs them). The
rules stay in this file; the measurements, tables and how-tos are in the skills:

| skill | load before |
|---|---|
| `case-api` | adding or changing a route, a manifest key, login / roles / Google sign-in |
| `frontend-ui` | any change under `frontend/` - the Overview's levels, look, tokens, attack graph |
| `add-detection-rule` | writing or changing a rule (product, generic or a SigmaHQ pin) |
| `validate-changes` | running tests, saying nothing regressed, updating the baseline, quoting a corpus figure |
| `local-llm` | the Ollama model, its settings, cost on this PC, the benchmark |
| `sentry-ir-console` | a Jira story, the Figma, a product decision's detail |

**Subagents** (`.claude/agents/`, only when the user asks for one): code-analyst
(read-only investigation), code-writer, code-reviewer, decoder-doctor (log sources,
mapping, "0 findings"), rule-engineer, parity-checker, prompt-tuner (the prompts
`analysis.py` / `triage.py` / the report summary send), frontend-dev, doc-keeper (keeps
this file, the gotchas and the skills true).

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
         mapping is resolved once from the header - from the log source
         profile identify.py matched (logsources.py, gotcha #27; a file no
         profile documents is refused before this, gotcha #53) - and baked
         into one INSERT ... SELECT read_csv(...). No row ever crosses into
         Python. The manifest's `mapping` says which, and the case page shows it.
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
         from lines.py and the manifest keeps it (`lines`, gotcha #62);
         SigmaHQ's high / critical Windows rules run last among them
       → sigma.apply_marks: SigmaHQ's other rules mark events (`sigma_marks`),
         the manifest's `sigma` says which commit ran and what could not
         (converted at image build into /opt/sigma, gotcha #79)
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
```

The full route list - every `/api/*` route and what it returns -, the manifest's keys and the
login detail are in the **`case-api`** skill; the Overview's three levels and what each figure
counts are in **`frontend-ui`**.

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
because the customer's own store went with it (gotcha #74) · `report/` the report skeletons,
`<sha256>.docx` each, and their hash-chained `log.jsonl` (provider configuration, never in git).
A project's report drafts and finals are the customer's: `customers/<id>/reports/<pj-id>/`, each
one a line of the project's hash-chained log (gotcha #83).
**Login accounts are not in `DATA_DIR` at all** (gotcha #41): `users.json` +
`session_secret` live in `AUTH_DIR` (`/auth`, its own Docker volume
`forensic-auth`; see *Login and roles* below).

**Login and roles (FR-1, IAI-13, IAI-14; detail in `case-api`).** Every `/api/*` route
needs a signed-in session except `/api/health`, `/api/auth/login`, `/api/auth/config` and
Google's start / callback - one middleware in `app/main.py`, so a new router is protected
without doing anything. Accounts live in `AUTH_DIR/users.json`, apart from customer data
(gotcha #41), made with `tools/create_user.py` or the Users page; there is no sign-up page.
Roles admin / manager / analyst are one table, `authz.PERMISSIONS`, deny by default, asked by
`authz.require` on the route - the server is the gate, the UI only reads it. Sign in with
Google (gotcha #82) is off until its four settings are set. **The review actor comes from the
session, never from the request body.**

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

## UI rules (detail in the `frontend-ui` skill)

- `frontend/` is the source; `static/` is its build output - generated, gitignored, never
  edited by hand. 8091 serves the bundle built in its image, so a UI change shows there only
  after `docker compose up -d --build --force-recreate` (or first through `npm run dev`).
- **Nothing fetched at runtime**: every asset is bundled (fonts via `@fontsource`), so a case
  is workable air-gapped (gotcha #17); dependencies are pinned exactly; the image builds the
  bundle itself, so it never ships a stale one.
- All UI text is English. The look is the SENTRY-IR Figma's tokens in the SOCRadar layout,
  light by default, dark only by the button (`fa_theme`) - the OS setting is not followed.
- **`--accent` (red) means "act here" only**; severity and warnings are `--warn`. Every colour
  is a token with a value under both themes - a literal hex is wrong in one of them.
- **Say a figure once on a page**, and the dashboard counts as the case page counts.
- The attack graph is a **static SVG with no library** - it is screenshotted into reports:
  columns by role, edge labels anchored past the source node, a node says only what the
  evidence does (gotchas #10, #80).
- No `window.prompt()` / `alert()`; never gate a submit button on React state that autofill
  feeds (Chrome fills without input events).
- Two instances on `localhost` share the `fa_session` cookie across ports and log each other
  out - test a host copy on `127.0.0.1:<port>`.

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
- #79 SigmaHQ on Windows (story 6, `specs/sigma_windows.md`): converted at image build into `/opt/sigma` (pySigma never at runtime), high / critical are `SIGMA-<uuid>` product rules, the rest marks on events (`sigma_marks`); pySigma's Windows pipelines pin `pysigma<2` (taxonomy map instead), booleans as text, the whole UUID as id, a `Data` field shadows `data`, one SigmaHQ rule's error never fails a case.
- #81 SigmaHQ's process creation rules also read Security 4688 (story 6d): SigmaHQ's own thor.yml map (Image <- NewProcessName, ParentImage <- ParentProcessName, CommandLine), an empty item NULL, a `NOT COALESCE` rule only on a 4688 holding every field it uses (1,220 of 1,425 run, 205 listed), 4688 read only where the host's Sysmon 1 does not cover that time.
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
- #82 Sign in with Google (specs/google_login.md): the `hd` claim not the parameter, bound to `sub` not the email, redirect URI from `PUBLIC_URL`, the ID token straight from Google's token endpoint (OIDC §3.1.3.7 step 6); the whole domain may sign in, so removing an account is not a ban - disable is.
- #48 Work is queued, durable and bounded (`jobs.py`); manifests are written atomically. **One process only.**
- #58 Ingest: question on the project (hash-chained log), provenance / declared time off the screen since 2026-10-27 (the user: too much, then not needed; `PUT /provenance` still takes them), a declared zone / clock offset applied only on re-process (`POST /reprocess`), a method record on every `processed` line, duplicates named within a customer.

**AI narrative** (`analysis.py`, `llm.py`, `grounding.py`, `veris.py`)
- #72 The AI explains and never decides (the user, 2026-10-27): no accept / reject / "likely attack" - what happened, why it fired, facts for an attack and for an ordinary cause, what is not shown, check next (Heuer ACH); log values quoted; the review line keeps only model + time; old advice replaced by Review again; one schema per suggestion (a batch-wide enum let 13 of 113 name another rule's false positive), the attack side `minItems: 1` (optional, 16 of 94 attacks came back empty); ~14 s a suggestion.
- #71 Every suggestion is reviewed by the AI itself, no cap (the user's requirement): the case is ready after the rules and the review runs on in the background (`triage.enqueue`, one worker, resumed at start-up), every rule first, a failed batch retried then sent one by one, what is left listed with "Review again" (`POST /ai-review`); batch size measured (`TRIAGE_BATCH`).
- #64 The AI reviews every suggestion while the case is processed (`triage.py`; since #71 after it is ready): facts computed in SQL (a destination's popularity among internal hosts, the rule's documented false positives), a schema, an address check; advice under each suggestion, kept on the review line; the Upload page counts the suggestions reviewed; `TRIAGE_ENABLED=0` in every rule check and in dev.
- #5 Groq's output-token limits and the measured sweeps (events 15, max_tokens 950); schema key order is the priority list. Groq only - not the local model.
- #10 The attack graph is SQL (`db.build_graph()`), not AI - don't hand it back to the model. Since 2026-10-28 it, its risk ranking and the attack timeline (case and project) take only the confirmed groups (`keys=`, `case_views.decided`) and stay empty until every suggestion is decided - MCP's `get_attack_graph` / `get_risk_ranking` too (`case_views.attack_path`); keys go in as one JSON string (a bound list cost 0.43 s a query).
- #80 An edge goes to the computer that logged the event (`coalesce(dstip, hostname, username)`), the account on the edge (`accounts`); an address is drawn as its host when that host's Sysmon 3 or its `NAME$` sign-in / TGT ties it to one computer only (`db._host_addresses`); a loopback source stays an address.
- #13 Every wrong narrative was missing input, never reasoning: compute the discriminating fact in SQL and hand it over; prompt hardening was measured to do nothing.
- #36 VERIS 1.4 classification is computed, then handed to the model.
- #37 The narrative is decoded inside a per-case JSON schema and grounding-checked; every query feeding the prompt needs a total `ORDER BY` tiebreak; citations `F<n>`.

**Exports**
- #32 ATT&CK Navigator layer (format 4.5).
- #34 STIX 2.1 bundle (and why `stix2-validator` rejects every bundle).
- #83 Report drafts (specs/forensic_report.md, IAI-72/73): the system writes an editable Word draft per project from an uploaded skeleton; a skeleton's `INCLUDEPICTURE` fields fetched another organisation's logos - every linked field / external relationship refused; an element out of ECMA-376 order hangs Word on a hidden repair dialog; the AI's Thai summary is checked (address, machine, dotted account, time against its cited `F<n>`), not trusted.

**Method**
- #18 Measure before optimising: time a stage first; corpus wall-clock spread is host I/O.
- #54 The product direction of 2026-10-20 - forensic reconstruction, Respond removed, in-house rules kept with SigmaHQ rules added beside them (the retirement was reversed after ADR-006: SigmaHQ has no correlation or failed-login rule, no firewall-traffic rule). **Read before designing anything.**
- #55 A standard is cited only from a document actually read (`docs/standards/SOURCES.md`); PDFs are read with `pdftotext` (the web fetcher returns compressed streams); ISO pages refuse automated access.

**`docs/STANDARDS.md` is the one-page map** of every pipeline step to its
standard (or "internal method", with the nearest framework named and the
method written out - risk ranking, TP/BTP/FP, rule validation, escalation
patterns). The user's requirement since 2026-10-12 is that every step cite
one; update that table whenever a step changes.

## Product decisions (the user's; detail in `sentry-ir-console`)

- **There is no "incident"**: the collapsed finding (`rid|srcip|username`, gotcha #19) is the
  only unit, ids `FD-YYYY-seq`; grouping survives only as related findings.
- **Every datum comes from an upload** - no live feed, integration or ingest API key.
- A customer is added only on the Upload page; every new case is in a project (gotcha #75).
- Uploads up to 10 GB measured after decompression, `.gz` / `.zip` (a zip is one case);
  the resumable upload (IAI-24) is not built.
- **The analyst decides; the system and the AI only suggest** (gotchas #72, #73). The status
  workflow and MTTC are off the screens; `lifecycle.py` stays for the audit trail.
- Alerts, Threat Intel, Playbooks and Assets pages are cut.
- Work is tracked in Jira project `IAI` (https://titlenattapat.atlassian.net): the active
  sprint in rank order, a dependent criterion split into a story of the later sprint.

## Environment / secrets

**Ollama must be running on the host** (`ollama serve`, or the Ollama app) for the AI review of
suggestions (gotcha #64) and the narrative; without it a case is still processed, with the
reason recorded. On 2026-10-22 it was not running, and when started from a Claude Code shell it
was later stopped for low memory - qwen3.5:9b, the 8091 container and the dev container together
are a lot for this PC; stop the dev container when not in use. `TRIAGE_ENABLED=0` turns the AI
review off (every rule check sets it; the dev container has it off unless `DEV_TRIAGE_ENABLED=1`).

**What the model costs on this PC, the benchmark of the local models, why qwen3.5:9b and
the settings in force are in the `local-llm` skill.**

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

cd frontend && npm ci && npm run build   # UI only, straight into ../static - the HOST's static/:
                                         # 8091 does not mount it and serves the bundle built
                                         # in its image, so a UI change shows there only after
                                         # `docker compose up -d --build --force-recreate`
                                         # (or see it first through `npm run dev`)
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
import duckdb, glob; con=duckdb.connect(glob.glob('/data/customers/*/db/{case_id}.duckdb')[0], read_only=True)
print(con.execute('SELECT rid, count(*) FROM findings GROUP BY rid').fetchall())"
```

Runs on host port **8091** (the older Wazuh-based `forensic-webapp` uses
8090 — don't collide if both are up). On Windows/git-bash, absolute
Unix-style paths in `docker exec`/`docker cp` need `MSYS_NO_PATHCONV=1`.

## Validating changes (detail in the `validate-changes` skill)

- After touching `decode.py`, `rules.py` or the ingest pipeline: `python tests/gen_usecase.py
  <dir>` then `python tests/check_parity.py <dir>` (expected counts in `tests/README.md`), then
  the corpus. `check_parity.py` is stdlib only, needs `FA_EMAIL` / `FA_PASSWORD`, uploads to
  customer "Parity check", and is run against the dev container (`--url
  http://127.0.0.1:8092`) with the AI review off - with it on, a hundred uploads take hours.
- **Run every `tests/check_*.py` before a rule change is merged.** The skill says which check
  covers which layer and how each must be run (some need the container, a scratch
  `AUTH_DIR`, Ollama, or inputs outside the repo).
- The baseline is `tests/baseline.json`, not a number in prose. `--update` merges; when a run
  claims everything matches, reconcile its totals against the previous run before believing
  it. A silent drop to 0 findings is gotcha #2 / #7; a plausible wrong finding is gotcha #22.
- Timing claims need more than one run (gotcha #18). Validation fills the store:
  `tools/prune_cases.py` (dry run first, `--keep-reviewed`).

## Extending the rule engine (detail in the `add-detection-rule` skill)

A new rule is a **product rule** (`specs/per_product_rules.md`): `rules_<product>.py` (firewall
products share `rules_firewall.build`), reading `product_events`, its line from `lines.py`, its
behaviour's document read (D14), a `RULE_META` entry (`python tests/check_rule_meta.py`), a
place in `areas.py` and a case in the product's check. **SigmaHQ's rules are not written here**
- a single Windows event SigmaHQ covers is not an in-house rule, and a new SigmaHQ commit is a
new pin (gotcha #79). Get the MITRE tag right - the AI trusts it - and give a correlation rule
an outer `WHERE` on the evidence rows (gotcha #23). Load the skill before writing or changing
any rule.
