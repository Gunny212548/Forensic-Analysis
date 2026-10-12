# CLAUDE.md

Guidance for Claude Code when working in this repo.

## What this is

A standalone forensic log analysis tool — **no Wazuh dependency**. Upload any
log file (syslog/auth.log style text, CSV firewall exports, JSON), the app's
own decoder + rule engine extracts structured fields and flags
security-relevant events with MITRE ATT&CK technique IDs. The attack graph
is then built straight from those findings in SQL, and Groq (AI) writes the
narrative around it — case summary, attack chain, timeline,
recommendations.

Formats exercised against real data so far: VMware ESXi `auth.log`,
Palo Alto CSV exports, Check Point SmartLog CSV exports. The decoder is
heuristic rather than per-log-source — it maps whatever columns a file happens
to have onto one canonical schema (see gotcha #7 for what that costs).

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
  → BackgroundTask → asyncio.to_thread(pipeline.process_case)

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
         path is ONE DuckDB statement and 1.1.3 has no query_progress(), so
         its share is an elapsed-time estimate at ~60 MB/s, held at 95% of
         the file, flagged `estimated` (the UI prefixes "~"). Manifests are
         now written tmp-then-rename, since they are rewritten while polled.
  then → rules.apply_rules() = SQL INSERT ... SELECT per rule
       → status=ready (or failed + error/traceback on the manifest)

data/db/{case_id}.duckdb
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
GET  /api/cases/{id}/events?limit=&offset=   paginated SQL
GET  /api/cases/{id}/findings                collapsed findings + computed
                                             confidence + review status
POST /api/cases/{id}/review                  one analyst decision (appended)
GET  /api/cases/{id}/review-log              full decision history
GET  /api/cases/{id}/custody                 evidence digest + chain of custody,
                                             hash chain checked on read
POST /api/cases/{id}/verify                  re-hash the raw file now, log it
GET  /api/rules[/{rid}]                      rule metadata: Sigma fields + ADS
                                             documentation (rule_meta.py)
POST /api/cases/{id}/analyze                 db.build_graph (SQL) for the
                                             graph + SQL top-N distinct → Groq
                                             for the narrative
GET  /api/overview                           KPIs, severity, techniques, top
                                             entities, activity + case list
                                             across all cases (services/
                                             overview.py; per-case facts cached
                                             on DuckDB/review-log mtime)
```

**The Overview page is interim until findings have a status.** It follows
`figma-export/Overview.svg`'s layout, but that design is status-shaped
(open findings, MTTC, an open-findings table), and the finding lifecycle only
arrives in Sprint 3 (IAI-45..49), with the real Overview stories in Sprint 5
(IAI-65..70).
Until then every tile is a case, finding, review or technique number, and the
table is the case list (IAI-20). No figure is a placeholder. "Top affected"
ranks by accumulated risk score, not by case count: ranked by count, the
benign admin account seen in every seeded case came out first (gotcha #16
again).

Storage layout under `DATA_DIR` (`/data`):
`cases/` manifests (small JSON) · `companies/` one JSON per customer ·
`db/` per-case DuckDB · `raw/` original
uploaded files, compressed ones kept compressed (audit trail) · `analysis/` cached AI output · `tmp/` staging ·
`intel/` threat-intel feed files (see gotcha #17) · `review/` append-only
analyst decision logs, one JSONL per case (see gotcha #19) · `custody/`
hash-chained chain-of-custody logs, one JSONL per case (gotcha #28) ·
`users.json` login accounts + `session_secret` (see *Login* below).

A manifest now carries more than the upload: `company_id`/`company_name`
(always set since FR-2.1), `compression` (`gz`/`zip`/null), `size_bytes` (as
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
  (add / list / remove); there is no sign-up page on purpose. Passwords are
  stdlib `scrypt`, so auth added no dependency.
- The session is an HMAC-signed cookie (`fa_session`, HttpOnly, 12h), not
  server state. Every request re-reads the account, so **removing a user
  ends their sessions at once**; what logout cannot do is revoke a copy of
  the cookie taken before it expires. There is no login rate limit yet.
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
                       #/result/<id>, and the menu routes of Sidebar.jsx)
  api.js               every call the UI makes, and nothing else
  format.js            fmtBytes/fmtTime/shortTs + the status & severity maps
  pages/               Overview (#/dashboard) · Upload · Customers · Result · Login · Placeholder
                       (menu pages whose story is not built yet)
  components/          Sidebar (app shell, FR-0) · Workspace (case tabs)
                       EventsTable · ReviewPanel
                       AttackGraph · analysis.jsx (chain/timeline/risk/meta)
                       common.jsx (severity pill, status badge, MITRE tags)
```

It replaced a hand-written 1,212-line `static/index.html`, whose URLs and
localStorage key `fa_recent_uploads` were kept unchanged so pasted case links
and an analyst's recent uploads survived the rewrite (`analyst-name` is no
longer read - the reviewer is the signed-in account, see *Login*). The
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
login and shell are in English, as the Figma is; page content is still Thai
until each page's story restyles it.

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

**1. DuckDB `executemany()` is catastrophically slow — never bulk-insert with it.**
Benchmarked here at ~300 rows/sec (20k rows = 65 seconds); a 65k-row file
took 3.5 minutes end-to-end. It's a per-row prepared-statement call. The
pipeline instead writes decoded rows to a staging CSV and lets DuckDB's CSV
reader ingest it in one statement — same file now processes in ~6 seconds.
(pandas/pyarrow would also work but add tens of MB of dependency for no
gain here.)

**2. Exact column-name matches must beat substring matches when decoding CSV.**
Palo Alto exports have both `Action` (allow/deny — the one that matters) and
`Log Action` (value: "Log Forwarding ALL"). A naive substring search finds
`Log Action` first, `verdict` becomes garbage, and *every* firewall rule
silently stops matching — the case processes "successfully" with 0 findings.
`decode._find_field()` tries exact matches first for this reason.

**3. Log lines without a hostname field break a naive syslog decoder.**
Standard syslog is `TIMESTAMP HOSTNAME PROGRAM[PID]: MESSAGE`; VMware ESXi
omits the hostname. A single greedy regex misparses the program as a
hostname and no program-specific decoder ever matches.
`decode._split_host_prog()` checks token-by-token instead.

**4. Don't conflate a connection's *source* port with a *destination* port.**
In `Connection from 1.2.3.4 port 53544` that's the client's ephemeral source
port. Feeding it to a port-scan rule (which counts distinct *destination*
ports) false-positives on any host that merely reconnects a lot. `decode.py`
deliberately does not set `dstport` from SSH regex captures.

**5. Groq output-token limits shape the whole prompt design.**
- **`qwen/qwen3.8-27b` is the only model now** — the gpt-oss branch (and its
  `reasoning_effort: "low"` workaround for hidden reasoning tokens) is gone.
  Everything below exists to make the schema fit qwen's budget.
- qwen's **1000 OTPM** cap on this tier is *per minute across all requests*,
  and Groq reserves the full `max_tokens` up front rather than charging
  actual usage. With `MAX_COMPLETION_TOKENS=950` that means **one analysis
  per minute**: a second `POST /analyze` inside the same minute is rejected
  with a 429 (`Used 856, Requested 950`), not truncated. `run_analysis()`
  retries in place when the API asks for <=25s and otherwise raises
  `AnalysisRateLimited` → HTTP **429 + Retry-After**, so the UI says how
  long to wait instead of showing a generic 502.
- **Second sweep, after the graph moved to SQL** (8 configs on the Azure
  case): `events=15` with `timeline<=6`, `attack_chain<=4`, `temp=0.2` is
  still the right setting and needs no change. `events=20` and `events=25`
  both hit `finish_reason: length` and the timeline *shrank* to 4 entries;
  raising the timeline cap to 8 also ran out of budget and still produced 4.
  The freed graph budget does not buy more coverage - it is already spent.
- **First sweep (7 configs, one call each, graded against the
  `tests/gen_usecase.py` ground truth — don't redo this by guesswork):**

  | config | events | max_tokens | complete? | chain/timeline/recs | notes |
  |---|---|---|---|---|---|
  | base | 8 | 950 | yes | 4/2/3 | never mentions the successful root login |
  | cov12 | 12 | 950 | yes | 4/2/3 | — |
  | cov15 | 15 | 950 | yes | 4/2/3 | best narrative; success tagged T1078 |
  | fast480 | 8 | 480 | **no** | 3/0/0 | loses recommendations + timeline |
  | fast650 | 8 | 650 | **no** | 4/0/0 | loses recommendations + timeline |
  | qual15 | 15 | 950 (+hardened prompt) | yes | 4/2/3 | no gain over cov15 |
  | qual8 | 8 | 950 (+hardened prompt) | yes | 4/2/3 | no gain over base |

- What that bought: `MAX_EVENTS_FOR_ANALYSIS` 8 → **15**. The model writes the
  same ~950-token object regardless of how many events it gets, so the extra
  input (+580 prompt tokens; input is not the capped resource) is free
  coverage. At 8 events the severity cut dropped the **successful root login**
  (lvl 3) before the model ever saw it, and the narrative never mentioned the
  pivot of the whole attack; at 15 it is described and tagged `T1078.003`.
- What did **not** work, so don't retry it:
  - *Lowering `max_tokens` to fit two analyses in one minute* — at 650 and
    480 the response loses `recommendations` and `timeline` entirely. The
    schema needs ~800-950 tokens; there is no useful smaller setting.
  - *Prompt hardening for the documented soft spots* (RFC1918-is-private,
    benign-source, T1078-not-T1110) — no measurable effect at n=1, and it
    costs ~180 prompt tokens. Raising coverage fixed the T1078 mis-tag
    instead: the model wasn't reasoning badly, it was never given the
    successful-login event.
- Beware of grading heuristics: the first rubric flagged "host 10.10.1.5
  exfiltrated to external IP 203.0.113.77" as an RFC1918 error because the
  sentence contained both "external" and a private IP. Check what a
  regression grader actually matched before believing it. Raising the event
  count or loosening those caps brings truncation straight back.
- `finish_reason: length` alone does **not** mean the output is damaged —
  qwen can spend its last tokens on trailing whitespace after a complete
  object (observed). `_meta.truncated` is therefore computed from
  *missing top-level keys*, not from finish_reason.
- When the JSON really is cut off mid-write, `_salvage_json()` rewinds to the
  last completed value, closes the open brackets and parses that, so a
  response that died inside `timeline` still delivers summary/attack_chain/
  graph. `_meta.salvaged` records when this happened.
- **The model does not draw the graph any more** — see gotcha #10. The
  schema it is asked for is `summary → attack_chain → recommendations →
  timeline`, and models generate keys in schema order, so that order *is*
  the priority list when the budget runs out. Don't reorder casually.
- `analysis._normalize_graph()` still exists only to render analyses cached
  before that change (flat `"src|dst|label|mitre"` strings, or an older
  nodes/edges object). Live runs never call it.
- Check `_meta.finish_reason` and `_meta.usage` in a cached analysis if
  output ever looks incomplete.

**6. A row can legitimately match several rules.**
Rules `INSERT` independently, so one row may produce multiple findings
(a login failure that is also part of a brute-force burst is both).
`flagged_count` counts `DISTINCT row_id` — don't switch it to `count(*)`.

**7. "ready with 0 findings" on a firewall export means a schema mismatch, not a clean log.**
This is the failure mode to be most suspicious of, because nothing errors.
A real Check Point export ingested 45,209 rows and produced zero findings:
every rule needs `srcip`, and `srcip` was NULL for every row. Diagnose by
counting non-NULL canonical columns before assuming the log is boring:

```sql
SELECT count(ts), count(srcip), count(dstip), count(verdict), count(app) FROM raw_events;
```

Log sources differ in three ways that all had to be handled:
- **Address format** — Check Point writes `object-name (1.2.3.4)`, Palo Alto
  writes a bare IP. `decode.extract_ip()` / the SQL `regexp_extract` pull the
  IP out and fall back to the original text so named entities survive.
- **Column names** — `Source`/`Destination` vs `Source address`/
  `Destination address`. Both are in `_FIELD_CANDIDATES`, specific ones
  first. `_AVOID_SUBSTRINGS` stops the loose pass from grabbing
  `Source User Name` as an IP.
- **Verdict vocabulary** — `accept`/`reject`/`prevent` vs `allow`/`deny`.
  `decode.normalize_verdict()` and the SQL `CASE` fold synonyms into the
  canonical spellings so rules stay readable.

**8. Not every log has a numeric port column.**
Check Point names the service (`http`, `FW1_ica_services`) and has no port
field at all, so `R2002` (distinct destination ports) can never fire on it.
`R2003` counts distinct *services* for the same signal. When adding rules,
check whether the field you depend on actually exists across log sources.

**9. A filtered export changes which rules can fire.**
The Check Point sample was exported after filtering SmartLog to one source
IP, so it contained exactly one `srcip` and ~18 minutes of traffic (the
console reported 96,418 matching rows; the CSV had 45,209). Consequences:
"100% of traffic is malicious" is an artifact of the filter, not a finding,
and a source-filtered or action-filtered export can silence correlation
rules entirely — `R2004` only works because both the allowed and blocked
rows for that IP were present. Ask what filter produced the file before
reading anything into cross-source comparisons.

**10. The attack graph is SQL, not AI — don't hand it back to the model.**
`db.build_graph()` derives it from `findings` joined to `raw_events`:
`srcip → coalesce(dstip, username)`, grouped per pair, rules merged into one
edge, MITRE IDs unioned, sorted by severity then volume. The graph is not
interpretation — every field an edge needs is already in the findings table,
put there by the rule engine.

Asking the model for it (the original design) cost real damage on qwen's
budget: at 950 output tokens a firewall case returned four narrated stages
and `missing_keys: [graph, recommendations, timeline]` — the picture gone,
the prose intact. It also capped edges at whatever fit, and let node names
drift from the evidence (an invented `Network` node appeared in testing).
Derived in SQL the graph is exact, complete, free, and every edge traces
back to real `row_id`s; the whole output budget goes to the narrative
(measured after the switch: 915 tokens, `finish_reason: stop`, timeline back
to 5 entries).

The prompt now explicitly tells the model *not* to emit a graph, and
`run_analysis(graph=...)` overwrites the key regardless. `_meta.graph_source`
records which produced it (`rules` vs `model` for old cached output).

**11. `action` on CSV, and why an auth verdict needs an account attached.**
The line-log decoder was the only thing that ever set `action`, so R1000-R1004
(and R2000, which builds on them) could not fire on *any* CSV — a real Azure AD
sign-in export ingested 91 rows with 14 failures against one account and
produced zero findings. `decode._FIELD_CANDIDATES["auth_status"]` +
`pipeline._ingest_csv_sql`'s `action_expr` now map a sign-in outcome column
onto `auth_success`/`auth_failed`.

Two guards make that safe, and both were put there by a real false positive:
- **Only the auth vocabulary translates** (`success`/`failure`/`failed`, and
  `normalize_auth_status()`). A firewall `Action` column of allow/deny yields
  NULL, so firewall traffic can never become an auth finding. Azure's
  `Interrupted` (the MFA / keep-me-signed-in prompt) maps to nothing — it is
  not a failed authentication.
- **A username is required**, both as a mapped column and non-NULL on the row.
  Without it an Exchange message-trace export (`MessageId, ..., Status`)
  matched `Status` and turned **335 failed email deliveries into 335 failed
  logins**. An authentication event is about an account; if nothing
  authenticated, it isn't one.

`R1000`/`R1001`/`R1002`/`R2000` also lost the word "SSH" from their `descr` and
`RULE_LABELS`. They were written when auth.log was the only source; leaving
"SSH brute-force" on an Azure AD web sign-in would propagate straight into the
AI narrative, which trusts these labels (see the R2001 MITRE lesson).

**12. "Resource" contains "source".**
`decode.match_column()`'s loose pass matched Azure AD's `Resource` column for
`srcip`, so an entire sign-in export decoded with resource names where its IPs
belonged, and `Multifactor authentication result` (a paragraph of prose) as its
`verdict`. Fixed by `_AVOID_SUBSTRINGS` (`resource`, plus `destination`/`source`
cross-guards now that `ip address` is a srcip candidate) and by putting
`status` ahead of `result` in the verdict candidates. Same family as gotcha #2 —
when adding a candidate substring, check what else in a real header contains it.

**13. Give the model the discriminating fact; don't instruct it to guess better.**
Asked to analyse an Azure AD sign-in case, the model called 20 successful
logins from one Thai ISP address "potential compromise" - the shape of the
account's own user. It was not reasoning badly: it had counts and nothing
else, so `success x20` and `success x12` looked alike. `db.source_profiles()`
now computes, per source, `auth_ok / auth_fail / allow / deny / days_active /
span / first_seen` over the whole case, and `_build_prompt()` appends it as a
compact "Source profiles" table (~15 tokens per source; input is not the
capped resource).

Same case, before and after:
- before: *"successful logins from 171.100.141.170, indicating potential
  compromise"* - the habitual user, active on 4 separate days.
- after: *"a burst of successful logins from 16 sources occurred on
  2026-06-07, indicating a likely compromise"* - the `89.251.0.0/24` address
  pool, which is the actual finding.

This is the same lesson as the R2001 MITRE retag and the T1078 coverage fix:
**every time the narrative was wrong, the cause was missing or mislabelled
input, never the model's reasoning.** Prompt hardening for these soft spots
was measured (gotcha #5 sweep) and did nothing. Compute the fact in SQL and
hand it over.

*Refined by a later ablation (8 configs, same case).* Once `R2005`/`R2006`
existed, **every** config got the reading right - including one with no
profiles and no risk table at all - because the finding text now says
"Password spray against X from 14 distinct sources" and the model only has to
repeat it. Re-run against rule-silent events (`R1000`/`R1001` only, the
pre-R2005 situation) the difference reappears sharply:

- with profiles: *"a mix of legitimate access from 171.100.141.170 ... a
  coordinated burst of successful logins from the 89.251.0.0/24 subnet"*
- without: *"20 successful logins from 171.100.141.170"* - leads with the
  owner's own activity and never mentions the burst at all.

So both layers earn their keep, in this order: **a rule that names the
pattern is worth more than any prompt context**, and the profiles are the
safety net for everything no rule covers yet. The profiles cost ~1,200 input
tokens, and input is not the capped resource.

**14. Per-source counters miss attacks that spread across sources.**
`R2000` counts failures per `srcip` and needs 3; a real Azure export had 14
distinct IPv4/IPv6 addresses each failing exactly once against one account,
so nothing fired while the account was plainly being sprayed. Two rules cover
the axis the per-source rules can't see:
- `R2005` (T1110.003): one account, failures from >=5 distinct sources. Also
  fires on the ESXi `auth.log` in the corpus - `root` was hit from 6 addresses.
- `R2006` (T1078): one account, successes from >=4 distinct sources inside the
  same hour. Caught 16 sources in `89.251.0.0/24` succeeding within minutes on
  2026-06-07 - the single most suspicious thing in that case, which neither
  the old rules nor the AI had flagged. Hour buckets are crude (a burst across
  a boundary splits) but need no window function.

Both leave `flagged_count` unchanged on that case - same rows, more rules per
row, which is gotcha #6 working as intended.

**15. Beaconing is a *regularity* test, and it only works on egress.**
`R2007` measures the interval between consecutive connections for each
src->dst pair and flags pairs whose intervals barely vary (jitter =
stddev/mean). Nothing threshold-based can express this: on the customer's
compromised host `R3000` flagged 12,281 rows and buried the four
destinations that mattered.

Calibrated on real data, not guessed: the true beacons sat at jitter
0.43-0.55 (300-450 connections at ~40-minute intervals over 11 days to
`72.154.7.0/24`, all `ssl`, all allowed) and ordinary bursty browsing at
0.89-0.94. The cut at 0.6 separates them with room on both sides.

**The egress restriction is not optional.** The first version, without it,
added 16,599 findings to one previously-clean file - all of them Windows
Delivery Optimization peer-to-peer updates (`ms-update-optimization-p2p`,
port 7680, 10.x -> 10.x, 44 host pairs). Internal traffic is periodic by
nature. Requiring a public IPv4 destination dropped every false positive and
kept the true one; the cost is that internal C2 and lateral beaconing are out
of scope. Even on egress, a legitimate update-check or telemetry endpoint is
indistinguishable from C2 in the logs alone - the rule localises, the analyst
identifies the destination.

**16. Risk ranking needs diminishing returns, or it just ranks by volume.**
`db.risk_scores()` accumulates finding severity per entity (source,
destination, account) the way modern SIEM risk-based alerting does, because
"which rule fired" does not answer "where do I look first" in a case with
25,579 findings. A flat `sum(lvl)` ranked a scanned host with three noisy
rules (79,500) *above* the actual C2 destination. Scoring per distinct rule
with a log-dampened count - `sum(lvl * (1 + ln(n)))` - puts the three
beaconing destinations on top instead, because it measures how many
different ways an entity is implicated rather than how much traffic it moved.
The ranking is sent to the model (it leads the summary with it) and rendered
in the analysis panel.

**17. Threat intel is offline on purpose, and it is just a JOIN.**
`intel.py` parses whatever is in `DATA_DIR/intel/` into one canonical `ioc`
table per case; `R3003` (known-bad destination, high) and `R3004`
(known-bad source, medium) join it. Nothing about analysis touches the
network - `tools/refresh_intel.py` downloads the feeds as a separate step, so
a case can be worked air-gapped and re-running it over the same feed files
gives the same findings, which matters when the output is evidence.

- The parser is format-agnostic, not one-per-feed: comment-prefixed CSV
  (abuse.ch Feodo, ThreatFox) or a bare list of addresses (blocklist.de,
  CINS, Tor exit nodes), plus anything a customer hands over in either shape.
  Only IP indicators are kept - the canonical schema has no URL, hash or
  domain column to match one against. Private/loopback/multicast addresses
  are dropped: a feed listing RFC1918 space would flag every internal flow.
- `R3004` is deliberately *lower* severity than `R3003`. Feeds like
  blocklist.de list any host that has ever probed anyone, so being scanned by
  one is background noise; talking **to** C2 infrastructure is not. On the
  corpus this is exactly what showed up - 2,480 hits, all inbound scanners
  against the customer's public addresses (and allowed).
- Indicators are loaded **after** ingest, filtered to addresses that appear
  in the case's own traffic (`intel.fill`). An indicator nobody talked to
  cannot produce a finding, and storing all ~43k in all 93 case files
  inflated every DuckDB for nothing.
- Feed snapshot at time of writing: 42,952 usable IPs from 5 feeds
  (blocklist_de 24,577 / cins 14,724 / threatfox 2,365 / tor 1,286).

**18. Measure before optimising - twice here the bottleneck was not where it
looked.** The corpus wall-clock moved from ~18s to ~60s when IOC matching
landed, which looked like the per-case indicator load. It was not: measured
directly, `intel.fill()` costs **13ms** and *all sixteen rules together* cost
**56ms** on the largest case (65,534 rows). A Parquet copy of the feed was
built to "fix" it, saved 5ms, and was removed again. Repeat runs of the
unchanged corpus took 52s, 60s, 67s and 74s - the variance is host I/O for
93 uploads, not anything the pipeline does. Time a stage before rewriting it.

**19. Review state lives outside the case DuckDB, and reviews collapsed
findings - both on purpose.**
Requirements FR-2.4/2.7, FR-4.2/4.6, FR-5.6, FR-7.6 and NFR-9 all need the
same thing underneath: an analyst decision attached to a finding, with
history. `review.py` stores one JSON line per decision in
`review/{case_id}.jsonl` and replays the file for current state.

- **Outside the case DB** because `db.drop()` deletes the whole `.duckdb`
  file when a case is re-processed. Verified: after a full re-process of the
  25,579-row case, both decisions were still attached to their findings.
- **Collapsed findings, not rows.** The review unit is
  `finding_key = rid|srcip|username` - the same grouping
  `top_distinct_findings()` already uses. That case has 20,063 finding rows
  over 18,888 distinct events and **4** reviewable findings. Reviewing rows
  one at a time is a requirement that cannot be met; four decisions take two
  minutes. (Was 6 reviewable before R2002/R2003 were restricted to denied
  traffic - see gotcha #23 - and the two that went away were the false
  positives, so the ratio this bullet is making a point about got better,
  not worse.)
- **Append-only** gives FR-2.5 history, FR-7.6 actor/time/reason and NFR
  auditability from one structure instead of three.
- Rejections require a `reason_code` from a fixed set (FR-4.6) - the API
  returns 400 without one, so mapping quality stays measurable.

**20. Confidence is computed, not asked of the model - and rule *ids* are the
wrong thing to count.**
`db._confidence()` implements section 6 of the requirements: `low` when no
timestamp parsed, `high` when the entity is implicated by >=2 rule
**families** with >=5 supporting events, `medium` otherwise with an explicit
`single-source` / `few-events` flag. A model scoring its own output cannot be
audited; this can be explained in one sentence per finding.

The first version counted distinct rule *ids* and returned `high` for
everything, which is a metric that discriminates nothing. R2002 (port scan)
and R2003 (service sweep) are one observation counted twice, and R2005 cannot
fire unless R1000 already did - so rule ids over-credit. Families
(R1 auth / R2 correlation / R3 network) are closer to independent evidence.
After the change the same corpus gives: beacon case 4 high (was 6 before the
R2002/R2003 deny restriction of gotcha #23 removed two false positives),
Azure case 2 high / 69 medium (`few-events` - each source failed exactly
once), Palo Alto 15 medium (`single-source`). All three re-measured
2026-09-15.

`timezone-unconfirmed` (FR-1.6) is flagged when `ts_raw` carries no zone -
it fires on the Check Point export (`Jun 23, 2026 10:03:02 PM`) and stays
quiet on the Palo Alto and Azure exports, which carry `+07:00` / `Z`. It is
tested against the **source text**, never against the rendered `ts`: since
gotcha #21 every row leaves ingest carrying `+07:00`, so testing the output
would report every source as zone-confirmed. What the flag records is that
the source itself never said and the GMT+7 rule was assumed.

**21. Every timestamp is normalised to GMT+7, and both ingest paths used to
get this wrong in opposite directions.**
`config.EVENT_TZ_*` is the single policy: a timestamp that states an offset
(`Z`, `+00:00`, `-03:00`) is **converted** into GMT+7; one that states none is
**taken to already be** GMT+7. So `raw_events.ts` is always GMT+7 wall-clock
and two rows from two log sources are directly comparable, which is the whole
point - the deliverable is a timeline. `ts_raw` still keeps the source text
verbatim.

What it replaced, on the same file:
- `pipeline._ingest_csv_sql` cast to `TIMESTAMP`, which silently converted
  every offset-bearing row **to UTC**: a Palo Alto `+07:00` export stored
  13:13 as 06:13.
- `decode.parse_ts` dropped `tzinfo` **without converting**, keeping the UTC
  wall clock: an Azure `03:12:00Z` stayed 03:12 instead of becoming 10:12.

So the SQL path and the Python path disagreed by seven hours on the same
input, and `db.top_distinct_findings()` then fed the model `ts_raw` (local)
while the events table rendered `ts` (UTC) - the narrative and the evidence
table quoted different times for the same event.

- SQL does it with `try_cast(x AS TIMESTAMPTZ) AT TIME ZONE 'Asia/Bangkok'`
  (ICU is already in the image; verified before writing it). `db.connect()`
  sets `SET TimeZone` on **every** connection so a zone-less string means the
  same thing wherever it is cast. The `try_strptime` fallbacks carry no offset
  at all, so what they return is already GMT+7 and needs no conversion.
- Python uses a fixed `timezone(timedelta(hours=7))` rather than
  `zoneinfo`, so the image needs no tzdata. Asia/Bangkok has been +07:00 with
  no DST since 1920, so the two spellings cannot disagree.
- `db._fmt_ts()` stamps `+07:00` onto every rendered time and the prompt says
  so in one line, so neither the analyst nor the model has to infer a zone.
- `ts_first`/`ts_last` now come from `min(ts)`/`max(ts)`. They used to be
  `min/max(ts_raw)`, which compares the **source text as strings** - it only
  happens to order correctly for ISO input, so a Check Point
  (`Jun 23, 2026...`) or Palo Alto (`04/06/2026...`) case reported a range
  that was not its earliest and latest event.

Verified 2026-09-15: six spellings of one instant (`Z`, `+07:00`, naive ISO,
`07/06/2026`, `Jun 7, 2026 10:12:00 AM`, `-03:00`) all produce
`2026-06-07 10:12:00` through both paths. Across 211 re-processed cases the
row count did not move by one (2,278,792 before and after) and 557 sampled
rows whose source states `+07:00` all match their source wall clock.

**A re-process is required after any change here**, and the old cases will
not tell you they are stale: they hold UTC and nothing flags it.

**22. A TSV export decodes into one garbage column, and the findings it
produces look plausible.**
`pipeline._csv_header()` reads the header with `csv.reader(fh)`, whose
delimiter is **comma, hardcoded**. Given a tab-separated Palo Alto export the
whole header comes back as one field - verified, `_csv_header()` returns
exactly 1 field for it - and `decode.match_column()` then loose-matches its
candidates *inside that one giant string*. Measured on the real file:
`ts`, `app` and `category` all resolve **to the same bogus column**, while
`srcip`, `dstip` and `verdict` resolve to `None`, because the giant string
also contains `destination`, `user` and `log action`, which the
`_AVOID_SUBSTRINGS` guards of gotchas #2/#12 correctly reject. `ts` then
parses to NULL because the value is a whole tab-joined row.

The result is worse than the silent 0-findings of gotcha #7, because it is
not silent: `R3002` fired **78 times** on one 102-row file purely because the
row text contains `used-by-malware`. The findings read like real malware hits
and are useless - no `srcip`, no `dstip`, nothing that can reach the attack
graph. The comma-separated twin of the same export (same 102 rows, different
md5) correctly yields `R3000` x78 with real `risk` values.

DuckDB is not the problem: `read_csv` sniffs the tab itself and returns all
117 columns for both files. The mapping is computed from the Python-read
header, which is wrong, so the generated SQL references a column that does not
exist, the fast path throws, and the Python fallback - `csv.DictReader`, comma
again - decodes the file into a one-key dict. Confirmed from the stored data
rather than inferred: the `raw` column of that case contains exactly one `=`
(`<whole header>=<whole row>`), which only the Python decoder produces; the
SQL path writes one `Col=value` pair per real column.

**Fixed 2026-09-15.** `parsers.sniff_delimiter()` counts `,` `\t` `;` `|` in
the header line and the result is handed to *all three* readers -
`csv.DictReader`, `pipeline._csv_header()` and `read_csv(delim=...)` - so the
header Python maps and the columns DuckDB returns cannot disagree about the
shape of the file. Counting beats `csv.Sniffer` because the answer is
explainable, and on a real 117-column export it is unambiguous (116 tabs vs 0
commas); ties and empty headers fall back to comma. The tab export now
ingests with all 102 rows carrying `ts`/`srcip`/`dstip`/`verdict`/`app`, and
`R3002` x78 became `R3000` x78 - identical to its comma-separated twin, which
is the whole point: same data, different format, same findings.

Those two lines were the *entire* whole-corpus diff for the day's work, which
is also the evidence that the `username` avoid-list, the R2007 off-by-one and
the CGNAT filter changed no counts at all.

**23. Restricting a correlation rule's threshold is not the same as
restricting the rows it flags.**
`R2002` (port scan) and `R2003` (service sweep) had no `WHERE` on the outer
query at all, so **every row of a matching source was flagged**, allowed
traffic included. `R2001` and `R2004` next to them always had one; the
principle was there, it just was not applied to these two.

Cost, measured: on `src10-8-3-215.csv` the pair flagged all 25,579 rows -
including 18,972 `allow` rows of an ordinary workstation - which handed
`db.risk_scores()` two `lvl 7` terms with `n=25,579` and pushed that source
above real findings, while `db._confidence()` read the two rule families as
independent evidence and returned `high` for both false positives.

Both the count and the flagged rows are now deny-restricted. What justified
the threshold staying at `>=10` / `>=20`, over 13,666 sources in the corpus:

| per source | median | p90 | reach >=10 | reach >=20 |
|---|---|---|---|---|
| distinct destination ports | 1 | 1 | 15 | 0 |
| distinct services | 1 | 1 | 25 | 6 |

Every one of the 15 sources reaching >=10 ports is ordinary traffic, and
deny-dominated sources top out at 1 port - so the deny filter removes 15 false
positives and no true ones. Of the 6 sources reaching >=20 services only 2 are
deny-dominated, one being the Check Point export, which carries **900**
distinct services among its denied rows and only 8 among its allowed ones.
The threshold was never the problem; counting rows that were allowed was.

Effect on the corpus: `R2002 -94,301` and `R2003 -82,709` findings, no other
rule moved by a single row, 4 files affected. The Check Point true positive
survives, narrowed from 45,209 rows to the 42,223 that were actually refused
(42,071 drops + 135 prevents + 17 rejects); its 2,978 accepted rows are a
policy gap, which is `R2004`'s finding and not a sweep.

**24. The workflow threshold matters - the obvious one opens 183 items.**
Only findings that pass a threshold enter the status workflow (IAI-42); the
rest stay visible at case level. Measured 2026-09-28 on 27 deduplicated real
files (no intel feeds loaded), back when findings were to be grouped into
*incidents* by attack-graph chain - a concept dropped on 2026-10-05 (see
*Decisions* below). The counts are therefore **chain groups, not findings**;
re-measure per finding before quoting them for the workflow. The `lvl`
numbers below are the **old 0-15 scale**, replaced by Sigma levels on
2026-10-12 (gotcha #26); re-express the threshold in levels before building
IAI-42. The new levels already do part of this table's job: 20 corpus files
dropped from High to Medium under them, the R3000-only noise included:

| opening rule | chain groups | files with any |
|---|---|---|
| any finding lvl >= 7 (High) **or** >= 2 rule families | 183 | 25 |
| any finding lvl >= 10 (Critical) **or** >= 2 rule families | **6** | 6 |

The first rule is useless because `R3000` (high-risk app allowed) is lvl 8
and fires alone on ordinary hosts: `dst10-8-2-37.csv` alone opened 38,
`log(10).csv` 56. The second leaves exactly the real attacks - the beaconing
host 10.8.3.215, host 10.8.2.37, the ESXi brute force/spray, the Azure spray,
and both `gen_usecase` files. The 21 Palo Alto files that carry only `R3000`
open none; their findings stay visible at case level. Families are the same
R1/R2/R3 split `db._confidence()` uses (gotcha #20).

The same grouping now defines **related findings** (IAI-43/44), shown on a
finding rather than merged into a new object. Chain grouping links sources
**only through pivots** (a target that is also a source). Linking through any
shared target would relate every scanner hitting one public IP - graphs here
are many-sources-to-one-target (see the attack-graph notes). But pivot-only
linking **splits an account-centric attack**: the Azure spray (14 sources, one
account) became 30 groups. `R2005`/`R2006` rows must instead be related by
`username`, which
takes that case to 1 and changes no other case. Pivots also never form
through accounts - a username is never a `srcip` - so auth chains are
single-hop by construction.

**25. An upload is fully received and spooled to disk before the handler runs,
so size and disk checks in `upload_log()` come too late.** Starlette parses the
multipart form - writing the whole file into a `SpooledTemporaryFile` in `/tmp`
(1MB in memory, the rest on disk) - before FastAPI calls the handler. The
"stream to disk in 1MB chunks" in `upload_log()` is true for memory but not for
disk or time: a 10 GB file has already crossed the network and landed in `/tmp`
when the handler's size check first sees it, and it sits on disk twice until
the spool is freed. Verified in the image (starlette 0.38.6,
`formparsers.spool_max_size = 1MB`).

So FR-2.2's refusals (`upload.capacity_problem()`: > `MAX_UPLOAD_BYTES` = 10
GB, or free space on `DATA_DIR` < `UPLOAD_DISK_FACTOR` = 2.5x the size) run
from **Content-Length in the middleware in `main.py`, before the body is
read**. Measured: an 11 GB upload declared in headers with no body sent gets
413 in 0.00s. The upload page also calls `GET /api/upload/check?size=` first,
because a browser that is still sending may report a network error instead of
the early 413/507. The 2.5x is not padding: spool copy + raw copy + DuckDB.
The handler's own byte count stays authoritative for the limit, because that
is the size *after* decompression. IAI-25 (.gz/.zip) must keep counting
decompressed bytes there, since Content-Length only knows the compressed size.

**26. Severity is a standard's level, not a number someone picked
(2026-10-12).** Every rule used to carry a hand-chosen `lvl` on Wazuh's 0-15
scale, bucketed by cut points nobody could cite (12+ critical, 7+ high...).
Nothing about Wazuh was left in the code but that scale, and it could not
answer "why is this High?". `severity.py` now grades in two layers, each
backed by a published standard:

- **Behaviour -> level: Sigma rules specification v2.1.0, `level` field.**
  Each rule declares one of `informational / low / medium / high / critical`
  in `rules.RULE_LEVEL`, chosen by the spec's own definitions (quoted in
  `severity.py`). No single rule is `critical`: the spec reserves it for
  near-certainty, which one log event almost never is.
- **A refused row is capped at medium** (`apply_rules`). In the ODNI Cyber
  Threat Framework a blocked attempt never crossed the intrusion boundary
  between Engagement and Presence.
- **Attack path -> escalation (ODNI CTF progression, MITRE ATT&CK tactics).**
  `credential-compromise` (R2000 brute force, then a success from that same
  source on that same account) raises the path to **high**.
  `compromised-host` (two *different* allowed post-intrusion behaviours on
  one source: R2007/R3003/R3002/R3001) raises it to **critical**. Rows go in
  the `escalations` table and the UI quotes the reason on the finding.

`findings.lvl` now stores the level's **weight** (1/2/4/8/16, doubling per
level), not a free number - so `ORDER BY lvl`, the graph and
`db.risk_scores()` keep working unchanged, and one `high` outweighs a
`medium` plus a `low`. Labels always come from `severity.level_of(lvl)`.
Measured: `risk_scores()` still puts the three beaconing destinations on top
(gotcha #16).

What the first version got wrong, so don't loosen it back:
- **Credential compromise is high, not critical.** The first version made it
  critical and also accepted mere R2005 (spray) membership. On the ESXi
  `auth.log` that escalated `10.9.59.182`, which failed twice and got in 9
  seconds later - a typo. A log cannot tell an attacker who guessed the
  password from an owner who mistyped it, so it is not Sigma's
  near-certainty, and it now needs R2000 (>=3 failures) from the same source.
- **Pair on the source, not the account.** The Azure account owner logs in
  successfully from their usual address while someone else sprays it; an
  account-level pairing would have called the owner's own logins a
  compromise (gotcha #13).

Effect on the corpus (host run, 63 distinct files, no intel feeds; rows,
flagged and every per-rule count identical to `tests/baseline.json`):
20 cases High -> Medium (all without escalation - mostly the R3000-only
Palo Alto noise of gotcha #24), 2 Medium -> Low, `src10-8-3-215.csv`
High -> Critical (beaconing + 8 uploads of ~96 MB to `135.119.206.211`),
`nightfall-firewall.csv` stays Critical (malware + large transfer from
10.10.1.5), and the ESXi, Azure and `nightfall-auth.log` cases stay High.
The planted brute-force -> root login is `credential-compromise`.

There is no lateral-movement pattern yet: nothing in the corpus shows a
compromised host attacking onward, so it could not be calibrated.
**A re-process is required after any change here** - manifests carry the
summary, and an old DuckDB still holds 0-15 numbers that `level_of()` will
mis-read.

**27. A column is read from the log source's documentation when one exists,
and a guess says it is a guess (2026-10-12).** `decode.match_column()` maps
any header by substring-matching column names, on purpose, so an unseen
export still yields something. Gotchas #2, #12 and #22 are all that guessing
going wrong. `logsources.py` now holds **profiles**: a header signature, then
each canonical field from the column the log source documents for it, the
value vocabulary that documentation lists, and the page it came from. The
manifest's `mapping` records `documented` / `heuristic` / `unrecognised`
and the UI states it on the case, with the doc links, so an analyst knows
which mappings to check.

- **Say "log source", not "vendor"** (the user's call: "vendor" misleads).
  A log source is the product that wrote the log, as in Sigma's `logsource`
  - PAN-OS traffic log, Entra ID sign-in log, OpenSSH sshd - not the company.
  Microsoft alone ships the Entra sign-in log and the Exchange message trace,
  two unrelated formats; the format is what a profile describes.
- Profiles exist only where there is **both a format document and a real
  file to test against**: PAN-OS traffic log, Microsoft Entra ID sign-in log,
  Exchange Online message trace. Line logs cite the message formats they
  match (OpenSSH `auth.c`, Linux-PAM `pam_unix`, FortiOS Log Message
  Reference). There is no Check Point profile: its export is not in the
  corpus any more (see below), and a profile no file has tested is a guess
  with a citation attached.
- A documented profile still falls back **per field** when an export lacks
  a column (the UI names the field). `gen_usecase`'s `nightfall-firewall.csv`
  is exactly that: it has no `Category`, so its malware marker - written into
  `Threat/Content Type` - is read by guess, flagged, and R3002 still fires.
- A line log in which no documented format matched is `unrecognised`, not
  `heuristic`: nothing was guessed, only timestamps and IPs were taken, and
  no rule can fire. That is 28 of the corpus files (ESXi `hostd.log` & co.)
  and it answers gotcha #7's "0 findings - schema mismatch or boring?" on
  the page itself.

What reading the documentation fixed - no count moved, but the values did:
- PAN-OS `category` came from `Threat/Content Type`, which PAN-OS documents
  as the log **subtype** (start/end/drop/deny). The documented `Category` is
  the URL category - what R3002's `malware|command-and-control` is for.
- Entra ID `username` came from `User`, the **display name** (an exact match
  on "user" won). Microsoft documents `Username` as the UPN, the account.
  **This changes finding keys** (`rid|srcip|username`, gotcha #19): a review
  recorded against the display name no longer attaches after re-processing.
- Entra ID `verdict` came from `Status` (a sign-in outcome read as a
  firewall verdict). The profile maps no verdict for a sign-in.

Measured: host run over 63 distinct corpus files, rows / flagged / every
per-rule count identical to `tests/baseline.json`; 33 CSVs documented
(31 PAN-OS - one with a guessed field - 1 Entra, 1 Exchange), 2 line logs
documented, 28 unrecognised.

**The Check Point benchmark is gone from the store.** *Real-world benchmark*
below says it lives in `DATA_DIR/raw/<case_id>.csv`; on 2026-10-12 the
store held 8 cases and none of them was it, and no copy was found under
`D:/forensic system`. Recover the original export before relying on that
section.

**28. Evidence is hashed when it arrives and re-hashed before every use
(2026-10-12).** Until then nothing could show that the file analysed was the
file handed over - every finding was uncitable as evidence. `custody.py`
follows ISO/IEC 27037, NIST SP 800-86 and RFC 3227 (chain of custody), with
SHA-256 from FIPS 180-4:

- `upload_log()` hashes the bytes **as they stream to `raw/`** (compressed
  stays compressed) - no second read of a 10 GB file - and writes the
  manifest's `evidence` plus a custody `acquired` entry (who, from which
  address, size, digest).
- `pipeline.process_case()` re-hashes before every run and **refuses** on a
  mismatch (`IntegrityError`, case `failed`). It checks before `db.drop()`,
  so the last good findings are not destroyed by the refusal.
- A merge is **derived** evidence: each source is re-hashed in the same pass
  that concatenates it, the merge is refused (409) if any changed, and the
  new case's first entry lists the sources and their digests.
- `custody/{case_id}.jsonl` is append-only and **hash-chained** (each entry
  carries `prev` + its own `hash`); `GET /custody` re-checks the chain on
  every read. That detects an edit, a deletion or a reorder. It cannot stop
  someone with write access from rebuilding the whole chain - only a digest
  kept somewhere else (or an external timestamp) would.
- `client_address` is the address **the server saw**. Behind Docker's port
  mapping that can be the bridge gateway rather than the analyst's machine.

Cases uploaded before this have no acquisition digest:
`tools/backfill_custody.py --apply` hashes them now and marks the digest
`retroactive` - it attests the file from that moment, not since upload, and
the Evidence tab says so. A case without any digest is still processed, with
an `unverified` custody entry. `prune_cases.py` removes a pruned duplicate's
custody log with it (the kept copy has the same digest).

Verified 2026-10-12 by an end-to-end API run (scratch DATA_DIR, 19 checks):
digest equals the uploaded bytes, acquired -> verified -> processed, a
one-byte append is caught by verify and by re-processing, a merge with an
altered source gets 409, an edited custody line breaks the chain, backfill
marks `retroactive` and skips cases that have a digest. Host parity
unchanged (63 files).

**29. Every rule is documented to the Sigma spec and the ADS framework, and
its status is earned, not assigned (2026-10-12).** `rule_meta.py` gives each
rule Sigma v2.1.0 metadata (UUID v4 `id`, `title`, `status`, `author`,
`date`/`modified`, `references`, `logsource`, `falsepositives`, `level`,
`tags` in Sigma's `attack.<tactic>` / `attack.t1234.001` form) and Palantir's
ADS sections (Goal, Categorization, Strategy Abstract, Technical Context,
Blind Spots and Assumptions, False Positives, Validation, Priority,
Response). `GET /api/rules` serves it; a finding's rule id in the Review tab
opens it, because accept/reject is exactly when an analyst needs the false
positives and blind spots.

- **Status is evidence.** `test` = fired correctly on real data with its
  false positives examined (the gotcha is cited in `validation`);
  `experimental` = synthetic hits only, or none. **No rule is `stable`**:
  Sigma means "may be used in production", and one customer's corpus plus
  synthetic files is not that. Result: 16 test, 4 experimental (R1002 and
  R3002 synthetic-only - R3002's real hits were gotcha #22's decoding bug;
  R3003 has only ever matched denied traffic; R3006 not measured).
- **Metadata, not an export.** The detection stays SQL on this tool's
  canonical schema. A Sigma `detection:` block written from it would look
  portable to other SIEMs and not be - that needs field names from a shared
  taxonomy first (OCSF, the schema step still to come).
- **The tags cannot drift from the SQL.** `tests/check_rule_meta.py` (stdlib
  + duckdb) fails if a rule lacks metadata, its documented techniques differ
  from the ATT&CK ids its SQL writes, a status is not Sigma's, or an id
  repeats. R1001/R1003/R1004 are untagged on purpose and say why.
- `date` is 2026-09-15 for every rule - the first commit, the earliest the
  history shows; the rules predate it.

**`docs/STANDARDS.md` is the one-page map** of every pipeline step to its
standard (or "internal method", with the nearest framework named and the
method written out - risk ranking, TP/BTP/FP, rule validation, escalation
patterns). The user's requirement since 2026-10-12 is that every step cite
one; update that table whenever a step changes.

**31. The review log is hash-chained too, and old decisions are sealed, not
rewritten (2026-10-12).** `hashchain.py` is the chain custody.py had,
shared: `review.append()` and `custody.record()` both go through it. Review
files written before carry unchained lines; the first chained decision's
`prev` is `seal:<SHA-256 of every byte before it>`, so from then on an edit
to an old decision is caught ("the earlier unchained entries were
changed"). The store's 2 review files are unsealed until their next
decision, and the Review tab says so. A custody log is chained from line 1,
so `custody.verify_chain()` treats any unchained line in it as a problem.
Verified: the custody logs written by the old code still verify, the
custody E2E (19 checks) passes on the refactor, and a seal/edit/delete/
append test set passes.

**30. Confidence is an Admiralty Code grade (2026-10-12).** `confidence.py`
rates each collapsed finding e.g. `B2`: letter = source reliability (B
documented mapping + acquisition digest verified; C retroactive/no digest or
a guessed field; D guessed columns; E failed integrity check; F no mapping
record; A never), number = credibility (1 same entity in another log source
of the case; 2 >=2 rule families and >=5 events; 3 otherwise; 4 no parsed
timestamp or `experimental` rule). Section 6's high/medium/low is kept and
derived (1-2 high, 3 medium, 4-6 low): on the 63-file corpus the only label
changes were 4 synthetic findings of experimental rules (medium -> low).
Reliability is added in the `/findings` route (needs manifest + custody);
the reasons show on hover in the Review tab. Verified: monsoon zip -
10.8.1.50 appears in both the firewall and ESXi members -> grade 1.

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
- **IAI-20 case list** - lives in the interim Overview (see Architecture).
- **IAI-18/19 Customers** - a customer is added on the Upload page only
  (see *Decisions*); the Customers page is read-only and shows, per
  customer, open cases of total / closed /
  highest open severity / last activity. FR-6.1 defines "open" by finding
  status, so until Sprint 3 a case is open while any finding group is
  **unreviewed** and the page footnotes that; the status rule is
  **IAI-79**. Cases without a customer (pre-FR-2.1) are a "No customer" row
  so the totals add up.
- Not yet: **IAI-24 resumable chunked
  upload** (Sprint 6). The upload is one request, so a dropped connection
  restarts a 10 GB file from zero.

Pages whose story has not come up render `pages/Placeholder.jsx` and appear
dimmed in the menu (`ready: false` in `components/Sidebar.jsx`). Flip the flag
when a page is built. Page *content* is still Thai wherever its story has not
restyled it yet. The shell, login, upload, overview and customers pages are
English, as the Figma is.

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
- **All UI text is English (2026-10-05)** - the Thai still left in the case
  (Result) page, review panel, analysis panel, events table, `format.js` labels
  and `api.js` error messages is to be translated, not kept alongside. Code
  comments were always English.
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

`.env` (gitignored) holds `GROQ_API_KEY`, `GROQ_MODEL`
(`qwen/qwen3.8-27b`), and optionally `MAX_EVENTS_FOR_ANALYSIS` (15 — set by
measurement, see the sweep table in gotcha #5). Copy `.env.example` to start. `docker compose`
auto-loads it for `${VAR}` substitution in `docker-compose.yml`.

## Common commands

```bash
docker compose up -d --build --force-recreate      # rebuild + restart
                                                   # (also rebuilds the UI)
docker exec forensic-analyzer-forensic-analyzer-1 python tools/refresh_intel.py
docker exec forensic-analyzer-forensic-analyzer-1 python tools/backfill_custody.py   # dry run; --apply
docker exec -it forensic-analyzer-forensic-analyzer-1 \
    python tools/create_user.py add you@example.com --name "..." --role analyst
docker logs forensic-analyzer-forensic-analyzer-1 --tail 50

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

The Check Point benchmark is in the baseline but is not under `Logtest`, so
checking it means pointing the script at a copy of
`DATA_DIR/raw/<case_id>.csv` renamed back to
`Logs_Jun_24__2026_11_09_44_102_AM_Logs_Table.csv`.

**Real-world benchmark.** A Check Point export was analysed alongside the
human SOC report written from the same data ("Firewall Port Scanning &
Implied Rule Bypass", Jun 2026). The source file is **not** under
`d:\forensic system\Logtest` and searching there for it (by name, or by
grepping for `171.6.30.201`) finds nothing - it is preserved in the audit
trail as `DATA_DIR/raw/<case_id>.csv`, renamed to the case id, which is what
`raw/` is for. Original name:
`Logs_Jun_24__2026_11_09_44_102_AM_Logs_Table.csv`. The benchmark is still
reproducible; don't conclude it is lost.

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
`rows / flagged / per-rule` counts for **70 files, 660,691 rows, 162,145
findings**, asserted by `tests/check_parity.py`. A silent drop to 0 findings
is exactly the failure mode gotcha #2 describes, and a *plausible* wrong
finding is gotcha #22.

The four anchors still worth knowing by heart, as of 2026-09-15:
`log_13_.csv` 65534/11324 · `src10-8-3-215.csv` 25579/**18888** ·
`log_22_.csv` 20530/14838 · `auth.log` 776/329. Two of those moved from the
numbers recorded before that date and both moves are deliberate:
`src10-8-3-215.csv` 25579 → 18888 from the R2002/R2003 deny restriction
(gotcha #23), `log_22_.csv` 14514 → 14838 from `R3004` (+324), the
threat-intel rule of gotcha #17, which postdates the original figure.

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
set `DATA_DIR` to a scratch folder, then `storage.create_case(...)` +
`pipeline.process_case(case_id, Path(file), kind)` per file. That
reproduces the baseline anchors exactly except the intel rules
(`R3003`-`R3006`), because `DATA_DIR/intel/` is empty - so `log_22_.csv`
gives 14514, not 14838. It is how gotcha #24 was measured while the Docker
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

Known, not investigated: the ESXi `auth.log` has no year in its timestamps,
and its `min(ts)` comes out as **2014-07-02** while the file's max is
2026-01-10 - the year inference misplaces some rows, which will distort any
timeline built from that file.
