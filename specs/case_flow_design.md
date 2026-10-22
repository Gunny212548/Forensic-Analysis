# Case flow - design

Status: **draft for approval** (2026-10-20). Decisions D1-D5 are taken as recommended
(the user, 2026-10-20). Open questions at the end change the design; nothing is built.
Proposal page: https://claude.ai/artifact/XDFqhbqPKE4ENX52t9MvdN. Standards basis:
`docs/STANDARDS.md`, section *Proposed: the analyst flow* (draft on this branch); which
documents were read, with the page of every sentence relied on: `docs/standards/SOURCES.md`.
A standard not marked read there is cited as aligned-with only.

## Why

An analyst working one case today walks 8 steps across 3 menu groups and reviews in two
places. A case page is called "Reports" and has no reports; a finding carries two status
lines (review and lifecycle) with nothing saying which comes first; Timeline and Attack
Graph are empty until Analyse is pressed on another page; no page says what is left before
the case can close. The user's words: the workflow is confusing, it should go node to node.

## Decisions taken

| # | Decision | Standard behind it |
|---|---|---|
| D1 | One status line per finding: Unreviewed -> Open -> Investigating -> Contained -> Resolved. Rejecting a workflow finding in triage closes it as a false positive. Both logs stay as they are. | NIST SP 800-61r3: triage and validation (RS.MA-02) precede analysis (RS.AN) and mitigation (RS.MI); ISO/IEC 27001 A.8.15 for the logs |
| D2 | High/critical findings are reviewed one by one. Medium/low/informational may be decided per rule in one action, still recorded as one decision per finding. The report gate counts both. | Sigma 2.1.0: "While `low` and `medium` level events have an informative character, events with `high` and `critical` level should lead to immediate reviews by security analysts"; CSF DE.AE-08; FIRST 2.1, 5.2 ("Recurring cases that can be automated should be identified and automated"); the procedure itself is an internal method |
| D3 | The AI step comes after Respond and is fed only findings that are not rejected; it can still be run from Triage on. A narrative whose input changed is marked stale. | NIST AI RMF 1.0 GOVERN / MANAGE; NIST AI 600-1 risks Confabulation and Human-AI Configuration ("automation bias, over-reliance") |
| D4 | Menu: Overview, Upload, Cases, Findings, Customers, Settings. Timeline, Attack Graph, ATT&CK Map and Reports leave the menu and live in the case's steps. Old links redirect. | ISO 9241-110:2020 (not read - aligned with only); old links redirect so a link pasted into a ticket still opens its case (CSF RS.AN-06: records' provenance preserved) |
| D5 | Build the case-flow shell first, then put IAI-60, 61, 59, 55 into their steps. Close IAI-50, 51, 53, 54, 56 with evidence. Every story updates its own `docs/STANDARDS.md` row before it closes. | - |

## Requirements (EARS)

Flow
- R1. When an analyst opens a case, the system shall show the six steps Ingest, Triage,
  Investigate, Respond, Analyse, Report in that order, each with its state and what remains.
- R2. The system shall compute each step's state on the server from the existing records
  (manifest, custody log, review log, finding registry, analysis cache); the browser shall not
  derive it.
- R3. The system shall show the first step that is not done as the recommended one, and shall
  not change the page the analyst is on by itself. Every step already reached shall stay open
  to the analyst.
- R4. Each step shall name the standards it follows. A step without at least one standard
  marked read in `docs/standards/SOURCES.md` shall fail the test suite.
- R5. While the AI provider is unavailable, every step except Analyse shall work unchanged,
  and Analyse shall say the provider is unavailable and can be skipped (IAI-59).

Triage (D1, D2)
- R6. When an analyst rejects a high or critical finding whose lifecycle is Open, the system
  shall record the review decision and a lifecycle entry Open -> Resolved with classification
  false positive, summary `Rejected in triage: <reason>` and the reviewer as actor and
  assignee (exception: Q1).
- R7. When a rejection made in triage is undone, the system shall return the finding to Open
  with a lifecycle entry that says so.
- R8. When an analyst starts investigation on a finding that is Unreviewed, the system shall
  refuse it (409) and say the finding must be triaged first. Findings already past Open keep
  their state.
- R9. When an analyst decides a rule's medium/low/informational findings in one action, the
  system shall append one decision per finding key, in one hash-chain write, and shall refuse
  the action (400) if any key in it is high or critical.
- R10. The report gate shall be open only when no finding of the case is Unreviewed.

Analyse (D3)
- R11. The AI input shall exclude every finding whose current review status is Rejected, in
  both the single-call and the map-reduce path, before the top-N cut.
- R12. Each analysis shall record the hash of the rejected-key set and the time of the case's
  last `processed` custody entry; when either differs now, the analysis shall be reported
  stale.

Navigation (D4)
- R13. `#/reports/<case>[/<tab>]`, `#/timeline/<case>`, `#/attack-graph/<case>` and the older
  `#/result/...` shall redirect to the matching step of `#/case/<case>/<step>`.

## Architecture

### Backend

`app/services/case_flow.py` (new, read-only)
- `STEPS`: the six steps, each `{id, title, standards: [...]}` - the single place the UI and
  `docs/STANDARDS.md` read the standards from. `tests/` fails if a step has no standard.
- `build(case_id, manifest) -> {"steps": [...], "recommended": id}`; each step
  `{id, state, remaining, total, reason}` with state one of
  `done | active | blocked | not_started | optional | stale | unavailable`:

| Step | done when | blocked when | remaining |
|---|---|---|---|
| ingest | `status == ready` and custody chain intact and last integrity check passed | `failed` (reason from manifest) | - |
| triage | no finding Unreviewed | ingest not done | Unreviewed keys (high/critical shown apart) |
| investigate | every tracked, not-rejected finding has an assignee and is past Open | triage has high/critical left | tracked findings still Open |
| respond | every tracked, not-rejected finding is Resolved | - | tracked findings not Resolved |
| analyse | an analysis exists and is not stale | never (optional; `unavailable` when the provider fails its check) | - |
| report | gate open and a final report exists (IAI-72/73) | gate closed | Unreviewed count |

- Reads only what `case_views.findings_view`, `review.current`, `lifecycle.state`,
  `custody_view` and `storage.load_analysis` already return; cached on the same
  `filestamp.of()` fingerprint as `findings_index` (gotcha #49/#51).

Routes (`app/routers/cases.py`)
- `GET /api/cases/{id}/flow` -> `case_flow.build`. Read-only, any signed-in user (as the
  other reads; ADR-3).
- `POST /api/cases/{id}/review/bulk` `{rid, action: accept|reject, reason_code?, note?}`
  -> R9. `_authorize(request, authz.REVIEW, company_id)`. `rid` must match `^R\d{4}$`;
  keys are the case's own collapsed findings for that rule below high; returns the count.
- `POST /api/cases/{id}/review` (existing): on `reject` of a tracked finding in Open, also
  appends the lifecycle dismissal (R6); on `unreview` of a triage-dismissed finding, the
  return to Open (R7). Both entries go to the same review log, so one file stays the audit
  trail.

`lifecycle.py`
- New entry action `dismiss` (Open -> Resolved, false positive, written only by the review
  route) and `restore` (Resolved-by-dismissal -> Open). `investigate` refuses an Unreviewed
  finding (R8). `summary()` already leaves false positives out of MTTC.

`hashchain.py`
- `append_many(path, entries)`: one lock, one read of the file, N chained lines. Needed
  because `append()` re-reads the whole file per entry: a 1,516-group rule would read the
  log 1,516 times.

`db.top_distinct_findings` and the map-reduce pool (`analysis_jobs`)
- Take `exclude_keys`; filtered in SQL before `LIMIT` (a temp table of keys), keeping the
  total `ORDER BY` tiebreak of gotcha #37. `_meta.input` gets `rejected_sha256` and
  `processed_at`; `GET /analysis` adds `stale` (R12). This also closes the open item "a
  cached narrative is never marked stale after a re-process" (gotcha #48).

`llm.py`
- `httpx.TransportError` / `TimeoutException` -> `AnalysisUnavailable` -> HTTP 503 with
  "The AI provider at <url> is not reachable" (R5, IAI-59).

### Frontend

- `pages/CaseFlow.jsx` (new) replaces `CaseView.jsx` as the case page:
  `#/case/<id>/<step>`. A header (case, customer > project breadcrumb, evidence digest)
  and `components/StepBar.jsx`: an ordered list of six steps, each with its state chip and
  remaining count, `aria-current="step"` on the open one, one **Next step** button. No
  automatic switching (memory: keep UX simple).
- What each step shows - all existing components, moved, not rewritten:

| Step | Contents |
|---|---|
| Ingest | upload progress, Mapping note + coverage, Evidence (custody), Events table |
| Triage | ReviewPanel: high/critical one by one; medium/low grouped by rule with "Accept all" / "Reject all" (reason required) |
| Investigate | tracked accepted findings with assignee and status, each opening `#/finding/...`; attack graph and risk ranking (per case until IAI-61); timeline (data timeline from IAI-60) |
| Respond | Lifecycle per tracked finding, MTTC against target |
| Analyse | Analyse button, summary / chain / recommendations / AI timeline, grounding warnings, stale and unavailable banners |
| Report | gate state, VERIS, STIX / Navigator exports, final report (IAI-72/73) |

- Each step's footer lists its standards from `/flow`.
- One status line (D1): `format.js` `stage(review, lifecycle)` -> Unreviewed / Open /
  Investigating / Contained / Resolved (+ verdict), used by the Findings page, the finding
  page and Triage. A tracked finding Rejected before this change and still Open is shown as
  "Rejected - not closed" and listed under Respond; it is **not** backfilled, because the
  tool must not write a decision on an analyst's behalf.
- `pages/Cases.jsx` (new, menu): cases of the scoped customer with project, status, the
  recommended step and open findings - from `GET /api/cases` plus `/flow` per row (or a
  `step` field added to the case list if that is slow; measured before choosing).
- `Sidebar.jsx`: the D4 menu. `App.jsx`: the R13 redirects, kept as one table.
- Overview, Upload ("Open case"), Customers and the finding page link to `#/case/...`.

### Security

| Check | Result |
|---|---|
| Authentication | unchanged: every `/api/*` behind the session middleware |
| Authorisation | `review/bulk` asks `authz.can(REVIEW)` like `review`; the dismissal is written by the review route under the same check; `/flow` is a read |
| Input | `rid` regex, `action` enum, `reason_code` from `review.REASON_CODES`, note <= 2,000 chars; bulk refuses high/critical keys |
| Customer isolation | every path through `storage.case_dir`; `check_customer_isolation` extended to `/flow` and `review/bulk` |
| Audit | every decision, dismissal and restore is a hash-chained line in the case's review log; `append_many` keeps one chain |
| Output | no new field carries account data beyond the existing reviewer email |
| CSRF | SameSite=Lax + JSON bodies, as today |

## Tests

- `tests/check_case_flow.py` (new, container, gen_usecase case): the step states from a fresh
  case to closed; every step has a standard; R6/R7 dismissal and undo with the chain intact;
  R8 refusal; R9 bulk writes N lines, refuses a high key, one chain; R10 gate; R11 rejected
  keys absent from the built prompt (no model call); R12 stale after a reject and after a
  re-process; R5 with the provider pointed at a closed port (503, other routes 200).
- `check_workflow`, `check_customer_isolation`, `check_mcp`, `check_authz` re-run; expected
  change: `check_workflow` cases that start investigation on an Unreviewed finding (R8).
- `bench_llm` x3 after R11: still byte-identical across runs; prompt hash changes only when a
  rejection exists (the bench has none).
- Browser at `127.0.0.1:8199`: the six steps on the ESXi, Entra and Palo Alto cases; every
  old link in R13; Next step; keyboard focus on the step bar.

## Stories (D5) - to create in Jira after approval

1. **Case flow shell**: `/flow`, StepBar, CaseFlow with existing components moved, Cases
   page, menu, redirects (R1-R4, R13). First.
2. **Triage in one place**: D1 line, dismissal and restore, bulk by rule, gate scope (R6-R10).
   Closes IAI-55's gate part; IAI-51/53/54 close with evidence before it.
3. **IAI-60** data timeline in Investigate.
4. **IAI-61** per-finding graph in Investigate.
5. **AI after decisions + IAI-59**: R5, R11, R12.
6. Close IAI-50, 51, 53, 54, 56 now, with evidence comments.
Standards upgrades (OCSF verdict, validation records per ISO/IEC 27041, MTTC as an SP 800-55
measure) are separate stories, after these.

## Revision 2 (2026-10-20, the user, after IAI-89) - supersedes the parts it names

Decided:
- **No guessing what a log is.** The system identifies every uploaded file
  automatically, by the Sigma logsource taxonomy (`sigma-appendix-taxonomy.md`, v2.1.0)
  plus a documented format profile per product. Heuristic column matching goes. Where
  the taxonomy names the source it is used as is (`windows/security`, `windows/sysmon`,
  `linux/auth`, `linux/sshd`, `azure/signinlogs`, `m365/exchange`); where it does not
  (Palo Alto, Check Point, Fortinet, Cisco ASA/FTD, CrowdStrike, VMware ESXi - verified
  absent) the file is `category: firewall` or the nearest category, with the product kept
  as a custom logsource value, and the case says so.
- **Formats still missing are researched and tested**: each new product needs its
  vendor's format document and a real file, and a test that the file is identified as
  that product (and that the others are not).
- **Triage must be complete before the next step** (replaces R3 for steps after Triage):
  Investigate onwards are locked, and the server refuses to start an investigation while
  the case has an Unreviewed finding.
- **No assignee dropdown.** The finding's owner is the signed-in account that starts the
  investigation; the reviewer of every decision, Undo included, is the signed-in account
  (already so since FR-7.6).
- **Attack Path becomes its own step after Respond, before Report**, built only from
  validated findings; exported as MITRE Attack Flow 4.0. The case-wide graph leaves
  Investigate. The separate Analyse step goes: AI assists in Triage (a suggestion, the
  analyst decides) and drafts the report narrative.

Order: Ingest -> Triage -> Investigate -> Respond -> Attack Path -> Report.

Still open:
- Q5 Attack Path input: findings triaged correct (accepted/modified) and not closed as
  false or benign positive? (recommended)
- Q6 AI suggestion in Triage shown on request rather than up front, so the analyst looks
  at the evidence first (recommended; AI 600-1 Human-AI Configuration names automation
  bias and over-reliance); every decision records what the AI suggested.
- Q7 Remove Groq from code, config and documents, keeping its provider-independent
  lessons rewritten for the local model (recommended).
- Q8 A file whose format is not supported: kept as evidence (hash, custody) but not
  analysed (recommended), or refused at upload.
- Q9 ESXi lines with no vendor document ("observed"): keep, or treat as guessing and drop.

## Revision 3 (2026-10-20, the user) - the purpose, and Respond removed

Purpose, confirmed by the user: a **forensic tool for log files**. It identifies what
each log is, puts every event in one timeline, helps the analyst find the attack
events, and turns them into an attack timeline, an attack path and a graph of what the
attacker did - which command, from which host, to which host. Severity grading stays
only as a hint for what to look at first.

Flow: **Ingest -> Timeline -> Attack events (system/AI suggests, analyst confirms,
per event) -> Attack timeline -> Attack path / graph -> Report.**

- **Respond is removed** (the user's call): no Contained / Resolved tracking, no
  containment-action record, no MTTC. What to do next goes in the report as
  recommendations. Code that depends on the lifecycle - `lifecycle.py`, the Findings
  page status filters, the Overview's MTTC KPI, the Customers page's open/closed case
  count, IAI-50 - is to be removed or re-based in a story of its own; nothing is
  deleted before that story's design is agreed.
- **The event schema must carry who / where / what**: actor, source host, destination
  host, action, command or process, outcome. The canonical schema today keeps a
  command only inside `raw`. Proposed basis: OCSF event classes (Authentication,
  Network Activity, Process Activity `cmd_line`) - `docs/STANDARDS.md` row 4.
- **AI in the attack-event step** suggests, cites event ids, and is checked before an
  analyst sees it; its rules and their sources are in the AI section of the proposal.

## Revision 4 (2026-10-20, the user) - detection from standard rules and data only (option C)

The 20 in-house rules (R1000-R3006, `rules.py`) are retired. What suggests attack events
from now on comes only from published rules and published data:

1. **SigmaHQ rules** (3,799 at commit time of the count; Detection Rule License 1.1 -
   use is free, but every match shown must name the rule's author) for the logsource
   identify.py found. Coverage measured 2026-10-20: Entra ID sign-in 18, Linux sshd 1 +
   syslog 22, Windows 2,424 (no reader yet); **PAN-OS, Check Point and FortiGate traffic
   0** (one generic firewall rule; the 7 FortiGate rules are for admin/config logs).
2. **Correlations taken from the examples in the Sigma correlation specification v2.1.0**
   (logic and format both published): "Many failed logins" (`event_count`), failed logons
   with many accounts per source (`value_count`), "Multiple Failed Logins Followed by
   Successful Login" (`temporal_ordered`), "Possible Exfiltration" (`value_sum` of
   bytes). Port scan and beaconing have no published example and are dropped.
3. **Threat-intel matching** of addresses against the feeds in `DATA_DIR/intel/`
   (STIX 2.1 and the published block lists) - standard data, no logic of ours beyond
   the equality join.

Consequences, stated so they are not discovered later:
- Firewall traffic files keep only (2)'s exfiltration sum and (3); the brute-force,
  scan, policy-gap and beaconing findings the corpus has today disappear. The analyst
  reads the timeline, with the AI suggesting events (AI section).
- Sigma rules match on their own field names: events must be stored in a standard
  schema (OCSF, revision 3) and mapped with pySigma's OCSF processing pipeline, or an
  equivalent mapping we document.
- pySigma (LGPL-2.1, 2.0.1) has no DuckDB backend; its SQLite backend claims every
  correlation type but uses SQLite-only SQL. A spike decides between running that
  output on DuckDB, evaluating rules in SQLite, or a converter of our own for the
  subset used.
- `severity.py` escalation, `rule_meta.py` (the ADS documentation of our rules),
  `areas.py`, confidence's rule families and the R-ids in the baseline, tests and
  related findings all depend on the 20 rules and are re-based in the stories below.

Still open:
- Q10 Correlation thresholds: the spec examples' values (e.g. >= 100 failed logins in
  an hour) as defaults, or set by the analyst per case? Proposed: spec values as
  defaults, shown on the finding, adjustable per case later.

Stories (to create): (a) spike - Sigma rules on DuckDB, and the OCSF field mapping;
(b) OCSF event store; (c) Sigma rule engine with DRL attribution, SigmaHQ release
pinned and its hash recorded; (d) the four spec correlations; (e) retire rules.py and
re-base everything that reads R-ids; (f) baseline re-taken and explained.

## Revision 5 (2026-10-20, the user) - the in-house rules stay; SigmaHQ is added beside them

Supersedes revision 4's retirement of the in-house rules; the rest of revision 4 stands.
Taken after spike (a) (`docs/adr/ADR-006-sigma-evaluation.md`): on the real Entra export
2 of 19 SigmaHQ rules matched anything (one of them every row), SigmaHQ publishes no
correlation rule and no failed-login base rule, so retiring R2005 would have lost the
password spray the corpus holds.

- **The 20 in-house rules (R1000-R3006) stay the primary detection**, as they are: each
  carries a Sigma level and ADS documentation (gotcha #29) and is an "internal method" in
  `docs/STANDARDS.md`.
- **SigmaHQ rules run in addition**, on the logsources identify.py names, as ADR-006
  decides: DuckDB dialect of pySigma's SQLite backend, the file's own fields, "not
  applicable" per rule and file, author / status / level shown (DRL 1.1), SigmaHQ commit
  and hash recorded on the case.
- **Every finding says where it came from**: in-house (R-id) or SigmaHQ (rule id, author).
  Sigma findings are stored apart, so the R-rule counts in `tests/baseline.json` do not move.
- **The spec correlations are dropped from scope**: R2000, R2005 and R2006 already cover
  many failed logins, spray and multi-source logins. Q11 is closed; Q10 applies only if a
  spec correlation is added later.

Stories, replacing revision 4's list: (a) spike - done, ADR-006; (b) OCSF event store -
still needed for who / where / what (revision 3), no longer a detection prerequisite;
(c) SigmaHQ engine beside `rules.py`, with provenance and "not applicable"; (d) and (e)
dropped; (f) baseline: in-house counts unchanged, Sigma findings measured separately.

Still open: Q12 (portal CSV value vocabulary) and Q13 (rules that match every row), both
in ADR-006. Q12 decided 2026-10-22: map only pairs a Microsoft page documents side by side,
otherwise "not applicable" for the CSV.

## Revision 6 (2026-10-20, draft) - what each step of the forensic flow does

Defines the six steps of revision 3, using the standards review in
`docs/standards/forensic-process.md` (SP 800-86, RFC 3227, ACPO v5, SP 800-92, IR 8354 -
all read). Replaces the step table, R1 and the "What each step shows" table of revision 1
for the new flow. Nothing is built. Decisions D6-D9 at the end of this revision: the flow
runs on the **project** (one investigation), each upload is one evidence item.

Common to every step (ACPO principles 1 and 3, RFC 3227 §3.1, SP 800-92 fn 23): nothing
changes `raw/` or `raw_events`; every analyst action is a hash-chained line; a view or a
filter never deletes. A step may be revisited at any time (SP 800-86 fn 14: examination and
analysis repeat).

| # | Step | SP 800-86 phase | Question it answers |
|---|---|---|---|
| 1 | Ingest | Collection | What is this evidence, where did it come from, is it intact? |
| 2 | Timeline | Examination | What happened, in order, across every source? |
| 3 | Attack events | Analysis (validation) | Which events are part of the attack? |
| 4 | Attack timeline | Analysis (reconstruction) | In what order did the attack happen, and where are the gaps? |
| 5 | Attack path / graph | Analysis (reconstruction) | Who or what moved from which host to which host, doing what? |
| 6 | Report | Reporting | What can be stated, how strongly, and what can't be? |

### 1. Ingest

- **System**: hash on arrival and before every run (have); identify each file, read it through
  its profile or keep it unread as evidence (have, IAI-92); coverage per file (have);
  **reproducibility record** per run on the custody log - application commit, profile id,
  rule set (in-house rules version + SigmaHQ commit and hash), intel feed hashes (new).
- **Analyst**: states the case question and known leads (Q15); records each file's
  provenance - source system, export method and filter, exported by / when, the source's
  time zone and any known clock offset (Q16).
- **Output**: evidence items with digest, identification, coverage, provenance; the question.
- **Done when**: every item is processed with its custody chain intact, and every item that
  was not analysed says why. A missing provenance field is a warning, not a block.
- **Standards**: SP 800-86 §3.1.2; RFC 3227 §2, §3.2, §4.1; ACPO P1, P3, 5.5, 5.10.3.
- **Sub-processes** (walked through with the user, 2026-10-20):

| # | Sub-process | By | Today |
|---|---|---|---|
| 1.1 | Open or pick the investigation (project); record its question and known leads | analyst | project yes, question no |
| 1.2 | Receive the file (10 GB after decompression, .gz, .zip) | system | built |
| 1.3 | SHA-256, who / when, custody chain starts | system | built |
| 1.4 | Provenance: source system, export method and filter, exported by / when, source time zone, known clock offset | analyst | missing |
| 1.5 | Identify the log; unknown or unreadable kept as evidence, not analysed | system | IAI-92 branch |
| 1.6 | Read into events; original line and timestamp kept; time normalised to GMT+7 | system | built |
| 1.7 | Coverage: rows read / not read, fields filled | system | built |
| 1.8 | Detection rules (in-house + SigmaHQ) | system | **open - to be discussed (the user)** |
| 1.9 | Reproducibility record: app, profile, rule and feed versions | system | missing |

- **D10 - source time zone (1.6).** A zone the analyst records in provenance (1.4) replaces the
  GMT+7 assumption for that source; without one, GMT+7 is assumed and flagged
  `timezone-unconfirmed` as today. Every change is a recorded, reversible entry (RFC 3227 §2:
  "For each timestamp provided, indicate whether UTC or local time is used").
- **D11 - duplicate evidence.** A file whose SHA-256 matches an item already in the
  investigation is accepted as its own evidence item, with a warning naming the match:
  receiving the same file twice is itself a custody fact. Its events are not counted twice
  on the timeline.

- **D12 - what the system knows about an event comes in three layers** (the user, 2026-10-20).
  A system cannot read an event the way an analyst does; everything it "knows" is written
  down in advance, and an entry's meaning "often depends upon the context surrounding it"
  (SP 800-92 §5.2.1).

| Layer | Question | Known from | Example: `Failed password for root from 203.0.113.5` |
|---|---|---|---|
| A. Event type | What is this event? | the log source's own documentation - a fact, no judgement | sign-in failed, wrong password, account root, over SSH |
| B. Known pattern | Does it fit a known attack pattern? | rules (in-house + SigmaHQ), threat intel, counts and sequences | 50 failures in 10 minutes from one address (R2000); address in a feed |
| C. Context | Is it unusual here? | facts computed from the investigation's own data (SP 800-92 §5.2.2: newness, time of day, frequency) | address never seen before; 03:00; account never used from abroad |
| Decision | Is it part of the attack? | **the analyst**, from A + B + C | confirmed in step 3 |

  Every event gets layer A, not only flagged ones. Layer B finds only what it was written
  for (SP 800-86 fn 107). Layer C states facts and never declares an event dangerous.
- **D13 - R1000-R1004 become layer A.** They name what an event is (sign-in failed, sign-in
  succeeded, account does not exist, SSH connection opened, password changed); they stop
  being findings to review. The correlation rules keep counting the same events. Cost:
  findings R1000-R1004 leave `tests/baseline.json` and the workflow counts - re-taken and
  explained in the story that does it.
- **D14 - layer A vocabulary from OCSF, read first.** The event classes (Authentication,
  Network Activity, Process Activity, Account Change) are read from the OCSF schema and laid
  against the events of our real files before a list is proposed. Each profile maps its
  vendor's messages and codes onto it, every line citing the vendor document.
- **D15 - an event no profile can type is shown as "type unknown"**, on the timeline like any
  other, and listed by message pattern as "not yet understood" (SP 800-92 §5.2.1).

### 2. Timeline

- **System**: one time-ordered list of every event of the investigation, each with its source
  file, original timestamp text (`ts_raw`) and raw line beside the normalised fields; the
  zone each source was read in and any declared offset applied; per source, first and last
  event and the silent periods drawn on the time axis (no threshold of ours); rule and
  SigmaHQ matches shown as marks on events, not as a separate list. Lines a reader could not
  parse are reachable from here.
- **Analyst**: filters (source, time window, address, account, host, rule), pivots from any
  value to every event across sources sharing it, starts from a lead of the question.
- **Output**: none written - this step is a view (SP 800-92 fn 59: filtering does not alter
  the logs). Saved filters are a convenience, not evidence.
- **Done when**: never blocks; it is the workspace.
- **Standards**: SP 800-86 §3.2, §6.4.2; SP 800-92 §3.2 (normalisation), §5.2.1; IR 8354 §2.3,
  §4.7.1; RFC 3227 §2 (clock vs UTC).

### 3. Attack events

- **System**: suggestions come from three sources, each labelled - an in-house rule (R-id),
  a SigmaHQ rule (id, author), the AI (on request, Q6; cites event ids; checked before
  shown). Order of review is a hint from SP 800-92 §5.2.2's factors (rule level, newness,
  intel match, frequency). A rule that could not run on a source is listed as not applicable.
- **Analyst**: confirms or rejects (with a reason), per the unit decided in Q14; may add an
  event no rule or AI suggested. Records what the AI suggested beside the decision.
- **Output**: the set of confirmed attack events, each decision a hash-chained line
  (review log, gotcha #19/#31).
- **Done when**: no suggestion is left undecided (revision 2's gate), **or** the analyst
  records that the remaining ones are out of scope, with a reason.
- **Standards**: SP 800-86 §6.4.2 (validate interpreted data; fn 107 absence of an alert is not
  benign); FIRST 5.2; IR 8354 §4.7.1 (verify AI results); AI 600-1 Human-AI Configuration.

### 4. Attack timeline

- **System**: the confirmed events only, in time order, grouped into steps by ATT&CK tactic
  where the event carries one; gaps between steps are drawn as gaps with their duration;
  every time shows its zone and whether it was inferred (`year-inferred`,
  `timezone-unconfirmed`).
- **Analyst**: writes, per gap, what is assumed and why (SP 800-86 §6.4.3: "assumptions
  regarding the missing data"); records alternative hypotheses, each with supporting and
  contradicting events; may mark the reconstruction "no conclusion yet".
- **Output**: the attack timeline with assumptions and hypotheses - all hash-chained notes.
- **Done when**: every gap has a note or is marked unexplained; at least one hypothesis is
  recorded, or "no conclusion yet".
- **Standards**: SP 800-86 §3.3, §3.4 (alternative explanations), §6.4.3; IR 8354 §4.7.

### 5. Attack path / graph

- **System**: built from the confirmed events only (Q5): a node is an address, host or
  account **as observed in the logs** - never an identity; an edge is an action from one
  node to another, labelled with what the event says (command, service, outcome) and citing
  its events. NAT / spoofing caveat shown on external nodes (SP 800-86 §6.4.4). Exported as
  MITRE Attack Flow 4.0. Same static-SVG geometry as today (gotcha #10).
- **Analyst**: reviews it; a node or edge with no confirmed event cannot be drawn.
- **Output**: the graph and its Attack Flow export.
- **Done when**: generated from the current set of confirmed events (stale if the set changed).
- **Standards**: SP 800-86 §3.3 (people, places, items, events and how they relate), §6.4.4;
  IR 8354 §4.7.1 (link analysis); Attack Flow 4.0.
- **Limit**: "which command" needs a command field; today a command exists only inside `raw`
  (revision 3, OCSF). Until then edges carry service / action / outcome.

### 6. Report

- **System**: drafts sections from records, never from memory: the question; evidence items
  with digests and provenance; method (the reproducibility record); attack timeline; attack
  path; hypotheses; **limitations** (items not analysed, rules not applicable, coverage,
  inferred times, silent periods, missing provenance); conversions applied (time zone,
  field mapping); recommendations, including logging improvements. The AI may draft prose;
  every factual sentence cites events, every opinion is marked as one.
- **Analyst**: edits, approves, signs.
- **Output**: a report file with its own SHA-256 on the custody log; STIX / VERIS / Navigator
  exports as today.
- **Done when**: approved by an analyst.
- **Standards**: SP 800-86 §3.4; ACPO 6.3, 6.5.3, 6.5.4; RFC 3227 §2.4.

### Decisions (revision 6, the user, 2026-10-20 - all as proposed)

- **D6 (Q17) - the flow runs on the project.** A project is one investigation; each upload is
  an evidence item in its Ingest step; steps 2-6 run across all of the project's items. An
  upload with no project is a one-item investigation. Today an investigation with a
  firewall export, an auth log and an Entra export is three cases whose timelines cannot
  meet unless zipped or merged. Cost: IAI-89's case page becomes the evidence-item page and
  the step bar moves to the project page; rules still run per item (their SQL is per DuckDB),
  the timeline and everything after it read across items.
- **D7 (Q14) - confirm per finding group, with exceptions.** The unit is the collapsed finding
  (`rid|srcip|username`, gotcha #19). Inside a confirmed group the analyst may exclude single
  events; an event no rule or AI suggested may be added on its own. One finding can hold
  thousands of events (a Palo Alto file: 18,888 flagged rows), so per-event-only is not
  workable.
- **D8 (Q15) - the case question is required before the report.** Asked at Ingest, editable
  any time, the report cannot be approved without it and opens with it.
- **D9 (Q16) - provenance is optional.** Entered at upload or later in Ingest; a missing field
  is a warning, never a block, and is listed under the report's limitations.

Still open from revision 2: Q5 (attack path from confirmed events only - written that way
above) and Q6 (AI suggestions on request).

## Revision 7 (2026-10-21, draft) - practitioner methods added to steps 2, 4, 5 and 6

The user asked how human analysts do this (2026-10-21). `docs/standards/practitioner-methods.md`
read five published methods (Carrier & Spafford 2004, the Diamond Model 2013, Casey 2002,
Heuer ACH, Gudjonsson's super timeline). They are methods, not standards: each addition below
cites one beside the standard the step already cites. Nothing is built; each line needs the
user's approval as revision 6 did.

- **Step 2 Timeline - temporal proximity.** From any event, "what happened within N minutes
  of this", across every evidence item, in time order (Gudjonsson §4.3: look "for other
  objects in the timeline that are in temporal proximity to the known event"). N is the
  analyst's choice per view, never a threshold of ours. The pivot of revision 6 (every event
  sharing a value) stays; the two combine - same address, ±N minutes. MCP has both since
  `search_events` (`since` / `until`); the UI has neither.
- **Step 2 Timeline - rare values.** Per field (event type, account, destination port, ...),
  the values rarest in this evidence, rarest first (Gudjonsson §4.4, "least frequency of
  occurrence"; SP 800-92 §5.2.2 "newness"). A fact of layer C, never a finding. Behaviour
  profiles today rank only the *most* active.
- **Step 3 Attack events - unknown is shown.** Each confirmed event shows actor (account),
  source, target, action, result and direction, and an empty one says "unknown" instead of
  being left out (Diamond §4: "any empty features are now identified knowledge gaps").
  Result as Success / Failure / Unknown (Diamond §4.5.3).
- **Step 4 Attack timeline - hypotheses as a matrix.** Revision 6 already records hypotheses
  with supporting and contradicting events. Added: shown as Heuer's matrix (hypotheses
  across, confirmed events down, each cell consistent / inconsistent / not applicable);
  events consistent with every hypothesis are marked "not diagnostic"; the hypotheses are
  ordered by evidence *against*, fewest first, not by evidence for (Heuer ch. 8 steps 3-5).
  The analyst decides; the matrix is the audit trail (Heuer p. 105).
- **Step 5 Attack path - edges actual or hypothesised.** Each edge carries the Diamond
  activity-thread label: Actual (cites confirmed events) or Hypothesised (cites the
  analyst's written assumption), with a confidence and what the step provides the next
  (Diamond §8, p. 35). **This conflicts with revision 6 step 5** ("a node or edge with no
  confirmed event cannot be drawn") - see Q30.
- **Step 6 Report - certainty of the data, and rejected hypotheses.** Each statement's
  evidence carries a Casey level, computed where it can be: one unprotected log = C2,
  independent evidence items agreeing = C4, contradicted = C0, an address behind a known
  proxy or NAT = C1 (Casey §2.3, Table 1). It grades the data, not the conclusion. The
  report lists every hypothesis considered and why the rejected ones were rejected (Heuer
  step 7). Beside, not instead of, the findings' Admiralty grade (gotcha #30) - see Q31.

### Questions (revision 7)

- **Q30 - hypothesised edges on the attack path.** Revision 6 draws only what confirmed events
  show. The Diamond Model draws hypothesised arcs dashed, with the assumption written on them,
  so a gap is visible where it is. Proposed: allow them, dashed, never in the Attack Flow
  export as fact, and only from a note the analyst wrote - the system and the AI never add
  one. Or keep revision 6 and show gaps only on the attack timeline (step 4).
- **Q31 - Casey levels beside Admiralty.** Admiralty grades a finding (source reliability +
  credibility); Casey grades the data under a statement (corroboration across independent
  items). Proposed: Casey on the report's evidence lines only, Admiralty unchanged. Or one of
  the two.
- **Q32 - where it lands.** Proposed: temporal proximity and rare values in story 3 (data
  timeline, IAI-60); unknown features with story 5 (confirmed events); the matrix with step 4;
  edge labels in story 7 (`specs/story7_attack_path_mcp.md`); Casey with the report story.

## Open questions

- **Q1** A rejection for `better_technique` says the ATT&CK mapping is wrong, not that the
  activity did not happen. Proposal: it does **not** dismiss the finding; the UI suggests
  Modify instead. The other three reasons dismiss.
- **Q2** Does the report gate also need Respond done? Proposal: no - FR-12.4 asks only that
  nothing be Unreviewed; a report may describe an incident still being contained.
- **Q3** The Cases page and the customer profile both list cases. Proposal: Cases is the
  working list (step, open findings); the profile keeps its history view.
- **Q4** Add OCSF verdicts Duplicate and Insufficient Data now? Proposal: later, with the
  OCSF verdict story.
