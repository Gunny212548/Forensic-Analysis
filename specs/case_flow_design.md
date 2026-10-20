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
