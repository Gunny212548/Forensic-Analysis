# Standards traceability

Every step from upload to report, the published standard it follows, where it
is implemented, and how far it goes. Where no standard exists, the step is
listed as an **internal method**, with the nearest framework named and the
method stated so it can be checked rather than believed.

Status: ✅ implemented · ⚠️ partial · ❌ not yet

| # | Step | Standard | Implemented in | Status |
|---|---|---|---|---|
| 1 | Evidence acquisition and integrity | ISO/IEC 27037:2012, NIST SP 800-86, RFC 3227 (chain of custody), FIPS 180-4 (SHA-256) | `app/services/custody.py`, `app/routers/upload.py` | ✅ |
| 2 | Reading each log format | The log source's own format documentation (PAN-OS Traffic Log Fields, Check Point sk144192, Microsoft Entra sign-in log, Microsoft Graph signIn / signInStatus + AADSTS error codes, RFC 5424 / RFC 3164 (syslog header), Exchange Get-MessageTrace, OpenSSH `auth.c`, Linux-PAM `pam_unix`, FortiOS Log Message Reference) | `app/services/logsources.py`, `parsers.py` | ⚠️ 4 CSV log sources (PAN-OS, Check Point SmartConsole, Entra, Exchange) + 1 JSON (Entra via Azure Monitor) + 4 line formats (OpenSSH, Linux-PAM, VMware ESXi per Broadcom KB 321910, FortiOS) and ESXi lines read as *observed* (no published format, said so on the case); others are guessed and flagged; unreadable JSON records counted and reported; every case reports per-field coverage and rows not loaded |
| 3 | Time | ISO 8601 / RFC 3339, single zone (GMT+7, FR-10.1) | `app/services/pipeline.py`, `decode.py` | ✅ (a zone-less source is flagged timezone-unconfirmed; an RFC 3164 timestamp's missing year is inferred from the upload date and flagged year-inferred) |
| 4 | Canonical event schema | OCSF | - | ❌ own schema (`raw_events`) |
| 5 | Threat intelligence | OASIS STIX 2.1 / TAXII 2.1 | `app/services/intel.py` | ⚠️ STIX 2.1 bundles read (IP-equality indicators); no TAXII client - export a collection and drop the bundle in |
| 6 | Detection rules | Sigma rules specification v2.1.0 (metadata), Palantir ADS framework (documentation) | `app/services/rule_meta.py` | ✅ metadata; detection stays SQL |
| 7 | Technique classification | MITRE ATT&CK, CISA *Best Practices for MITRE ATT&CK Mapping* | `rules.py`, `rule_meta.py` | ✅ |
| 8 | Severity | Sigma `level`; escalation by ODNI Cyber Threat Framework stage | `app/services/severity.py` | ✅ |
| 9 | Confidence | Admiralty Code (NATO 6x6) | `app/services/confidence.py` | ✅ |
| 10 | Attack graph / chain | ATT&CK tactics, ODNI CTF stages | `db.build_graph` | ⚠️ graph exact; stages not labelled on it |
| 11 | Entity risk ranking | **Internal method** - see below | `db.risk_scores` | ⚠️ documented here |
| 12 | AI narrative | VERIS 1.4 (classification), NIST AI RMF 1.0 (governance) | `app/services/veris.py`, `analysis.py` | ✅ VERIS 4A computed from findings, validated against the VERIS schema, given to the model as fact; AI RMF alignment below |
| 13 | Analyst review audit trail | ISO/IEC 27001:2022 A.8.15 (logging) | `app/services/review.py`, `hashchain.py` | ✅ append-only, hash-chained; pre-chain decisions sealed |
| 14 | Finding lifecycle and MTTC | NIST SP 800-61 Rev. 3 (CSF 2.0: RS.MA-02, RS.AN-03, RS.MI-01, RS.MI-02) | `app/services/lifecycle.py` | ✅ Open / Investigating / Contained / Resolved; workflow admits Sigma high and critical |
| 15 | Report export | NIST SP 800-86 (reporting), OASIS STIX 2.1, ATT&CK Navigator layers | `app/services/attack_layer.py`, `stix_export.py` | ⚠️ Navigator layer (format 4.5) and STIX 2.1 bundle per case; the human-readable report not yet |
| 16 | Machine access to case data (MCP) | Model Context Protocol 2025-11-25; ISO/IEC 27037 (access to evidence recorded) | `app/mcp_server.py`, `hashchain.py` | ✅ read-only stdio server, 12 tools, every call in a hash-chained access log; no write tools, no free SQL |
| 17 | Finding ids and traceability | **Internal method**: `FD-YYYY-nnnn`, numbered per customer and year, in an append-only hash-chained registry (`hashchain.py`); every finding lists its source events, each with its file and the evidence digest (ISO/IEC 27037: evidence must be traceable to its source) | `app/services/finding_ids.py`, `case_views.py` | ✅ |
| 18 | Related findings | **Internal method**: findings are chained only through pivot hosts (a target that is also a source) over the whole case, and by account for a spray; a shared final target is not a relation. Nearest framework: ATT&CK tactic progression | `app/services/related.py` | ✅ |
| 19 | Overview detection areas | **Internal method**: every rule belongs to exactly one of six areas by the behaviour it detects; the card's number is findings in the workflow not yet Resolved, `New` is those still Open, `Total` is every finding of the area by Sigma level, the trend is findings first seen per day of event time. Nearest framework: ATT&CK tactics (too coarse on real data - two tactics hold ~98% of findings) | `app/services/areas.py`, `overview.py` | ✅ |

What each implemented step does, and what it does not claim, is recorded in
`CLAUDE.md` gotchas #26 (severity), #27 (log source mapping), #28 (evidence),
#29 (rule metadata) and #30 (confidence).

## Proposed: the analyst flow and upgrades of internal methods (draft, 2026-10-20)

**Nothing in this section is built yet.** It is the standards basis of the
proposed case flow (six steps from upload to report) and of a plan to back
the internal methods above with standards. Each row moves into the main table
when its story is done. Decisions D1-D5 of the proposal are still open.

### Analyst flow - one case, six steps

The order of the steps is taken from a standard, not chosen: NIST SP 800-86
divides forensics into Collection -> Examination -> Analysis -> Reporting.
NIST SP 800-61 Rev. 3 allows this: "Organizations should use the incident
response life cycle framework or model that suits them best" (p. 6). What each
step must deliver is taken from the CSF 2.0 outcomes SP 800-61r3 is built on;
step 4 comes from them, because SP 800-86 does not cover containment. ISO/IEC
27043 is said to order an investigation the same way, but it has not been read
(`docs/standards/SOURCES.md`), so it is not relied on.

Which documents were read, the copies (with SHA-256) and the page of every
sentence relied on: **`docs/standards/SOURCES.md`**. ISO documents marked
*(not read)* below are cited as aligned-with only, until a copy is obtained.

| Step | Standard | Done when | Today |
|---|---|---|---|
| 1 Ingest | SP 800-86 Collection; ISO/IEC 27037 (not read); RFC 3227; FIPS 180-4; CSF RS.AN-07; each log source's format documentation, RFC 5424 / 3164; ISO 8601 | case `ready`, acquisition digest verified | ✅ rows 1-3 |
| 2 Triage | SP 800-86 Examination; CSF DE.AE-02, DE.AE-08, RS.MA-02, RS.MA-03; Sigma `level`; Admiralty Code; ATT&CK | no finding in scope left Unreviewed (scope: D2) | ⚠️ review in two places (finding page, Reports tab) |
| 3 Investigate | SP 800-86 Analysis; ISO/IEC 27042 (not read); CSF RS.AN-03, RS.AN-06, RS.AN-08, DE.AE-03; ATT&CK, ODNI CTF | every high/critical finding has an assignee and is past Open | ⚠️ graph per case only; timeline is the AI's (IAI-60, IAI-61) |
| 4 Respond | SP 800-61r3: CSF RS.MI-01, RS.MI-02, RS.MA | every workflow finding Resolved | ✅ row 14 |
| 5 AI narrative | NIST AI RMF 1.0; NIST AI 600-1 (Confabulation, Human-AI Configuration); VERIS 1.4 | a narrative exists, or the step is skipped when AI is unavailable - no other step waits for it | ⚠️ rejected findings still reach the model; an Ollama outage is a 500 (IAI-59) |
| 6 Report | SP 800-86 Reporting; CSF RS.CO-02, RS.CO-03; STIX 2.1; VERIS 1.4; ATT&CK Navigator 4.5 | a report naming the evidence digest | ⚠️ exports only; the gate is shown, not enforced (IAI-55, IAI-72/73) |
| all | CSF RS.AN-06 (actions recorded, integrity and provenance preserved); RFC 3227 (custody); ISO/IEC 27037, ISO/IEC 27001:2022 A.8.15 (logging), A.8.3 (access restriction per customer), A.5.15 (access control - seam only until IAI-14) - all ISO here not read | - | ✅ / ⚠️ A.5.15 |
| screen order | ISO 9241-110:2020 (not read): interaction principles - suitability for the task, self-descriptiveness, conformity with user expectations | - | ❌ |

Every CSF 2.0 subcategory id above was checked against CSWP 29 (Appendix A,
p. 21-22) on 2026-10-20; the text of each is in `docs/standards/SOURCES.md`.

### Backing the internal methods with standards

Three routes. **A - a standard's data model**: the method stays ours, its
result is recorded in a published vocabulary. **B - method validation**: the
method stays ours and is tested and documented the way a forensic lab does it -
SWGDE 18-Q-001 v2.1, whose Section 6 lists what a test record holds (purpose
and scope, who, date, procedure or scenarios, datasets with expected results,
results and anomalies, identified limitations). `tests/gen_usecase.py` and
`tests/check_parity.py` already do the testing; what is missing is that record.
ISO/IEC 27041:2015 covers the same assurance in general terms but has not been
read. **C - a measurement standard**: NIST SP 800-55 Vol. 1 (December 2024),
whose 3.1.1 gives the fields of a measure (unique id, goal, scope, measure,
type, formula, target, implementation evidence, time-based reference). ISO/IEC
27004 is not needed for this.

| Internal method (row) | Route | Result | Order |
|---|---|---|---|
| TP / benign TP / FP at close (14) | A: OCSF 1.9.0 Incident Finding `verdict_id` 2 True Positive / 5 Benign / 1 False Positive. Practice: FIRST CSIRT Services Framework 2.1, 5.2 ("qualified as an information security incident (true positive) or as a false alarm (false positive)"), Microsoft Defender XDR (the same three classes). SP 800-61r3 defines none of them (searched) | standard | 1 |
| Lifecycle status (14) | A: OCSF `status_id` - Open -> New, Investigating and Contained -> In Progress, Resolved -> Resolved | stronger | 1 |
| Rule validation (6) | B: SWGDE 18-Q-001 Section 6, one test record per rule | standard | 2 |
| Related findings (18) | Practice: FIRST 5.2 names "automatically identifying related information security events" as part of triage. A: OCSF `finding_info_list`; export as MITRE Attack Flow 4.0 (STIX 2.1 extension). B: test record on real data - measured on synthetic data only (CLAUDE.md gotcha #51) | practice-backed, validated | 2 |
| Escalation patterns (8), risk ranking (11) | Practice for risk ranking: FIRST 5.2 ("assigning risk scores based on the criticality of affected assets and identities"; "higher criticality should be analyzed before less critical ones"). B: test record per SWGDE Section 6 | practice-backed, validated | 2 |
| MTTC (14) | C: documented with the SP 800-55v1 3.1.1 fields - goal, scope, measure ("average time from creation to Contained"), type (efficiency), formula, target `MTTC_TARGET_HOURS`, implementation evidence (id registry and review log), time-based reference. SP 800-55v1 names mean time to detect and to recovery (p. 23), not to contain | defined to a standard | 3 |
| Acknowledging medium/low by rule (proposal D2) | Sigma 2.1.0: "While `low` and `medium` level events have an informative character, events with `high` and `critical` level should lead to immediate reviews by security analysts"; CSF DE.AE-08; FIRST 5.2 ("Recurring cases that can be automated should be identified and automated") | principle backed, procedure ours | - |
| Detection areas (19) | none found; ATT&CK tactics too coarse on real data. Display only | stays internal | - |

Considered and not recommended: **CISA SSVC** as the finding priority instead
of the risk score - a published decision tree (Track / Track* / Attend / Act),
but designed for vulnerabilities, and its mission-prevalence branch needs an
asset inventory the tool does not have.

OCSF `verdict_id` also offers **Duplicate** and **Insufficient Data**, which
fit cases seen for real (a filtered export, CLAUDE.md gotcha #9). Adding them
as close options is an open decision.

**How far each source was read** is recorded per document in
`docs/standards/SOURCES.md`: the NIST documents, SWGDE, FIRST, Sigma, OCSF and
Attack Flow were read (2026-10-20); the ISO documents were not, and the order in
which to obtain them is listed there.

## Where a standard is only "aligned with"

Stated plainly so the claims stay accurate:

- **CISA NCISS.** The severity escalation uses the same *observed activity*
  stages NCISS takes from the ODNI framework. A full NCISS score also needs
  functional impact, information impact and recoverability, which logs alone
  cannot give (there is no asset inventory). The tool is aligned with NCISS
  observed activity; it does not compute an NCISS score.
- **ODNI to ATT&CK.** No official crosswalk between ODNI stages and ATT&CK
  tactics was found. The mapping in `severity.py` is ours, anchored on the
  intrusion boundary (Engagement | Presence) that ODNI does define.
- **Sigma.** Rules carry Sigma metadata and levels; their detection logic is
  SQL over this tool's schema and is not exported as Sigma `detection:`. That
  needs a shared field taxonomy first (step 4, OCSF).
- **Admiralty Code.** The grade wording is the published scale. Which facts
  earn which grade (documented mapping + verified digest = B, and so on) is
  this tool's rule, written one sentence per grade in `confidence.py`.
- **Audit trails (A.8.15, RFC 3227).** The custody and review logs are
  append-only and hash-chained (`hashchain.py`): an edit, deletion or
  reorder is detected. Review decisions made before chaining existed are
  *sealed* by the first chained decision - protected from then on, with
  nothing able to vouch for them before it. Anyone with write access could
  rebuild a whole chain; preventing that needs a digest held elsewhere or an
  external timestamp, which the tool does not have.

## The AI narrative and NIST AI RMF 1.0

The model (a local Ollama model - `qwen3.5:9b` since 2026-10-14,
`qwen2.5:7b-instruct` from 2026-10-12; Groq-hosted qwen before) writes prose only. Everything a reader could act on
is computed without it. How that maps onto the RMF's four functions -
aligned with, not certified against:

- **GOVERN** - a final report needs every finding reviewed by an analyst
  (FR-5.6 export gate); the review and status history are hash-chained.
  With the local model, case data no longer leaves the machine to produce
  the narrative.
- **MAP** - the model is given computed facts: rule-tagged ATT&CK ids,
  Sigma levels, source profiles, risk ranking and the VERIS classification,
  and told not to re-grade or reclassify them (CLAUDE.md gotcha #13).
- **MEASURE** - each analysis records model, finish reason, token usage,
  missing keys, temperature, seed and the SHA-256 of its prompt and schema
  in `_meta`; the same case gives the same narrative (CLAUDE.md gotcha #37).
  `_meta.grounding` lists every address, technique id, e-mail, date or
  stage the prose states that its input did not contain. Graded against
  ground truth with `tests/bench_llm.py` (local models) and the gotcha #5
  sweeps (Groq).
- **MAP (constraint)** - with the local model the response is decoded
  inside a per-case JSON schema: technique ids, ATT&CK stages, timestamps,
  levels, addresses and targets can only be values the evidence contains.
- **MEASURE (traceability)** - every attack-chain stage and timeline entry
  cites the findings it rests on (`refs` -> `finding_keys`, the review unit
  `rid|srcip|username`; the schema allows only findings the prompt carried,
  at least one) and states a `basis`: `fact` or `inference`. Each citation
  opens its finding in the Review tab. `_meta.grounding` also flags an entry
  that names an address none of its cited findings states - a wrong link
  between two real entities, which the schema cannot rule out. The model's
  own `basis` label is not relied on: it called such links `fact` (CLAUDE.md
  gotcha #37).
- **MANAGE** - the attack graph, severity, confidence, VERIS record and all
  exports are produced without the model, so an AI outage or a bad answer
  removes the prose, never the findings.

## Internal methods (no standard exists)

### Entity risk ranking (step 11)

**What it answers:** which source, destination or account to look at first
in a case with thousands of findings.

**Method** (`db.risk_scores`): for each entity, for each rule that implicates
it, take that rule's level weight `w` (informational 1, low 2, medium 4,
high 8, critical 16 - each level double the one below) and the number of
rows `n`; score = `sum over rules of w * (1 + ln n)`. One term per distinct
rule, with diminishing returns on repeats.

**Why this shape:** a plain sum of severities ranks by traffic volume - on
the customer's beaconing case it put a scanned host with three noisy rules
above the actual command-and-control destination. Counting each rule once,
log-dampened, ranks by *how many different ways* an entity is implicated.
Measured: the three beaconing destinations rank first (CLAUDE.md gotcha #16,
re-checked after the Sigma weights).

**Nearest frameworks:** NIST SP 800-30 Rev. 1 defines risk as likelihood x
impact. This score is a likelihood-side ordering only - impact needs asset
criticality, which the tool does not have. Commercial SIEMs' risk-based
alerting accumulates per-entity risk the same way, but no published standard
fixes a formula.

**Not claimed:** the number is an ordering, not a probability or a risk
level; it is not comparable across cases.

### Finding classification at close: TP / benign TP / FP (step 14)

**Definitions used** (requirements FR-4.7):
- *True positive* - the activity happened and was malicious.
- *Benign true positive* - the activity happened as detected, and it was
  authorised or harmless (an admin's scan, a sanctioned tool).
- *False positive* - the detected activity did not happen as the rule
  describes (a decoding error, a mis-mapped column, a misread verdict).

**Nearest framework:** NIST SP 800-61 Rev. 3 speaks of precursors,
indicators and incidents but does not define these three outcome classes;
they are common SOC practice. Only true positives must pass through
*Contained*, and benign/false positives are excluded from MTTC, so the
metric measures containment that actually happened.

### Rule validation (supports step 6)

**Method:** a rule's Sigma `status` is earned by evidence -
`test` when it fired correctly on real data and its false positives were
examined, `experimental` when it has synthetic hits only or none; `stable`
is reserved until a rule has proven itself across more than one customer
environment. Ground truth is `tests/gen_usecase.py`; regression is
`tests/check_parity.py` against `tests/baseline.json`; metadata consistency
is `tests/check_rule_meta.py`.

**Nearest frameworks:** Sigma's status definitions; the ADS framework's
*Validation* section; detection-as-code practice. No standard prescribes a
validation procedure for detection rules.

### Attack-path escalation patterns (supports step 8)

**Method:** two patterns, each a sentence an analyst can check -
*credential-compromise* (a source brute-forced an account, then logged in to
it from that same source) raises to high; *compromised-host* (one source
shows two different allowed post-intrusion behaviours) raises to critical.

**Nearest frameworks:** ODNI CTF stages and Sigma's definition of critical
("probability borders certainty"). The patterns themselves - which evidence
combinations reach which stage - are ours, calibrated on the corpus
(CLAUDE.md gotcha #26 records the version that was too loose).
