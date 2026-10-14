# Standards traceability

Every step from upload to report, the published standard it follows, where it
is implemented, and how far it goes. Where no standard exists, the step is
listed as an **internal method**, with the nearest framework named and the
method stated so it can be checked rather than believed.

Status: ✅ implemented · ⚠️ partial · ❌ not yet

| # | Step | Standard | Implemented in | Status |
|---|---|---|---|---|
| 1 | Evidence acquisition and integrity | ISO/IEC 27037:2012, NIST SP 800-86, RFC 3227 (chain of custody), FIPS 180-4 (SHA-256) | `app/services/custody.py`, `app/routers/upload.py` | ✅ |
| 2 | Reading each log format | The log source's own format documentation (PAN-OS Traffic Log Fields, Microsoft Entra sign-in log, Microsoft Graph signIn / signInStatus + AADSTS error codes, Exchange Get-MessageTrace, OpenSSH `auth.c`, Linux-PAM `pam_unix`, FortiOS Log Message Reference) | `app/services/logsources.py`, `parsers.py` | ⚠️ 3 CSV log sources + 1 JSON (Entra via Azure Monitor) + 3 line formats; others are guessed and flagged; unreadable JSON records counted and reported |
| 3 | Time | ISO 8601 / RFC 3339, single zone (GMT+7, FR-10.1) | `app/services/pipeline.py`, `decode.py` | ✅ |
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

What each implemented step does, and what it does not claim, is recorded in
`CLAUDE.md` gotchas #26 (severity), #27 (log source mapping), #28 (evidence),
#29 (rule metadata) and #30 (confidence).

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
