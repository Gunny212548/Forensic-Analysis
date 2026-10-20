# The forensic process, as the standards describe it - and what it asks of this tool

Review of 2026-10-20, written to design the case flow of `specs/case_flow_design.md`
(Ingest -> Timeline -> Attack events -> Attack timeline -> Attack path / graph -> Report).
Every statement below cites a document that was **read** (`SOURCES.md`); quotes are
verbatim. The tool starts *after* collection: it receives log files someone else exported.
Live-system collection (order of volatility, write blockers, imaging) is outside its scope
and is not reviewed here, except where it constrains what we must record.

## 1. Documents

| Document | Why it is here |
|---|---|
| NIST SP 800-86 (2006) - Guide to Integrating Forensic Techniques into Incident Response | The process: four phases; §6.4 is the method for examining log / network data |
| RFC 3227 (BCP 55, 2002) - Guidelines for Evidence Collection and Archiving | Evidence principles, chain of custody, time |
| ACPO Good Practice Guide for Digital Evidence v5 (2012) | The four principles of digital evidence; interpretation; reporting |
| NIST SP 800-92 (2006) - Guide to Computer Security Log Management | Parsing, normalisation, correlation, log integrity, log analysis practice |
| NIST IR 8354 (2022) - Digital Investigation Techniques: A NIST Scientific Foundation Review | Analysis of results, anti-forensics, validation vs verification, error types |
| SWGDE 18-Q-001 2.1, FIRST CSIRT Framework 2.1, CSF 2.0, SP 800-61r3, AI 600-1 | Read earlier (`SOURCES.md`); cited where they apply |

Not read: ISO/IEC 27037, 27041, 27042, 27043 (not obtainable, `SOURCES.md`). Downloaded but
not used: SP 800-92 Rev. 1 initial public draft (2023) - a draft about log management
planning, not analysis.

## 2. The process

**Four phases (SP 800-86 §3).** "During collection, data related to a specific event is
identified, labeled, recorded, and collected, and its integrity is preserved." Examination:
tools "identify and extract the relevant information from the collected data while
protecting its integrity." Analysis: "analyzing the results of the examination to derive
useful information that addresses the questions that were the impetus for performing the
collection and examination." Reporting: "describing the actions performed, determining what
other actions need to be performed, and recommending improvements". The phases are not a
one-way line: "an analyst examines data and performs analysis of that data, then conducts
additional examination and analysis based on the results of the initial analysis" (fn 14).
Other models "differ primarily in how granular each phase of the process is" (fn 8) - which
is what allows six steps.

Our six steps against the phases:

| Phase (SP 800-86) | Our step |
|---|---|
| Collection | Ingest: accept the copy, hash it, record custody and provenance |
| Examination | Ingest (identify each file, parse) + Timeline (filter, search, reduce) |
| Analysis | Attack events (validate) + Attack timeline + Attack path / graph (reconstruct) |
| Reporting | Report |

**Principles that hold over every phase.**

- ACPO Principle 1: no action "should change data which may subsequently be relied upon in
  court." Principle 3: "An audit trail or other record of all processes applied to digital
  evidence should be created and preserved. An independent third party should be able to
  examine those processes and achieve the same result."
- RFC 3227 §3.1: "The methods used to collect evidence should be transparent and
  reproducible." §2.4: evidence must be admissible, authentic, **complete** ("It must tell
  the whole story and not just a particular perspective"), reliable, believable.
- SP 800-92 §3.2: log functions are "performed in such a way that they do not alter the
  original logs"; fn 23: "Ensuring that the original logs are not altered supports their use
  for evidentiary purposes."
- SP 800-86 §3.3: "The foundation of forensics is using a methodical approach to reach
  appropriate conclusions based on the available data or determine that no conclusion can
  yet be drawn."

## 3. What each step must do, and where the tool stands

Status: **have** (built, on `main` or the IAI-92 branch), **partial**, **gap**.

### 3.0 Before ingest: the question

- SP 800-86 §3.3: analysis addresses "the questions that were the impetus". ACPO 5.5:
  "investigators must supply specific requirements. It is not practically possible to
  examine every item of digital data and clear tasking is needed". ACPO 5.6: the forensic
  strategy "should be regularly reviewed".
- SP 800-86 §6.4.1: examination starts from an **event of interest**, found either through
  "an automated alert or a user complaint" or during routine review; "even general
  information provides the analyst with a starting point". §6.4.3: "The focus of the
  investigation should be determined at the onset by the appropriate parties, who should
  decide if learning the identity of the attacker is vital."

| Requirement | Status |
|---|---|
| A case records its question, scope (time window, systems) and known leads (hosts, accounts, addresses) | **gap** - upload has a free-text `note` only |
| The timeline can start from a lead the analyst brings, not only from a rule hit | **gap** - today every path into a case is a finding |

### 3.1 Ingest (collection)

- RFC 3227 §4.1, to be documented: "Where, when, and by whom was the evidence discovered and
  collected"; "Where, when and by whom was the evidence handled or examined"; "Who had
  custody of the evidence, during what period."
- ACPO 5.10.3: "Establishing the provenance of digital evidence is another key task ...
  identify not just that the evidence exists but also how it came to be there."
- SP 800-86 §3.1.2: verify integrity by message digest; fn 39: digests "should be used to
  ensure the integrity of all data that is acquired during forensic activity, including log
  files"; examine "using only the copied evidence"; "a detailed log should be kept of every
  step that was taken to collect the data, including information about each tool used".
- RFC 3227 §2: "Note the difference between the system clock and UTC. For each timestamp
  provided, indicate whether UTC or local time is used." §3.2: "Record the extent of the
  system's clock drift."
- SP 800-92 §2.1.4: "be particularly cautious about the accuracy of logs from hosts that have
  been attacked successfully". §2.3.2: "many rootkits are specifically designed to alter
  logs".

| Requirement | Status |
|---|---|
| SHA-256 on arrival, re-hashed before every run, hash-chained custody log, recorded_by | **have** (gotcha #28) |
| Original kept unchanged; analysis on a derived copy | **have** - `raw/` kept, DuckDB derived; `.gz`/`.zip` kept compressed |
| Provenance per file: source system, how it was exported (query, filter - gotcha #9), exported by, exported when, original time zone if known | **gap** |
| Each file identified before it is read; no guessed columns; unknown kept as evidence | **have** (IAI-92 branch, gotcha #53) |
| Coverage: rows not loaded, fields filled, per file | **have** (gotcha #43) |
| Clock: original timestamp text kept; zone stated per source; an analyst-declared offset for a drifting source, recorded and reversible (SP 800-92 fn 24: "it might be necessary to add or subtract times from the log entries recorded by out-of-sync sources") | **partial** - normalised to GMT+7 with `timezone-unconfirmed` / `year-inferred` flags (gotchas #21, #44); no declared offset |

### 3.2 Timeline (examination)

- SP 800-86 §3.2: "yesterday's firewall log might hold millions of records, but only five of
  the records might be related to the event of interest" - examination is reduction.
- SP 800-92 §3.2 normalisation: "each log data field is converted to a particular data
  representation and categorized consistently"; filtering "does not alter the content of the
  original logs--it simply restricts which log entries are used for analysis" (fn 59).
- SP 800-86 §6.4.2: "analysts should have more confidence in original data sources than in
  data sources that receive normalized (modified) data from other sources."
- SP 800-86 §4.2.3, why a time may be wrong: the clock was not synchronised, the time "may not
  be recorded with the expected level of detail", "An attacker may have altered the recorded
  file times." IR 8354 §2.3: ambiguous formats, epochs and granularity, time zones,
  intentionally wrong clocks.
- IR 8354 §4.7.1: "A time-line tool can be used to put events into a temporal sequence".
- SP 800-92 §5.2.1: keep "two reports: one for the entries thought to be most important, and
  another for entries that are not yet fully understood".
- IR 8354 §4.7.2: anti-forensics includes "deleting information from system log files (to
  remove a record of an event)".

| Requirement | Status |
|---|---|
| One timeline over every file of the case | **partial** - planned (IAI-60) |
| Every row shows its raw line and source file beside the normalised fields | **partial** - finding events carry the source file (gotcha #49) |
| Filters are views; nothing filtered is deleted | **have** by construction (SQL over `raw_events`) |
| Lines the reader did not understand are reachable, not hidden | **partial** - counted in coverage, not browsable |
| Per source: first / last event and silent periods shown on the timeline, for the analyst to judge (no threshold of ours) | **gap** |

### 3.3 Attack events (analysis - validation)

- SP 800-86 §6.4.2: "analysts should validate data that is based on interpretation, such as
  IDS and SEM alerts. No tool for identifying malicious activity is completely accurate; they
  produce both false positives ... and false negatives". Fn 107: "Analysts should not assume
  that an activity is benign if security devices have not reported it as malicious."
- SP 800-86 §6.4.2, pivoting: "query the appropriate secondary data sources based on the
  pertinent data from the primary data sources ... Analysts also use timestamps, protocols,
  port numbers, and other common data fields to narrow their search".
- SP 800-86 §6.4.2.1, firewalls: "By itself, data from these sources is usually of little
  value ... The primary value of the data is to correlate events recorded by other sources";
  NAT means "the apparent IP address of an attacker or a victim might actually have been used
  by hundreds or thousands of hosts".
- SP 800-86 §3.3: "identifying people, places, items, and events, and determining how these
  elements are related"; e.g. an IDS log links an event to a host, host audit logs link it to
  a user account, the host IDS shows what that user did.
- SP 800-92 §5.2.2, factors for prioritising entries: entry type, "Newness of the entry type",
  log source, source or destination address (e.g. on a blacklist), time of day, frequency.
- FIRST 5.2: triage qualifies each potential incident as true or false positive.
- IR 8354 §4.7.1: AI results "could be misleading and should be verified or confirmed".

| Requirement | Status |
|---|---|
| The system and the AI suggest; the analyst confirms each event; the AI's suggestion is recorded beside the decision | **partial** - review is per finding (gotcha #19); per-event confirmation is in the design |
| Absence of a match is never shown as "benign": a rule that could not run says so | **gap** - ADR-006 decision 3 |
| Pivot: from a confirmed event, every event across all files sharing its address / account / host in a time window | **partial** - related findings via pivot hosts (gotcha #49), not over raw events |
| Who / where / what on each event (actor, source host, destination host, action, command, outcome) | **gap** - revision 3, OCSF |
| "What to look at first" is a hint built from SP 800-92's listed factors, not a verdict | **partial** - severity is a Sigma level (gotcha #26); newness and time of day unused |
| Firewall logs serve corroboration and pivoting; little detection is expected from them | **consistent** with revision 4's accepted gap |

### 3.4 Attack timeline and attack path / graph (analysis - reconstruction)

- SP 800-86 §6.4.3: "the available data is typically not comprehensive"; analysis "develops
  conclusions based on the data that is available and assumptions regarding the missing data
  (which should be based on technical knowledge and expertise)"; the analyst should "locate,
  validate, and analyze enough data to be able to reconstruct the event, understand its
  significance, and determine its impact"; "the negative impact of the event should be the
  primary concern"; "Determining the intent of an attacker is also very difficult".
- IR 8354 §4.7: "Considering and evaluating alternative hypothesis"; "Verifying that
  assembled pieces of the developed narrative are consistent, and any contradictions are
  noted"; "Is the temporal information accurate?"; can activities "be attributed to a source
  such as the user of the machine or an external actor"; "What steps have been taken to
  identify and mitigate human bias". §4.7.1: "Link analysis can look for relationships
  between entities".
- SP 800-86 §6.4.4: addresses may be spoofed, many sources may be illusory, "the system
  currently at a particular IP address might not be the same system that was there when the
  attack occurred"; research the address's history; "Organizations should not send network
  traffic to an apparent attacking IP address".
- ACPO 5.10.2: the presence of an artefact is not by itself proof; other evidence is
  interpreted "to establish the likelihood".

| Requirement | Status |
|---|---|
| Built only from confirmed events; every step and every edge cites its events | **partial** - graph is SQL over findings (gotcha #10), not over confirmed events |
| A node is an address / account **as observed**, not an identity; NAT and spoofing caveats shown | **gap** |
| Gaps in the chain are drawn as gaps, with the assumption written next to them | **gap** |
| Hypotheses: each with supporting and contradicting events; "no conclusion yet" is a valid state | **gap** |
| Nothing is sent to an attacking address; enrichment is offline intel only | **have** (gotcha #17) |

### 3.5 Report

- SP 800-86 §3.4: alternative explanations ("each should be given due consideration"),
  audience (senior management may want "a simplified visual representation of how the attack
  occurred"), actionable information; identify "policy shortcomings or procedural errors".
  §6.5: "configure data sources to improve the collection of information".
- ACPO 6.3: "communicate both the extent and the limitations of the digital forensic
  evidence". 6.5.3: when an item has to be converted for review, "the fact that it has been
  converted must be stated in the report". 6.5.4: "make clear
  the strength of any conclusions reached and always identify where an opinion is being
  given, to distinguish this from fact", stating "the facts on which this is based".
- SP 800-86 §3.4 (fn 9): "evidence" in the strict legal sense is only what a judge admits.

| Requirement | Status |
|---|---|
| Fact (event cited) vs opinion (analyst or AI interpretation) marked in every section | **partial** - narrative cites `F<n>` and is grounding-checked (gotcha #37) |
| Limitations: files not analysed, rules not applicable, coverage, time assumptions, sources silent | **gap** as a report section |
| Conversions stated: time normalised to GMT+7 from which zone, fields mapped by which profile | **partial** - mapping shown on the case, not in a report |
| Executive view and technical view | **gap** - IAI-55 |
| Recommendations include logging improvements found during the case | **gap** |
| **Reproducibility record**: application commit, profile versions, rule set (SigmaHQ commit + hash), intel feed hashes, model and prompt version, parameters - written to the custody log at each run and printed in the report (ACPO Principle 3) | **gap** - nothing records a version today |

## 4. Validating the tool itself

- IR 8354 §4.8: validation shows a method "fit for purpose" - "the process of providing
  objective evidence that the method is good enough to do the job required by the end user";
  verification "is the demonstration that the implementation of the method correctly follows
  the tool design."
- IR 8354 §4.10.1 / takeaway 4.4: "Digital processes tend to have systematic errors rather
  than random errors. Therefore, an error mitigation analysis provides more information and
  is the correct way to manage uncertainty."
- IR 8354 §4.10.2, error types to test for: **incompleteness**; inaccuracy as **existence**
  ("Do all artifacts reported as present exist?"), **alteration**, **association** ("is each
  item truly a part of that set?"), **corruption**; **misinterpretation**.
- SWGDE 18-Q-001 §6: seven fields of a test record (read earlier).

| Error type | Where it can happen here | Check today |
|---|---|---|
| Incompleteness | rows not loaded; rules not run; unsupported files | coverage (#43); `check_parity.py` |
| Existence | a finding with no source event | `check_workflow.py` (source events) |
| Alteration | time normalisation, value mapping | `gen_usecase.py` ground truth covers some; no dedicated check |
| Association | correlation windows, related findings, graph edges | ADR-006 differential test (spike) |
| Corruption | encodings, truncated lines, blank leading lines | gotchas #22, #46, #53 |
| Misinterpretation | field meaning, vendor codes (e.g. AADSTS 50053 covers two causes) | profiles cite vendor docs (#27); "observed" level (#42) |

Gap: validation records in the SWGDE §6 format per method (design: separate story).

## 5. What this changes in the design

Ranked by how directly a standard asks for it and how little it costs:

1. **Reproducibility record** per run (ACPO P3, RFC 3227 §3.1, SP 800-86 §3.1.2) - small, and
   needed before SigmaHQ rules arrive, since their commit then changes results.
2. **Provenance at ingest** (RFC 3227 §4.1, ACPO 5.10.3) - source system, export method and
   filter, exported by / when, known time zone.
3. **Case question and leads** (SP 800-86 §3.3, §6.4.1; ACPO 5.5) - so a timeline can start
   from what the analyst already knows.
4. **Original beside normalised; declared clock offset per source** (SP 800-86 §6.4.2,
   §4.2.3; RFC 3227 §2, §3.2; SP 800-92 fn 24).
5. **Pivot over raw events** across files (SP 800-86 §6.4.2).
6. **Source coverage over time** on the timeline (SP 800-92 §2.3.2; IR 8354 §4.7.2) - display
   only, no threshold of ours.
7. **Hypotheses, gaps and contradictions** in the attack path (SP 800-86 §6.4.3; IR 8354 §4.7).
8. **Report sections**: limitations, conversions, fact vs opinion, two audiences, logging
   recommendations (ACPO 6.3-6.5; SP 800-86 §3.4).
9. **Validation records** per method in SWGDE §6 format, organised by IR 8354's error types.

Items 1-2 belong to Ingest, 3-6 to Timeline, 7 to the attack path, 8 to Report.
