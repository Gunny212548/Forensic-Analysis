# Standards: what was read, and what was not

Every standard `docs/STANDARDS.md` and `specs/case_flow_design.md` cite, with the copy that
was read, where each quoted sentence is, and the ones not obtained yet. A claim may cite a
standard at clause level **only if its document is marked read here**. Read on 2026-10-20.
The PDFs are kept beside this file in `files/` but **not in git** (`*.pdf` is ignored, the
user's call): the SHA-256 below identifies the exact copy that was read, and a fresh
download can be checked against it.

## Read

| Document | Version | Copy (SHA-256, first 16) | What was checked |
|---|---|---|---|
| NIST CSWP 29, The NIST Cybersecurity Framework (CSF) 2.0 | Feb 2024 | `files/NIST.CSWP.29-CSF-2.0.pdf` (`3c31f46fee98cac0`) | Every subcategory id the flow cites exists with this text (Appendix A core, p. 21-22) |
| NIST SP 800-86, Guide to Integrating Forensic Techniques into Incident Response | Aug 2006 | `files/NIST.SP.800-86.pdf` (`ea7eb645bcd3feaf`) | The four phases (Executive Summary, PDF p. 9; Section 3) |
| NIST SP 800-61 Rev. 3, Incident Response Recommendations and Considerations for Cybersecurity Risk Management: A CSF 2.0 Community Profile | Apr 2025 | `files/NIST.SP.800-61r3.pdf` (`e5593d6bb85daece`) | Organised by CSF 2.0; maps the old life cycle to CSF Functions (Table 1, p. 6); leaves the life-cycle model to the organisation (p. 6). Defines no TP / FP / benign classes (searched: not found) |
| NIST AI 600-1, Generative AI Profile | Jul 2024 | `files/NIST.AI.600-1.pdf` (`6e73620ab6b64e90`) | The 12 GAI risks; Confabulation and Human-AI Configuration (p. 4) |
| NIST AI 100-1, AI RMF 1.0 | Jan 2023 | `files/NIST.AI.100-1-AI-RMF-1.0.pdf` (`7576edb531d98488`) | GOVERN, MAP, MEASURE, MANAGE descriptions (Section 5, PDF p. 26, 29, 33, 36) |
| NIST SP 800-55 Vol. 1, Measurement Guide for Information Security: Identifying and Selecting Measures | Dec 2024 | `files/NIST.SP.800-55v1.pdf` (`29435d0db5af6dcb`) | Measure documentation fields (3.1.1, p. 12-13); mean-time metrics named (p. 23) - MTTC is not among them |
| SWGDE 18-Q-001, Minimum Requirements for Testing Tools Used in Digital and Multimedia Forensics | 2.1, 2024-03-07 | `files/SWGDE-18-Q-001-2.1.pdf` (`c15e744931ff38cd`) | Scope (p. 2), test documentation fields (Section 6, p. 14) |
| FIRST CSIRT Services Framework | 2.1 | `files/FIRST-CSIRT-Services-Framework-v2.1.pdf` (`8561dee38166163b`) | 5.2 Event analysis: purpose and description (PDF p. 10-11) |
| Sigma rules specification | 2.1.0, 2025-08-02 | web: github.com/SigmaHQ/sigma-specification, `specification/sigma-rules-specification.md` | `level` and `status` definitions |
| OCSF Incident Finding (class 2005) | schema 1.9.0 | web: schema.ocsf.io/classes/incident_finding | `verdict_id`, `status_id`, `finding_info_list` enums and descriptions |
| MITRE CTID Attack Flow | **4.0** (not 3) | web: center-for-threat-informed-defense.github.io/attack-flow/language/ | "defined as an extension to the STIX 2.1 Standard"; SDOs attack-flow, attack-action, attack-asset, attack-condition, attack-operator. The linked schema file is named `attack-flow-schema-2.0.0.json` - check before relying on it |

### The sentences the design rests on

- **SP 800-86** - "The process for performing digital forensics comprises the following basic
  phases: Collection ... Examination ... Analysis ... Reporting". Also, on its own limits:
  it "should not be used as a guide to executing a digital forensic investigation, construed
  as legal advice, or used as the basis for investigations of criminal activity." The tool
  uses it for the order of incident-response forensics, which is its stated focus.
- **SP 800-61r3** - "Organizations should use the incident response life cycle framework or
  model that suits them best. The model in this document is based on CSF 2.0 ..." (p. 6).
  This is what allows the six-step order to come from SP 800-86 while the outcomes come from
  CSF 2.0.
- **CSF 2.0** - DE.AE-02 "Potentially adverse events are analyzed to better understand
  associated activities"; DE.AE-03 "Information is correlated from multiple sources";
  DE.AE-08 "Incidents are declared when adverse events meet the defined incident criteria";
  RS.MA-02 "Incident reports are triaged and validated"; RS.MA-03 "Incidents are categorized
  and prioritized"; RS.AN-03 "Analysis is performed to establish what has taken place during
  an incident and the root cause of the incident"; RS.AN-06 "Actions performed during an
  investigation are recorded, and the records' integrity and provenance are preserved";
  RS.AN-07 "Incident data and metadata are collected, and their integrity and provenance are
  preserved"; RS.AN-08 "An incident's magnitude is estimated and validated"; RS.MI-01
  "Incidents are contained"; RS.MI-02 "Incidents are eradicated"; RS.CO-02 "Internal and
  external stakeholders are notified of incidents"; RS.CO-03 "Information is shared with
  designated internal and external stakeholders".
- **AI 600-1** - Confabulation: "The production of confidently stated but erroneous or false
  content (known colloquially as 'hallucinations' or 'fabrications') by which users may be
  misled or deceived." Human-AI Configuration: arrangements "which can result in the human
  inappropriately anthropomorphizing GAI systems or experiencing algorithmic aversion,
  automation bias, over-reliance, or emotional entanglement with GAI systems."
- **Sigma 2.1.0** - "While `low` and `medium` level events have an informative character,
  events with `high` and `critical` level should lead to immediate reviews by security
  analysts." medium: "Relevant event that should be reviewed manually on a more frequent
  basis." high: "Relevant event that should trigger an internal alert and requires a prompt
  review." This is the basis of D2.
- **FIRST 5.2 Event analysis** - "Potential information security incidents need to be
  triaged and each qualified as an information security incident (true positive) or as a
  false alarm (false positive)." The same paragraph: "Mature tooling facilitates effective
  triage by enriching with context information, assigning risk scores based on the
  criticality of affected assets and identities and/or automatically identifying related
  information security events" and "Potential information security incidents with higher
  criticality should be analyzed before less critical ones." This backs, as recognised
  practice, three internal methods at once: TP/FP qualification, risk ranking and related
  findings.
- **SWGDE 18-Q-001 2.1** - scope: "testing of the core tools used to support forensic
  examinations"; purpose covers "commonly used forensic tools and procedures". Section 6 -
  testing documentation "should include: Purpose and scope of testing (identify tool or
  technique); Who performed the testing; Date; Testing procedure used or scenarios; Datasets
  or other testing material used, including expected results; Results and a description of
  anomalies and their significance; Identified limitations". These seven fields are the
  validation record format for rules and internal methods.
- **SP 800-55v1 3.1.1** - measure fields: Unique ID, Goal, Scope, Measure, Type, Formula,
  Target, Implementation evidence, Time-based reference (and further fields on p. 13). These
  are the format for MTTC.

## Not obtained

ISO refuses automated access (HTTP 403 on every iso.org page) and the documents are sold.
Until one is read, it is cited only as *aligned with*, never by clause, and a free document
that was read is cited first.

| Document | Cited for | Free document cited first meanwhile | Priority to obtain |
|---|---|---|---|
| ISO/IEC 27037:2012 | evidence acquisition and preservation (existing row 1) | SP 800-86 Collection; RFC 3227 | 1 - already cited in the main table |
| ISO/IEC 27043:2015 | investigation process order, concurrent processes | SP 800-86 four phases | 2 |
| ISO/IEC 27041:2015 | assurance / validation of investigative methods | SWGDE 18-Q-001 Section 6 | 3 |
| ISO/IEC 27042:2015 | analysis and interpretation | SP 800-86 Analysis | 4 |
| ISO 9241-110:2020 | interaction principles for the step bar and menu | none found | 5 |
| ISO/IEC 27001:2022 Annex A (A.5.15, A.8.3, A.8.15) | access control, access restriction, logging (existing rows 13, 16) | none | 1 - already cited |
| ISO/IEC 27004:2016 | measurement constructs | SP 800-55v1 3.1.1 | **not needed** - SP 800-55v1 covers it |
