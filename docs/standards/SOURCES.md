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
| NIST SP 800-86 - read again, beyond the phases | Aug 2006 | as above | §3.1-3.5 in full; §4.2.2-4.2.3 integrity and file times; §5.3; §6.3.2-6.5 examining log / network data (event of interest, data source fidelity and value, drawing conclusions, attacker identification); §7.1.3, §7.4; §8 intro (2026-10-20, `forensic-process.md`) |
| RFC 3227 (BCP 55), Guidelines for Evidence Collection and Archiving | Feb 2002 | `files/rfc3227.txt` (`32e81a23d3f6093a`) | Whole body: §2 principles (clock vs UTC), §2.4 evidence properties, §3 collection (clock drift), §4 chain of custody |
| ACPO Good Practice Guide for Digital Evidence | v5, Mar 2012 | `files/ACPO-Good-Practice-Guide-Digital-Evidence-v5.pdf` (`3bfbfef11be8dd33`) | §2 the four principles and their explanation; §5.4-5.10 tasking, triage, interpretation, provenance; §6.2-6.5 reporting (limitations, conversions, fact vs opinion) |
| NIST SP 800-92, Guide to Computer Security Log Management | Sep 2006 | `files/NIST.SP.800-92.pdf` (`466c3ab1580bc3b2`) | §2.1.4, §2.3 (inconsistent content / timestamps / formats, log protection), §3.2 functions (parsing, filtering, normalisation, integrity, correlation; fn 23-24), §5.2 analysis (baseline, prioritisation factors), §5.6 |
| NIST IR 8354, Digital Investigation Techniques: A NIST Scientific Foundation Review | Nov 2022 | `files/NIST.IR.8354.pdf` (`8088e60ff2e14271`) | The 12 key takeaways; §2.3 time; §2.7; §4.5 parsing; §4.7 analysis of results, anti-forensics; §4.8 validation vs verification; §4.10 error rates and observed error types |
| MITRE ATT&CK techniques T1110.001, T1110.003, T1133 | v1.7 (2026-05-12), v1.8 (2025-10-24), v2.5 (2026-05-12) | web: attack.mitre.org/techniques/T1110/001, /T1110/003, /T1133 | First description paragraph of each; used by `specs/rules_review.md` (R2005 and R2004 tags) |
| Sigma correlation rules specification | 2.1.0 | web: github.com/SigmaHQ/sigma-specification commit `ba9251a`, `specification/sigma-correlation-rules-specification.md` | Correlation types and their examples (event_count, value_count, temporal, temporal_ordered, value_sum, value_avg); used by ADR-006 |

### Practitioner methods (read 2026-10-21, `practitioner-methods.md`)

Published methods, not standards: cited as *method* beside the standard a step cites. All
read in full except where the row says otherwise. Downloaded with `curl --ssl-no-revoke`
(the host's schannel could not reach a revocation server; certificates were still checked).

| Document | Version | Copy (SHA-256, first 16) | What was checked |
|---|---|---|---|
| Carrier & Spafford, Defining Event Reconstruction of Digital Crime Scenes | J Forensic Sci 49(6), Nov 2004 (CERIAS TR 2004-37) | `files/Carrier-Spafford-2004-Event-Reconstruction.pdf` (`047be0f0e72cb27b`) | Whole paper: roles, event chain, the five reconstruction phases, construction steps 1-9, gaps as hypotheses |
| Caltagirone, Pendergast & Betz, The Diamond Model of Intrusion Analysis | 2013 (activeresponse.org copy; the DTIC copy ADA586960 refused automated access) | `files/Caltagirone-2013-Diamond-Model.pdf` (`ed177039dcca97a7`) | §3-4.5 event, features, confidence, meta-features; §7 pivoting; §8-8.3 activity thread, hypothesis support, activity-attack graph. Not read: §5, §6, §9-12 |
| Casey, Error, Uncertainty, and Loss in Digital Evidence | IJDE 1(2), Summer 2002 | `files/Casey-2002-Error-Uncertainty-Loss.pdf` (`b3bcee4c6e4a8fc0`) | §2.3 and Table 1 (certainty scale C0-C6) with its log examples; §3 opening (where log errors enter). Rest not read |
| Heuer, Psychology of Intelligence Analysis | CIA Center for the Study of Intelligence, 1999 | `files/Heuer-1999-Psychology-of-Intelligence-Analysis.pdf` (`bc703f2140e39e14`) | Chapter 8, Analysis of Competing Hypotheses, p. 95-108 (the closing example on p. 109 not read). Other chapters not read |
| Gudjonsson, Mastering the Super Timeline With log2timeline | GIAC GCFA paper, SANS 2010 | `files/Gudjonsson-2010-Super-Timeline.pdf` (`ec5a287b91f9e7dd`) | §1.1 background, problems, anti-forensics; §4 timeline analysis (4.2 context, 4.3 temporal proximity, 4.4 frequency). The tool chapters 2-3 not read |

### Log source documentation (read 2026-10-21, IAI-85)

| Document | Version | Copy (SHA-256, first 16) | What was checked |
|---|---|---|---|
| Check Point sk144192, Description of Fields in Check Point Logs | page as served 2026-10-21 | `files/CheckPoint-sk144192-Log-Fields.html` (`ff6f357ec160268b`) | The whole field table, 879 rows parsed from the saved page (an earlier web fetch read only its first 118k characters): every field `checkpoint_le.py` maps, `action`'s value list, `ifdir` listed as internal |
| Check Point Log Exporter Administration Guide, *Format Configuration* | sc1.checkpoint.com/documents/Log_Exporter, dated 07 September 2026 | `files/CheckPoint-LogExporter-Format-Configuration.htm` (`52a5360c05ecd296`) | The syslog format's body delimiters, separators, value quoting and escapes |
| same guide, *Appendix B - Additional Information* | as above | `files/CheckPoint-LogExporter-Appendix-B.htm` (`e51e286315eccaa0`) | Epoch time (Splunk `TIME_FORMAT = %s`, LEEF note); update logs in raw read-mode and `loguid` |
| Check Point sk122323, Log Exporter | web | web: support.checkpoint.com/results/sk/sk122323 | The format list (Syslog, Splunk, CEF, LEEF, Generic, JSON, LogRhythm, RSA); no body layout |
| Check Point R81 CLI Reference, `cp_log_export` | R81 | web: sc1.checkpoint.com/.../MDSG/cp_log_export.htm | `format` default `syslog`; `time-in-milli`; example action filter values incl. Prevent |
| ManageEngine EventLog Analyzer user guide, *Report export and customization* | web | web: manageengine.com/products/eventlog/help/.../report-export-and-customization.html | Report export formats; **no layout for the search-result CSV** - the wrapper is observed, not documented |

### Windows event logs (read 2026-10-21, `specs/windows_event_logs.md`)

All read on the web (no saved copy); quotes are in the spec and `winevent.py`.

| Document | Version | Where | What was checked |
|---|---|---|---|
| Microsoft, Windows Event schema: `SystemPropertiesType`, `EventDataType` | learn.microsoft.com | /windows/win32/wes/eventschema-* | Children of System (Provider, EventID, TimeCreated/@SystemTime, EventRecordID, Channel, Computer, Security/@UserID); EventData's `Data` items |
| Microsoft, Security auditing events 4624, 4625, 4648, 4672, 4688, 4697, 4698, 4720, 4740, 4768, 4769, 4771, 4776, 1102 | learn.microsoft.com (archived Windows 10 pages) | /previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-<id> | Each event's meaning and its EventData names; 4624's LogonType table; 4625's status codes; 1102's UserData |
| Microsoft Sysinternals, Sysmon | learn.microsoft.com | /sysinternals/downloads/sysmon | Event IDs 1-29 and 255 with their headings; "Event timestamps are in UTC standard time" |
| libyal (Joachim Metz), Windows XML Event Log (EVTX) format | GitHub libyal/libevtx `main` documentation, read again in full 2026-10-21 for W2 | /documentation/Windows XML Event Log (EVTX).asciidoc | `ElfFile\0` file signature; chunks of 65,536 bytes after a 4096-byte header; chunk header (512 bytes): first / last event record identifier at 24 / 32, free space offset at 48 ("sometimes point to the end of the chunk"); event record `**\0\0`, size, identifier at 8, Binary XML at 24; template instance 0x0c with its definition data offset at +5 (definition inline when it points right after itself: 33 bytes then data size); instance data = value count, 4-byte (size, type) descriptors, values; value types 0x0f GUID, 0x11 FILETIME, 0x12 system time (y, mo, dow, d, h, mi, s, ms), 0x21 Binary XML, 0x81 UTF-16 string array with an end-of-string character after each |
| omerbenamram, `evtx` (pyevtx-rs) 0.13.1, MIT | PyPI / GitHub | the package's own docstrings | `PyEvtxParser(path_or_file_like, number_of_threads, ansi_codec)`; `records()` yields a dict (`event_record_id`, `timestamp`, `data` XML) or a `RuntimeError` object. **Measured, not documented**: a damaged chunk's records and a cut file's last chunk are dropped with no error (gotcha #60) |
| Microsoft, the providers' own event metadata: `System.Diagnostics.Eventing.Reader.ProviderMetadata.Events` for Microsoft-Windows-Security-Auditing and Microsoft-Windows-Eventlog | Windows 11 (10.0.26300) on the analyst's PC, read 2026-10-21 (W3) | exported to `app/data/windows/*.json` by `tools/export_win_templates.ps1` | Per event ID and version: the message with `%n` insertions and the template's data item names in order (`outType` win:HexInt* for hex items) - what names each value of a rendered message. The same version can differ between builds (5156 v1) |
| NXLog Agent reference, `im_msvistalog` | docs.nxlog.co, current (`/agent/current/im/msvistalog.html`) and v5.11 (`/refman/v5.11/...`), read 2026-10-21 (W4) | web | The module's fields (`$AccountName` ... `$Version`, `$raw_event`) - the same 30 in both versions; `EventTime` = EvtSystemTimeCreated, `Hostname` = EvtSystemComputer, `SourceName` = EvtSystemProviderName; the JSON output sample with `ExecutionThreadID`, the `paramN` items and an `EventData` XML string |
| Elastic, Winlogbeat's own test data (`x-pack/winlogbeat/module/*/test/testdata/collection`: `.evtx` + `.evtx.golden.json`) | github.com/elastic/beats `main`, downloaded 2026-10-21 | lab, outside the repo (Elastic License 2.0) | What Winlogbeat writes from a given `.evtx`: measured, not documented - empty items left out, `%%` rendered, GUIDs upper case |
| Elastic, Winlogbeat exported fields (winlog) | elastic.co | /guide/en/beats/winlogbeat/current/exported-fields-winlog.html | `winlog.event_data`, `event_id`, `channel`, `computer_name`, `provider_name`; unnamed items `param1`, `param2`... |

Not obtained: Splunk Add-on for Windows docs (HTTP 403) - its classic text layout is observed only.

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
