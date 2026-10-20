# Gotcha #54

**54. The product direction of 2026-10-20 - read before designing anything.** Decided by
the user in one session; recorded in `specs/case_flow_design.md` revisions 1-4 (branch
`IAI-92-identify-logsource`) and on the page https://claude.ai/artifact/XDFqhbqPKE4ENX52t9MvdN.

- **Purpose: forensic reconstruction from log files.** Identify each log, put every event
  on one timeline, let the analyst confirm which events are the attack (the system and the
  AI suggest), then build the attack timeline, the attack path and a graph of what the
  attacker did - which command, from which host, to which host. Severity is a hint for
  what to look at first, not the point.
- **Flow:** Ingest -> Timeline -> Attack events -> Attack timeline -> Attack path / graph ->
  Report. The order follows NIST SP 800-86 (Collection, Examination, Analysis, Reporting);
  SP 800-61r3 p. 6 lets an organisation use the model that suits it.
- **Respond is removed** (no Contained / Resolved tracking, no MTTC, no close
  classification). `lifecycle.py`, the Findings status filters, the Overview MTTC KPI, the
  Customers open/closed count and IAI-50 depend on it - re-based in a story of its own.
- **Detection: the 20 in-house rules (R1000-R3006) stay, SigmaHQ rules are added beside
  them** (revision 5). Revision 4 had retired the in-house rules for SigmaHQ + the Sigma
  correlation spec's examples + intel; the user reversed that the same day after the spike
  (ADR-006) measured what it would cost: on the real Entra export 2 of 19 SigmaHQ rules
  matched anything (one matched every row), SigmaHQ publishes **no correlation rule and no
  failed-login base rule**, and PAN-OS / Check Point / FortiGate traffic has no SigmaHQ
  rule at all - so spray, brute force, scan, beaconing and policy-gap findings would have
  gone. Every finding names its origin; a SigmaHQ match names its author (DRL 1.1).
- **Engine for the SigmaHQ rules (ADR-006):** a DuckDB subclass of pySigma's SQLite
  backend, measured against SQLite as the oracle. Running the SQLite SQL on DuckDB
  directly is wrong *without an error* (LIKE is case-sensitive there). Rules run on the
  file's own fields, not OCSF (`pySigma-pipeline-ocsf` covers none of our sources); a rule
  whose fields the file lacks is "not applicable", never 0 matches. OCSF is still what
  the who / where / what timeline needs, since `raw_events` keeps a command only inside
  `raw`.
- **AI** suggests attack events and links, cites event ids, is checked before an analyst
  sees it, and every decision records AI-suggested vs analyst-chosen (AI 600-1 MS-2.5-003,
  MS-4.2-004, MP-2.3-001 - read). Log text is data, never instructions: AI 600-1 describes
  indirect prompt injection "injecting prompts into data likely to be retrieved".
- **Status words:** a case's "status" is the file's processing state (Ready = processed,
  not finished); a finding has review and lifecycle states. To be renamed so they cannot
  be read as one another.
- **Open:** Q5 attack-path input, Q6 AI suggestion shown on request, Q7 remove Groq,
  Q12 Entra portal CSV value vocabulary, Q13 SigmaHQ rules that match every row (ADR-006).
  Q10 (spec correlation thresholds) and Q11 (base rules) fell away with revision 5.
