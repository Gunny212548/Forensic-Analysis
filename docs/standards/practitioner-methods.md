# How human analysts do it - practitioner methods, and what they ask of this tool

Review of 2026-10-21, at the user's request ("ไปค้นหาวิธีการที่มนุษย์ใช้ในการทำ Digital
Forensic"). `forensic-process.md` covered what the *standards* require (SP 800-86, RFC 3227,
ACPO, SP 800-92, IR 8354). This file covers the *methods* practitioners use to get from a
pile of logs to "what happened": timelines, temporal proximity, pivoting, event
reconstruction, competing hypotheses and stated certainty. Every quote below is from a
document **read** (`SOURCES.md`, section *Practitioner methods*); pages are the documents'
own printed page numbers.

These are not standards. They are the published methods the standards leave to the
analyst - SP 800-86 says it "should not be used as a guide to executing a digital forensic
investigation". Cite them as *method*, beside the standard a step already cites.

## 1. Documents

| Document | What it is |
|---|---|
| Carrier & Spafford, *Defining Event Reconstruction of Digital Crime Scenes*, J Forensic Sci 49(6), 2004 | A five-phase procedure for reconstructing events from evidence, built to be implemented in software |
| Caltagirone, Pendergast & Betz, *The Diamond Model of Intrusion Analysis*, 2013 | The analysts' model of an intrusion event, pivoting, and activity threads (a phase-ordered attack graph of what *did* happen) |
| Casey, *Error, Uncertainty, and Loss in Digital Evidence*, IJDE 1(2), 2002 | The certainty scale C0-C6 for digital evidence, with log examples |
| Heuer, *Psychology of Intelligence Analysis*, CIA CSI, 1999, ch. 8 | Analysis of Competing Hypotheses (ACH), eight steps |
| Gudjonsson, *Mastering the Super Timeline With log2timeline*, GIAC GCFA paper, SANS 2010 | The super timeline (every source on one timeline, log *content* included) and how it is analysed |

Searched, not read: SANS blog posts on super / targeted timelines (both URLs 404), Silberman
2010 on "least frequency of occurrence" (known only through Gudjonsson's citation).

## 2. The methods

### 2.1 One timeline of everything, then reduce it (Gudjonsson)

- Why: "relying solely on filesystem timestamps lacks context that might only be written
  inside log files ... The true value in these files is found within the actual content"
  (§1.1.1, p. 3). A super timeline puts every source's timestamps, log lines included, in one
  order.
- Full vs targeted: extracting everything "could potentially drown the investigator with
  unnecessary information. Instead it might be more valuable to only include limited sources
  in the timeline ... For other investigations however it might make perfect sense to simply
  get as much information as possible, and then sift through them afterwards using data
  reduction techniques" (§4, p. 62).
- Context: "it is necessary to examine each timestamp in conjunction with other surrounding
  events to get the context needed to determine the true reason behind the timestamp entry"
  (§4.2, p. 66).
- **Temporal proximity** - the core move: "When the investigator has discovered something
  that is a part of the attack he or she can look for other objects in the timeline that are
  in temporal proximity to the known event" (§4.3, p. 71). It is only as good as the clocks:
  it works "if timestamps of files haven't been modified", which is why several sources
  matter (§4.3, p. 71; anti-forensics §1.1.2, p. 4: the investigator needs "information
  gathered from multiple locations to verify his or hers results").
- Frequency: "many investigations will follow the rule of least frequency of occurrence
  (LFO)", and some benefit from looking at spikes instead (§4.4, p. 71-72).

### 2.2 Pivoting (Diamond Model §7)

- "Pivoting is the analytic technique of extracting a data element and exploiting that
  element, in conjunction with data sources, to discover other related elements. Ultimately,
  pivoting is about the fundamental analytic task of hypothesis testing" (p. 26).
- The worked example is a log pivot: "(pivot 4) firewall logs are examined illuminating
  other compromised hosts in the victim's network establishing communications with the
  now-revealed malware controller IP address" (p. 26).
- A limit stated by the authors: "Success is not guaranteed by the Diamond. It only
  highlights what is possible, not what is certain" (fn 11).

### 2.3 What one event is (Diamond Model §4)

- "For every intrusion event there exists an adversary taking a step towards an intended goal
  by using a capability over infrastructure against a victim to produce a result" (Axiom 1,
  p. 8). Meta-features: timestamp (start and end), phase, result, direction, methodology,
  resources; expansions name "data source", "author", "detection method", "detection
  signature" (§4.5.7, p. 18).
- **Each feature carries its own confidence**, "left purposefully undefined as each model
  implementation may understand confidence differently" (p. 8).
- **Empty features are knowledge gaps**: "after documenting an event with all available
  information any empty features are now identified knowledge gaps which should encourage
  additional pivoting" (p. 10). "Adversary knowledge is generally elusive and this feature is
  likely to be empty for most events" (p. 11).
- An address is not an actor: Type 2 infrastructure is "controlled by an (witting or
  unwitting) intermediary. Typically, this is the infrastructure that a victim will see as the
  adversary" (p. 13); a victim asset "can be the end target ... in one event and then
  leveraged as infrastructure in further events" (p. 14).
- Result: "One method is to use the 3-tuple Success, Failure, Unknown" (p. 16). Direction:
  Victim-to-Infrastructure, Infrastructure-to-Victim, ..., Bidirectional, Unknown (p. 17).

### 2.4 Event reconstruction (Carrier & Spafford)

- Five phases: "1. Evidence Examination 2. Role Classification 3. Event Construction and
  Testing 4. Event Sequencing 5. Hypothesis Testing" (p. 3).
- An event "uses the characteristics from one or more objects and changes the
  characteristics of one or more objects" (p. 3); "An event chain is a sequence of events ...
  such that an effect of event ei is a cause of event ei+1" (p. 3).
- Evidence examination includes reliability: "It needs to be considered if the information
  exists because of the incident, the response to the incident, or if the attacker staged it"
  (p. 3).
- Construction: backward search from an effect to its possible causes, forward search from a
  cause to its other effects; a passed test is added "with a confidence value that
  corresponds to both the amount of evidence that exists to support the event and the amount
  of evidence that does not exist and for which hypotheses had to be created" (step 7, p. 5).
- Sequencing: "In many cases, we will not be able to make one big event chain for the entire
  incident ... we will have many single events or small event chains"; "To account for the
  event gaps, hypotheses should be created for the events that occurred in between the known
  event chains" (p. 5-6). Known phases of a class of incident can order events (p. 6).
- Hypothesis testing: "The final theory, if one is found, must be supported by the evidence
  and must account for the events where there are missing cause or effect objects" (p. 6).
- On tools: "digital evidence requires us to use tools to process it. Therefore, it lends
  itself well to databases of data that can be queried and processed" (p. 8).

### 2.5 The attack path as an activity thread (Diamond Model §8)

- "An activity thread is a directed phase-ordered graph where each vertex is an event and the
  arcs (i.e., directed edges) identify causal relationships between the events" (p. 30);
  "each thread is specific to one adversary-victim pair" (p. 30).
- Each arc carries **Confidence, And/Or, Hypothetical/Actual, Provides** (p. 35); in the
  example figure "solid lines represent actual element of information supported by evidence
  and dashed lines represent hypothesized elements" (Fig. 6, p. 31).
- Unlike an attack graph that lists every possible path, "activity threads model knowledge
  of actual attack paths" (p. 34).
- Gaps: "By phase-organizing the thread, one can also more easily identify knowledge gaps
  where activity should have occurred but no knowledge of such exists" (p. 34).
- "one of the failings of most analysis is the lack of documented hypotheses and
  furthermore, and more dangerously, the lack of differentiation between hypothesis and
  fact" (§8.2, p. 38). And: "The first step of analysis is to define the question to be
  addressed" (p. 38).

### 2.6 Competing hypotheses (Heuer ch. 8)

- The eight steps (p. 97): identify the hypotheses; list evidence and arguments for and
  against each; a matrix of hypotheses across and evidence down, judging "diagnosticity";
  refine it; "Draw tentative conclusions ... Proceed by trying to disprove the hypotheses
  rather than prove them"; analyse sensitivity to "a few critical items of evidence";
  "Report conclusions. Discuss the relative likelihood of all the hypotheses, not just the
  most likely one"; identify milestones that would change the judgment.
- Diagnosticity: "If an item of evidence seems consistent with all the hypotheses, it may
  have no diagnostic value" (p. 102).
- Disproof over support: "The most probable hypothesis is usually the one with the least
  evidence against it, not the one with the most evidence for it" (p. 108).
- Absence: "Note the absence of evidence as well as its presence" (p. 99); unproven is not
  disproved - "Unproven hypotheses should be kept alive until they can be disproved" (p. 98).
- The analyst decides: "The matrix should not dictate the conclusion to you ... You, not the
  matrix, must make the decision" (p. 105) - the matrix is "an audit trail showing how you
  arrived at your conclusion" (p. 105).

### 2.7 Saying how certain (Casey)

Table 1 (§2.3), lowest to highest: **C0** "Evidence contradicts known facts" -
Erroneous/Incorrect; **C1** "Evidence is highly questionable" - Highly Uncertain; **C2** "Only
one source of evidence that is not protected against tampering" - Somewhat Uncertain; **C3**
"The source(s) of evidence are more difficult to tamper with but there is not enough evidence
to support a firm conclusion or there are unexplained inconsistencies in the available
evidence" - Possible; **C4** "Evidence is protected against tampering or multiple,
independent sources of evidence agree but evidence is not protected against tampering" -
Probable; **C5** "Agreement of evidence from multiple, independent sources that are protected
against tampering. However small uncertainties exist" - Almost Certain; **C6** tamper proof -
Certain, which "may exist in the future".

- On logs exactly: "A standard syslog entry has a lower certainty level (C2) than a
  cryptographically signed entry (C4)"; "An entry in a single log file that is susceptible to
  tampering has a low certainty level (C2) unless there are other independent sources of
  corroborating evidence (C4)"; a proxy in play leaves "virtually no certainty in associated
  IP addresses recorded in log files (C1)".
- Its scope: "The certainty levels in Table 1 apply to data, not to conclusions based on
  digital evidence since erroneous conclusions can be drawn from reliable data."
- On time: the same IIS line could be 04:42 GMT or 23:42 EST the day before, "the system
  clock of the computer could be incorrect by minutes, hours, or days"; "these potential
  errors can be avoided by documenting the system clock time and the Web server
  configuration" (§2.3).

## 3. What this asks of the tool

Status as in `forensic-process.md`: **have**, **partial**, **gap**. Nothing here overrides a
standard; each row names the step of the case flow it belongs to.

| Method | What the tool should do | Step | Status |
|---|---|---|---|
| The question first (Diamond §8.2; Heuer step 1) | A case records the question it answers | Ingest | **gap** - same as `forensic-process.md` 3.0 |
| Super timeline (Gudjonsson §1.1.1) | Every file of the case on one timeline, the log line itself shown | Timeline | **partial** - one `raw_events` per case, time order exists (`get_timeline`, the events table's time order); per-file source column not on every row |
| Targeted vs full (Gudjonsson §4) | Filter the timeline to sources / event types without deleting anything | Timeline | **partial** - filters are SQL views; the UI filters flagged vs all only |
| Temporal proximity (Gudjonsson §4.3) | From any event: "show what happened within N minutes of this", across all files | Timeline, Attack events | **gap** in the UI; **have** over MCP (`search_events` with `since` / `until`) |
| Pivoting (Diamond §7) | From an address / account / host on any row: every event sharing it, across files | Attack events | **partial** - MCP `search_events`; the UI opens a behaviour profile, not the pivoted rows |
| LFO / stacking (Gudjonsson §4.4) | Per field, values rarest in this evidence, rarest first | Timeline | **gap** - profiles rank the *most* active (`list_unusual`); rarity is SP 800-92 §5.2.2's "newness" too |
| Event features with own confidence, empty = gap (Diamond §4) | Each attack event shows actor / source / target / action / result / direction, empty ones marked "unknown", not left out | Attack events | **gap** - same as `forensic-process.md` 3.3 who/where/what |
| Address is not actor (Diamond §4.3-4.4; Casey C1 on proxies) | A node is labelled "address as observed", never an identity | Attack path | **gap** - same as 3.4 |
| Activity thread (Diamond §8) | Attack path edges labelled actual (cites events) or hypothesised (written assumption, dashed), with confidence and what one step provides the next | Attack path / graph | **gap** - the graph is SQL over findings (gotcha #10); story 7 is the place |
| Gaps as hypotheses (Carrier p. 5-6; Diamond p. 34) | A phase with no confirmed event is drawn as a gap, not skipped | Attack timeline | **gap** |
| ACH (Heuer ch. 8) | Hypotheses with supporting *and contradicting* events; "no conclusion yet" allowed; the report lists the rejected ones and why | Attack path, Report | **gap** - same as 3.4 / 3.5 |
| Certainty of data (Casey Table 1) | Per event or per source: one unprotected log = C2; two independent files agreeing = C4; contradicted = C0 | Attack events | **partial** - findings carry an Admiralty grade (gotcha #30), which grades source reliability and credibility of the *finding*, not corroboration across files |
| Clock documented (Casey §2.3) | Each source's zone and drift recorded, not assumed | Ingest | **partial** - same as 3.1 |

The three rows that most change the product, because nothing in it does them yet:
**temporal proximity in the UI**, **actual-vs-hypothesised edges on the attack path**, and
**hypotheses with contradicting evidence**. All three are what the Diamond Model and Carrier
describe as the analyst's work; the tool's part is to put the rows in front of them and record
what they decided - the same division as "the system and the AI only suggest".
