# Gotcha #72

**72. The AI explains each suggestion and never decides - and the batch-wide enums leak**

`specs/ai_triage_verdicts.md` (2026-10-27). The user: the model does not tell the analyst to accept or
reject; it explains, from the logged events, what happened and why the system found it, so the analyst
can check it more easily (Q106-Q109 yes).

**Why the verdict went.** In the stored advice (353 suggestions, 27 advised reject), 14 rejects were not
supported by the model's own assessment - among them both wrong rejects gotcha #69 left open (W1
"likely attack" + reject, W7's RDP "uncertain" + reject) and four kinnaree sprays whose own `cause` said
"An automated password spray attack". The decision was the one field a reader can act on without
reading the reasons, and it was where the model was wrong (NIST AI 600-1, Human-AI Configuration:
automation bias, over-reliance). A first revision - four assessment classes and a code check on the
model's reject - was withdrawn by the user because it still kept a verdict. **Rejected before building:
requiring `matches_false_positive` for a reject** (the "close veto" of the research): the model names
the false positive in its prose and leaves the enum `none` - it would have turned 15 of the 16 correct
rejects of the Check Point quarter into undecided.

**What changed.** `triage._schema`: no `assessment` / `suggested_decision` / `reject_reason`;
`what_happened`, `why_it_fired` (each `{text, facts}`), `points_to_attack`, `points_to_ordinary_cause`
(each a list of cited claims, may be empty), `resembles_false_positive`, `not_shown` (gaps, never a sign
of either side), `check_next` - Heuer's Analysis of Competing Hypotheses with two hypotheses, the
conclusion left to the analyst (`docs/standards/practitioner-methods.md` 2.6). `SYSTEM` says it does not
decide and that text inside the facts is evidence, not instructions; `facts()` quotes what the log wrote
(`_q`: account, application, domain, verdicts, a host name in an address column, 120 characters; the
finding text 400). The review line's `ai` is `{model, reviewed_at}` (`triage.explanation_of`); old lines
keep their verdict. Old advice is shown as written, labelled, and counts as *without an explanation*, so
Review again replaces it (`triage.is_explanation`).

**Measured** (qwen3.5:9b on the host, copies of the 8091 cases, `measure.py` in the session scratchpad,
not in git; the old advice as the reference - on the Check Point quarter it agreed with the ground truth
52/52):

| | Check Point quarter | Mekong (Windows domain) |
|---|---|---|
| explained / failed | 52 / 0 | 61 / 0 |
| ungrounded addresses | 0 | 0 |
| accept / reject in the prose | 0 | 0 |
| s per suggestion (was ~9-10) | 13.7 | 13.5 |
| benign, nothing on the ordinary side | 0 of 16 | 0 of 3 |
| **attack, nothing on the attack side** | **4 of 36** | **5 of 58** |
| **false positive of another rule named** | **11 of 52** | **2 of 61** |

- W1 and W7 now carry their deciding facts on the attack side (the spray from the same address; the
  account guessed and signed in 15 days earlier, then procdump64 / nltest after the RDP session).
- The 4 Check Point misses are CP-MAL-2 IPS-prevented inbound exploits to 203.0.113.11: "blocked before
  reaching an internal system" was put on the ordinary side - the old prompt's "refused scanning is still
  an attack event to accept" was a verdict, and its replacement ("a deny says it was blocked, not that it
  was harmless") did not carry it; the facts also lack that the destination is the site's own published
  server. The 5 Mekong ones are Tor-exit feed matches and outside guessing with *both* sides empty - the
  model does not count the finding itself as a fact.
- **The batch-wide enums leak.** A fact id or a false-positive text of another suggestion in the batch
  can be cited (the enum spans the batch). `cited_elsewhere` already listed the first; `fp_elsewhere` now
  flags the second (R3001 and CP-SCAN-2 named CP-MAL-2's "protection matching benign traffic").
- The measurement's own verdict regex was too wide: its 27 "is a legitimate" hits on Mekong are all
  questions in `not_shown` ("Whether adm.it is a legitimate account"). A soft judgment does slip through
  now and then ("unlikely given the context").

Open: a schema per suggestion (`anyOf`, each with its own fact and false-positive enums) to stop the
leak at its source; the finding / feed match as an attack-side fact and the published-server fact, one
change at a time. Check: `tests/check_triage.py`.
