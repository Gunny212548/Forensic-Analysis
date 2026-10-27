# Gotcha #72

**72. The AI explains each suggestion and never decides - one schema per suggestion, an attack side never empty**

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

**Fixed, one change at a time, both cases re-run each time** (greedy decoding with a fixed seed, so a
difference between rounds is the change, not chance):

| round | change | another rule's FP | another's fact cited | attacks with no attack-side fact | s / suggestion (CP, Mekong) |
|---|---|---|---|---|---|
| 1 | (the schema above, one enum for the batch) | 13 | 6 | 9 of 94 | 13.7, 13.5 |
| 2 | `reviews` an object, one property per suggestion with only its own fact ids and its own rule's false positives (`_item`) | 0 | 0 | **16 of 94** | 17.1, 12.4 |
| 3 | `points_to_attack` `minItems: 1` | 0 | 0 | **0 of 94** | 13.8, 15.7 |

- Round 2 stopped the leak but emptied more attack sides (CP-MAL-2's Critical CVE-2024-24919 exploit
  came back with only "protection matching benign traffic"): an optional list is the cheapest thing a
  grammar lets the model write. The attack side cannot honestly be empty - the rule fired because the
  behaviour matched the attack it describes - so round 3 requires one.
- Round 3, read by hand: the 16 Check Point non-attacks still carry their ordinary cause (zabbix-trapper,
  OneDrive reached by 131 hosts); their attack side mostly restates the rule ("large outbound transfers
  can indicate exfiltration") - consistent with both hypotheses, so of no diagnostic value (Heuer p. 102),
  not invented - and twice it put the OneDrive false positive on the attack side. The Tor-exit feed
  matches now cite the feed on the attack side and say the evidence does not show a corporate exit.
- Time moves 12-17 s a suggestion between cases and rounds with no pattern; ~14 s is the planning figure
  (kinnaree's 567: ~130 minutes).
- Still seen: `check_next` sometimes lists fact ids ("S27.f2 and S27.f4") instead of a place to look.

Check: `tests/check_triage.py`.
