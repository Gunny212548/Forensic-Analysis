# AI review of each suggestion before the analyst decides - design (draft)

Status: **Answered 2026-10-22 and built**: Q78 automatic, while the case is processed, before
the findings show; Q79 advice - why the finding fired and what caused it; Q80 (unanswered) as
recommended - the advice is kept on the review line. **Q78 changed 2026-10-26**
(`specs/ai_review_coverage.md`, Q101 a): every suggestion is reviewed, so the case is ready after the
rules and the review runs on in the background.
Requirement (the user, 2026-10-22): "ขั้นตอนก่อนให้ Analyze กด Accept หรือ Reject คิดว่าต้องมี AI
narrative มาตรวจ" - before the analyst accepts or rejects a suggestion on the Attack events
step, an AI should check it.

## Why now

On the synthetic Check Point quarter (`tests/gen_checkpoint_quarter.py`) the Attack events step
offered 52 suggestions: 38 attacks, 14 not (13 OneDrive syncs over R3001's 50 MB, one Zabbix
heartbeat as beaconing). The analyst has to tell them apart one by one.

## What the AI gets - facts, not rows (gotcha #13)

Every wrong narrative measured so far was missing input, never reasoning: the discriminating fact
is computed in SQL and handed over. Per suggestion:

- the rule: its behaviour, ATT&CK technique and **its documented false positives** (rule_meta.py
  ADS) - e.g. R3001 "backups, cloud sync"; beaconing "update checks, telemetry, monitoring";
- the line it crossed and why (lines.py record);
- the entity: internal or external; its behaviour profile (profiles.py); its other findings;
- the destination: **how many other internal hosts reach it** (one host -> MEGA vs thirteen staff
  -> OneDrive), the application / domain names the log carries (Check Point `appi_name`,
  `destination_domain_name`), any threat-intel match;
- time: first / last event, how long, regularity;
- a few sample events.

## What the AI returns - inside a JSON schema, grounding-checked (gotcha #37)

Per suggestion: `assessment` (likely attack / likely benign / uncertain), `reasons` (each citing
the facts above by id - a reason naming a number or address the facts do not hold is flagged),
`matches_false_positive` (which documented false positive, if any), `suggested_decision` (accept /
reject + reason code), `ask_the_analyst` (what to check). The analyst still decides
("the system and the AI only suggest", gotcha #54).

## Measured before it ships

Scored on the quarter's ground truth like the rules: how often the AI's assessment agrees, and -
the costly error - how often it calls a real attack benign. Model: the local qwen3.5:9b
(`.env`), temperature 0 and a seed, so a run is repeatable.

## Questions

- **Q78 - when it runs.** (a) a button on Attack events, "AI review", run in the background with
  progress (recommended: the local model takes tens of seconds per batch; 52 suggestions is
  minutes); (b) automatically after every processing.
- **Q79 - advice or gate.** (a) advice shown beside each suggestion; Accept / Reject work as today
  (recommended); (b) a gate: Accept / Reject disabled until the AI has reviewed that suggestion.
- **Q80 - recorded with the decision.** When the analyst decides, the review log line also records
  the AI's assessment at that moment (model, assessment), so the record shows whether the analyst
  followed or overrode it (recommended: yes).
