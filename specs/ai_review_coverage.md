# The AI reviews every suggestion (design)

Status: **proposed 2026-10-26**, waiting for Q101-Q104. The user: "หาขั้นตอนวิธีการทำให้ Ai review
ครบทุก Finding", then, on the first draft (one review per pattern, the advice inherited by the other
members): **"ทุก Finding ที่เจอต้องได้รับการ review จาก AI"** - every finding must be reviewed by the
AI itself. Inherited advice is therefore out (Q100, answered no). Builds on `specs/ai_triage.md` (Q78:
automatic, before the findings show; Q79: advice) and gotcha #64.

The unit is the suggestion an analyst decides on - the collapsed finding `rid|srcip|username` (gotcha
#19, #69) - not each flagged row: 18,187 rows of kinnaree are 526 suggestions.

## Where it stands

`triage.review_case` reviews at most 80 suggestions (`MAX_SUGGESTIONS`), highest level first, then the
most events, five per model call (`BATCH`). Measured on 8091 (qwen3.5:9b on this PC): **about 9-10 s
per suggestion** - Mekong 61 in ~10 min, kinnaree 80 in ~14 min (upload to `created_at`, ingest
included).

| Case | Suggestions | Reviewed today | Every one, at ~9.5 s |
|---|---|---|---|
| Mekong (gotcha #69) | 61 | 61 | ~10 min |
| kinnaree after story 5e | 526 | 80 | **~83 min** |

## Proposed decisions

### C-D1 - no cap: every suggestion is reviewed by the model (the user's requirement)

`MAX_SUGGESTIONS` goes. Every suggestion of the case is sent, with its own facts, and gets its own
advice; nothing is inherited, nothing skipped. A case's AI review is finished only when every
suggestion has advice or a recorded error (C-D4).

### C-D2 - the case is ready when the rules are done; the review continues (Q101)

Q78 put the review before the findings show. At ~83 minutes for kinnaree that would keep a case
unreadable for an hour and a half. Proposed: the case is **ready** after the rules (as before the AI
review existed), and the review runs on in the background - the Upload page and the case show "AI
reviewing 120 of 526", each suggestion without advice yet says "AI review pending", and advice appears
as each batch finishes. The analyst may decide before the advice arrives (the AI only advises, gotcha
#54). The other choice (b): keep Q78 - ready only when all are reviewed.

### C-D3 - the order: every rule first, then the rest (Q102)

So the first minutes cover every kind of behaviour, not one rule's volume: one suggestion per rule
first (highest level, then most events), then round by round, each rule's next. On kinnaree the 7 high
and the lateral-movement suggestions are reviewed in the first few batches instead of waiting behind
K13's 509.

### C-D4 - every one, even when a call fails (Q103)

A batch that fails (timeout, invalid JSON, a model that cannot be reached) is retried once, then its
suggestions one by one. A suggestion still without advice is listed with its error, and a **"Review
again"** action re-sends only those. A suggestion that appears after a re-process is reviewed with the
case. So "every suggestion" is checkable: reviewed + errors = suggestions.

### C-D5 - throughput, measured before it is set (Q104)

The time is the cost of the requirement, so it is measured, not guessed: the same 50 kinnaree
suggestions at `BATCH` 5, 10 and 15 (output tokens capped by `OLLAMA_MAX_COMPLETION_TOKENS`, 3000
today - raised if a batch needs it). Kept: the fastest size whose batches all end `stop` with valid
JSON and whose advice matches the size-5 run on the same suggestions. Nothing else changes in the
prompt (gotcha #13). Parallel calls are not proposed: this PC runs the model, 8091 and the dev
container together (CLAUDE.md *Environment*).

## Tests

- `tests/check_triage.py` (fake model): more than 80 suggestions all reviewed; the per-rule-first
  order; a failing batch retried, then one by one; an error left listed and "Review again" sending only
  it; reviewed + errors = suggestions; the case ready before the review ends, progress counted.
- kinnaree on 8091 (Ollama): every one of the 526 reviewed, the time taken, advice per incident against
  its answer key - a measurement, the key having been read (gotcha #70). Mekong: no suggestion loses
  advice it had.

## Questions

- **Q100 - inherited advice.** Answered no (the user, 2026-10-26): every suggestion is reviewed itself.
- **Q101 - when the case is ready (C-D2).** (a) ready after the rules, the AI review continuing with its
  progress shown; or (b) ready only when every suggestion is reviewed (~83 min on kinnaree).
  Recommended: (a).
- **Q102 - order (C-D3).** Every rule first, then round by round? Recommended: yes.
- **Q103 - failures (C-D4).** Retry once, then one by one; what is left listed with a "Review again"?
  Recommended: yes.
- **Q104 - batch size (C-D5).** Measure 5 / 10 / 15 and keep the fastest that stays valid and matches?
  Recommended: yes.
