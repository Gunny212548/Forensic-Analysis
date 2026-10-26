# Gotcha #71

**71. The AI reviews every suggestion - after the case is ready, and a bigger batch is slower**

`specs/ai_review_coverage.md` (2026-10-26). The user: every finding found must be reviewed by the AI
(Q100: no advice inherited from a similar suggestion), the case ready after the rules (Q101 a).

**What changed.** `triage.MAX_SUGGESTIONS` (80) is gone. `pipeline.process_case` sets the case `ready`
and calls `triage.enqueue`; one background worker reviews one case at a time (one model on this PC),
writing `<case>.triage.json` after every batch, so advice appears as it arrives. The manifest's
`ai_review: {status queued / running / done / failed / off, done, total, failed, model, run}` is the
count; the old `progress.ai` and `Progress.ai` are gone. Order: every rule's first suggestion, then
round by round (`_order`) - kinnaree's 7 high and its lateral-movement suggestions no longer wait
behind K13's 509. A batch that fails or leaves a suggestion out is sent again, then one by one
(`_review_chunk`); what still fails is in the file's `failed` with its error, shown on the finding,
and `POST /api/cases/{id}/ai-review` ("Review again", case:reprocess) sends only those. A review cut
short by a restart is resumed at start-up (`triage.resume`). A re-process or a delete stops a review
between batches (the manifest's `run` no longer matches) - checked *before* writing, so a deleted case
does not get its file back.

**Batch size, measured (C-D5)** on 50 kinnaree suggestions, qwen3.5:9b, `OLLAMA_MAX_COMPLETION_TOKENS`
3000, from Ollama's own request log (the run was stopped before 15 finished, the user's call):
- **5: 7.4 min, ~9 s a suggestion**, every call ~35-57 s and complete.
- **10: ~27 min, ~32 s a suggestion.** Every 10-suggestion call ran 1 min 20 s - the 3,000-token cap at
  ~35 tokens/s - and was cut off; the retry was cut off again; then ten single calls of ~12 s.
- 15: the same truncation on its first calls.
The time is the model *writing*: ~300 tokens of advice per suggestion at ~35 tokens/s. A larger batch
with a larger cap would write the same tokens; it cannot be faster, and a cut-off costs a retry. So
`TRIAGE_BATCH` stays 5. At ~9 s, kinnaree's 526 suggestions are ~80 minutes in the background.

Check: `tests/check_triage.py` (90 suggestions, no cap; every rule first; a left-out suggestion retried
alone; one that keeps failing listed, then Review again sending only it; the background queue counting
to the end).
