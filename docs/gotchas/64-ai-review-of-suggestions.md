# Gotcha #64

**64. The AI reviews every suggestion while the case is processed, before the findings show
(`triage.py`, `specs/ai_triage.md`, the user's Q78-Q80 of 2026-10-22).**

- **When**: in `pipeline.process_case`, after the rules, escalations, profiles and FD ids, before
  `status=ready`; the manifest's progress reads stage `ai` (the Upload page says "AI reviewing the
  findings"). Never fails the case: a model that cannot be reached is recorded in
  `analysis/<case>.triage.json` (`error`, or per-batch `errors`) and the case becomes ready.
  `TRIAGE_ENABLED=0` switches it off - every rule check sets it (they measure rules), and the dev
  container has it off unless `DEV_TRIAGE_ENABLED=1` (parity uploads a hundred cases).
- **What it gets - facts, not rows** (gotcha #13): per suggestion, computed in SQL by
  `triage.facts`: the rule's goal and **documented false positives** (rule_meta.py), the finding
  text (with its line), the source (internal / external, account, span, verdicts), up to three
  destinations each with **how many internal hosts reach it in the whole evidence**, the
  application and domain names (Check Point `appi_name` / `destination_domain_name` from the
  record), bytes, the source's other findings, any escalation. Facts carry ids `S<n>.f<m>`.
- **What it returns**: inside a JSON schema whose enums are the batch's suggestion ids, fact ids
  and false-positive texts: why it fired, the likely cause, an assessment (likely attack / likely
  benign / uncertain), reasons citing fact ids, the matching documented false positive, a suggested
  decision (accept / reject + reason code) and what to check. Checked after: an address none of
  the suggestion's facts holds is `ungrounded`; a fact of another suggestion in the same batch is
  `cited_elsewhere` (the enum spans the batch - it happened on the quarter). Both shown.
- **Shown** under each suggestion on Attack events (`AiReview.jsx`), advice only; the analyst's
  review line keeps the AI's assessment and suggestion at that moment (`ai`, Q80).
- **Measured on the synthetic Check Point quarter** (52 suggestions, ground truth): qwen3.5:9b,
  batches of 5, **52 of 52 suggested decisions agreed with the ground truth** (38 accept, 14
  reject), 0 ungrounded, 522 s. The deciding facts were the ones handed over: `zabbix-trapper`
  for the heartbeat, `onedrive.live.com` reached by 131 internal hosts for the syncs, a beacon
  host's other findings. Weak spots seen: the compromised terminal server's SMB spread was
  "uncertain" (it reached for "vulnerability scanner"), and one review cited another
  suggestion's fact. One synthetic case is a lead, not a verdict.
- **Cost**: about 10 s per suggestion on this machine (36 tokens/s); up to `MAX_SUGGESTIONS` (80)
  per case, highest level first - the rest are listed as skipped. A case with many suggestions
  takes minutes longer to become ready.
- Ollama must be running on the host (`ollama serve`); the container reaches it at
  `host.docker.internal:11434`. On 2026-10-22 it was not running and the container answered
  "Network is unreachable".
