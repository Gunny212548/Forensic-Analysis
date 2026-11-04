---
name: local-llm
description: The local Ollama model behind the AI review of suggestions, the narrative and the report summary: what qwen3.5:9b costs on this PC, the model benchmark, why qwen3.5:9b, the settings in force, the thinking-model flag, map-reduce token caps, and the old Groq path. Load before changing the model or any OLLAMA_* / TRIAGE_* setting, or before reasoning about AI speed, cost or quality.
---

# Local LLM (Ollama)

Moved out of `CLAUDE.md` on 2026-11-04, word for word; `CLAUDE.md` keeps the one-line rules and the gotcha index. **Before changing code a gotcha names, read `docs/gotchas/NN-*.md`.** If this file and the code disagree, the code is the fact - fix this file (doc-keeper).

Ollama must be running on the host (`ollama serve`); `TRIAGE_ENABLED=0` turns the AI review off - see *Environment* in `CLAUDE.md`.

**What the model costs on this PC (measured 2026-10-26, gotcha #71).** RTX 5050 Laptop, 8 GB VRAM:
qwen3.5:9b loads 30 of 33 layers on the GPU (4.4 GB, KV 512 MB for one 16,384-token slot,
`n_slots = 1`), ~35 tokens/s. The AI review writes ~300 tokens a suggestion: **~9 s a suggestion at
`TRIAGE_BATCH` 5** - Mekong 61 in ~10 min, the blind quarter's 526 in ~80 min. A batch of 10 or 15
is cut off at the 3,000-token cap and falls back to single calls (~32 s a suggestion) - keep 5. A
single batch-5 call is ~1,500 tokens for one suggestion; running two requests at once
(`OLLAMA_NUM_PARALLEL`) is proposed, not measured - it changes the user's Ollama settings, so ask.

**The narrative LLM is local now (2026-10-12): `LLM_PROVIDER=ollama`,
`OLLAMA_MODEL=qwen2.5:7b-instruct`, then `qwen3.5:9b` from 2026-10-14 (see
below)** on the host's Ollama
(`host.docker.internal:11434`). Settings in force (`.env`; since 2026-11-02 the
`docker-compose.yml`, `.env.example` and `config.py` defaults are the same - ollama, qwen3.5:9b):
`OLLAMA_MAX_EVENTS_FOR_ANALYSIS` 50, `OLLAMA_MAX_COMPLETION_TOKENS` 3000,
`OLLAMA_MAP_COMPLETION_TOKENS` 1200, `OLLAMA_TEMPERATURE` 0 and
`OLLAMA_SEED` 42 (config defaults - gotcha #37); `config.py` swaps these in
for the Groq values. Also pulled on the host: `gemma4:12b-it-qat`,
`gemma4:e4b`, `qwen2.5:7b-instruct`. Consequences:
- **Gotcha #5's limits are Groq's** (1000 OTPM, 950 max_tokens, one
  analysis a minute, 429 + Retry-After). They do not bind a local model.
  The local settings are graded by `tests/bench_llm.py` against
  gen_usecase's ground truth (below and #37), but the events / token
  numbers were **not** swept the way #5 swept Groq's - that is still open.
- A 7B model is weaker: on the ESXi case it wrote an attack chain with
  Execution / Defense Evasion / Discovery stages no finding supports.
- **Thinking models need `"think": false`** (`analysis._to_ollama`).
  qwen3.5 and gemma4 reason before answering and that reasoning counts
  against `num_predict`: gemma4:12b spent all 2400 tokens thinking and
  returned empty content (502, finish `length`) on both runs. The prompt's
  `/no_think` is a Qwen convention the others ignore. Non-thinking models
  accept the flag (checked on qwen2.5).

**Local model benchmark (2026-10-12, `tests/bench_llm.py`, 3 runs each,
thinking off).** gen_usecase's two files zipped into one case, graded
against tests/README.md's ground truth:

| model | ok | avg s | expected stages hit (of 6) | unsupported stages | invented ATT&CK ids |
|---|---|---|---|---|---|
| qwen2.5:7b-instruct (in use until 2026-10-14) | 3/3 | 21 | 2.0 | 5 | 3 |
| **qwen3.5:9b** | 3/3 | 54 | 3.0 | **0** | **0** |
| gemma4:e4b | 3/3 | 19 | **4.3** | 3 | 4 (T1021.001 RDP) |
| gemma4:12b-it-qat | 3/3 | 93 | 3.7 | 1 | 2 (T1073.003) |

All named the four planted entities every run and none put the benign
10.10.1.9 into the chain. qwen3.5:9b never invented a stage or a technique
*in these three runs* - but it overruns the 6-entry timeline cap (up to 13)
and used up to 2,164 of the 2,400 completion tokens. n=3 on one synthetic
case: a lead, not a verdict - see the re-run below.

**Switched to qwen3.5:9b on 2026-10-14** (`.env`: `OLLAMA_MODEL=qwen3.5:9b`,
`OLLAMA_MAX_COMPLETION_TOKENS=3000`, `OLLAMA_MAP_COMPLETION_TOKENS=1200`;
the defaults in docker-compose / config.py followed on 2026-11-02). Measured
after the switch:
- **Re-run of the benchmark (3 more runs): 1 unsupported stage
  (Execution) and 5 invented ids** (T1076 - a deprecated RDP id -,
  T1552.004, T1059), all completions under 1,900 tokens. So over 6 runs
  qwen3.5 is clearly better on *stages* than qwen2.5 but not on technique
  ids. The likely cause is the schema itself: `"mitre": [... REQUIRED, infer
  from context if the underlying events didn't already have one]` asks the
  model to invent. **Fixed the same day (gotcha #37):** the schema now
  allows only the ids and stages the evidence carries, and the re-run gave
  0 unsupported stages, 0 invented ids and three byte-identical runs in
  33 s.
- Three real cases, single call: all `stop`, 1,282-1,488 tokens, 42-49 s,
  no unsupported stage; on ESXi it called 10.9.3.91 a legitimate internal
  host (source profiles at work); on the monsoon zip it called 10.8.1.50 an
  "external actor" (the RFC1918 soft spot of #5, still there).
- **Map-reduce needs the bigger map cap.** The Palo Alto case (1,516
  groups) runs 5 batches + 1 reduce. At the old 600 map tokens 3 of 5
  batches ended `length` and the final chain gained Collection / Defense
  Evasion; at 1,200 every batch ended `stop` (529-631 tokens each - just
  over 600) and the chain was Reconnaissance / C2 / Exfiltration. 154 s
  for the whole case.
- Case data no longer leaves the machine for the narrative - which also
  settles the confidentiality question NIST AI RMF GOVERN raises.
