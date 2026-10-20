# Gotcha #5

**5. Groq output-token limits shape the whole prompt design.** *(Applies to
`LLM_PROVIDER=groq`. Since 2026-10-12 the app runs a local Ollama model -
see Environment / secrets; none of these limits bind it. Its output is
graded by `tests/bench_llm.py` (#37), but its settings have not been swept
the way this section's were.)*
- **`qwen/qwen3.8-27b` is the only model now** — the gpt-oss branch (and its
  `reasoning_effort: "low"` workaround for hidden reasoning tokens) is gone.
  Everything below exists to make the schema fit qwen's budget.
- qwen's **1000 OTPM** cap on this tier is *per minute across all requests*,
  and Groq reserves the full `max_tokens` up front rather than charging
  actual usage. With `MAX_COMPLETION_TOKENS=950` that means **one analysis
  per minute**: a second `POST /analyze` inside the same minute is rejected
  with a 429 (`Used 856, Requested 950`), not truncated. `run_analysis()`
  retries in place when the API asks for <=25s and otherwise raises
  `AnalysisRateLimited` → HTTP **429 + Retry-After**, so the UI says how
  long to wait instead of showing a generic 502.
- **Second sweep, after the graph moved to SQL** (8 configs on the Azure
  case): `events=15` with `timeline<=6`, `attack_chain<=4`, `temp=0.2` is
  still the right setting and needs no change. `events=20` and `events=25`
  both hit `finish_reason: length` and the timeline *shrank* to 4 entries;
  raising the timeline cap to 8 also ran out of budget and still produced 4.
  The freed graph budget does not buy more coverage - it is already spent.
- **First sweep (7 configs, one call each, graded against the
  `tests/gen_usecase.py` ground truth — don't redo this by guesswork):**

  | config | events | max_tokens | complete? | chain/timeline/recs | notes |
  |---|---|---|---|---|---|
  | base | 8 | 950 | yes | 4/2/3 | never mentions the successful root login |
  | cov12 | 12 | 950 | yes | 4/2/3 | — |
  | cov15 | 15 | 950 | yes | 4/2/3 | best narrative; success tagged T1078 |
  | fast480 | 8 | 480 | **no** | 3/0/0 | loses recommendations + timeline |
  | fast650 | 8 | 650 | **no** | 4/0/0 | loses recommendations + timeline |
  | qual15 | 15 | 950 (+hardened prompt) | yes | 4/2/3 | no gain over cov15 |
  | qual8 | 8 | 950 (+hardened prompt) | yes | 4/2/3 | no gain over base |

- What that bought: `MAX_EVENTS_FOR_ANALYSIS` 8 → **15**. The model writes the
  same ~950-token object regardless of how many events it gets, so the extra
  input (+580 prompt tokens; input is not the capped resource) is free
  coverage. At 8 events the severity cut dropped the **successful root login**
  (lvl 3) before the model ever saw it, and the narrative never mentioned the
  pivot of the whole attack; at 15 it is described and tagged `T1078.003`.
- What did **not** work, so don't retry it:
  - *Lowering `max_tokens` to fit two analyses in one minute* — at 650 and
    480 the response loses `recommendations` and `timeline` entirely. The
    schema needs ~800-950 tokens; there is no useful smaller setting.
  - *Prompt hardening for the documented soft spots* (RFC1918-is-private,
    benign-source, T1078-not-T1110) — no measurable effect at n=1, and it
    costs ~180 prompt tokens. Raising coverage fixed the T1078 mis-tag
    instead: the model wasn't reasoning badly, it was never given the
    successful-login event.
- Beware of grading heuristics: the first rubric flagged "host 10.10.1.5
  exfiltrated to external IP 203.0.113.77" as an RFC1918 error because the
  sentence contained both "external" and a private IP. Check what a
  regression grader actually matched before believing it. Raising the event
  count or loosening those caps brings truncation straight back.
- `finish_reason: length` alone does **not** mean the output is damaged —
  qwen can spend its last tokens on trailing whitespace after a complete
  object (observed). `_meta.truncated` is therefore computed from
  *missing top-level keys*, not from finish_reason.
- When the JSON really is cut off mid-write, `_salvage_json()` rewinds to the
  last completed value, closes the open brackets and parses that, so a
  response that died inside `timeline` still delivers summary/attack_chain/
  graph. `_meta.salvaged` records when this happened.
- **The model does not draw the graph any more** — see gotcha #10. The
  schema it is asked for is `summary → attack_chain → recommendations →
  timeline`, and models generate keys in schema order, so that order *is*
  the priority list when the budget runs out. Don't reorder casually.
- `analysis._normalize_graph()` still exists only to render analyses cached
  before that change (flat `"src|dst|label|mitre"` strings, or an older
  nodes/edges object). Live runs never call it.
- Check `_meta.finish_reason` and `_meta.usage` in a cached analysis if
  output ever looks incomplete.
