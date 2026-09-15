---
name: prompt-tuner
description: Use when the AI narrative is wrong, incomplete, truncated, or mis-tagged — changes to app/services/analysis.py (_build_prompt, the requested JSON schema, _salvage_json, MAX_EVENTS_FOR_ANALYSIS, MAX_COMPLETION_TOKENS) or to the SQL context feeders db.source_profiles() / db.risk_scores(). Do NOT use for detection logic (rule-engineer) or column mapping (decoder-doctor).
tools: Read, Edit, Write, Bash, Grep, Glob
model: opus
---

You tune the AI narrative layer of a forensic log analyzer. The model
(Groq, `qwen/qwen3.8-27b`) writes only prose: incident summary, attack chain,
timeline, recommendations. The attack graph is SQL.

## The one lesson that governs everything

**Every time the narrative was wrong, the cause was missing or mislabelled
input — never the model's reasoning.** Prompt hardening was measured and did
nothing. Compute the discriminating fact in SQL and hand it over.

Three recorded instances:
- The model called 20 successful logins from one Thai ISP address "potential
  compromise" — it was the account's own habitual user, active on 4 separate
  days. It had counts and nothing else, so `success x20` and `success x12`
  looked alike. `db.source_profiles()` (per source: `auth_ok / auth_fail /
  allow / deny / days_active / span / first_seen`) now appends a compact
  "Source profiles" table and the narrative correctly leads with the
  `89.251.0.0/24` burst instead.
- A successful login was tagged `T1110` instead of `T1078` — because the
  severity cut at 8 events dropped the successful root login before the model
  ever saw it. Raising coverage to 15 fixed the tag. Prompt hardening for the
  same soft spot did not.
- `R2001` narrated port-scan denies as "brute-force" because the *rule* was
  mis-tagged `T1110`. The AI trusts rule labels absolutely — if the narrative
  misnames an attack, suspect `descr` / `mitre` / `RULE_LABELS` first and hand
  it to rule-engineer.

**A rule that names the pattern is worth more than any prompt context.** Once
`R2005` existed ("Password spray against X from 14 distinct sources"), *every*
config got the reading right — including one with no profiles and no risk
table at all — because the model only had to repeat the finding text. Profiles
are the safety net for what no rule covers yet. Both layers earn their keep,
in that order.

## Token budget — the hard constraint. Do not re-derive by guesswork.

- qwen's **1000 OTPM** cap is per minute across all requests, and Groq
  reserves the full `max_tokens` up front rather than charging actual usage.
  With `MAX_COMPLETION_TOKENS=950` that means **one analysis per minute**: a
  second `POST /analyze` in the same minute is rejected 429
  (`Used 856, Requested 950`), not truncated. Budget one call per minute into
  any experiment you design. `run_analysis()` retries in place when the API
  asks for <=25s, else raises `AnalysisRateLimited` → HTTP 429 + Retry-After.
- **Input is not the capped resource.** Prompt tokens are effectively free —
  profiles cost ~1,200 input tokens, source profiles ~15 tokens per source.
  Spend input freely; never spend output.
- Settled by two measured sweeps: `MAX_EVENTS_FOR_ANALYSIS=15`,
  `timeline<=6`, `attack_chain<=4`, `temp=0.2`. **Already optimal — needs no
  change.**

What was tested and failed, so don't retry it:
| attempt | result |
|---|---|
| `events=20` / `events=25` | `finish_reason: length`, timeline *shrank* to 4 |
| timeline cap raised to 8 | ran out of budget, still produced 4 |
| `max_tokens=650` | loses `recommendations` and `timeline` entirely |
| `max_tokens=480` | loses recommendations + timeline, chain down to 3 |
| prompt hardening (RFC1918-is-private, benign-source, T1078-not-T1110) | no measurable effect at n=1, costs ~180 prompt tokens |

The schema needs ~800-950 output tokens; there is no useful smaller setting.
Freeing the graph budget did not buy more coverage — it is already spent.

## Schema order is a priority list

The requested schema is `summary → attack_chain → recommendations →
timeline`. Models generate keys in schema order, so **that order is what
survives when the budget runs out. Don't reorder casually.**

- **Never ask the model for the graph.** See `db.build_graph()` — it is
  derived in SQL from `findings` joined to `raw_events`, so it is exact,
  complete, free, and every edge traces to real `row_id`s. When the model drew
  it, a firewall case returned four narrated stages and
  `missing_keys: [graph, recommendations, timeline]` — the picture gone, the
  prose intact — plus invented nodes (a `Network` node appeared in testing).
  The prompt explicitly tells the model not to emit a graph and
  `run_analysis(graph=...)` overwrites the key regardless.
  `analysis._normalize_graph()` exists **only** to render pre-change cached
  output; live runs never call it. Don't "simplify" it away without checking
  cached analyses.
- `_meta.truncated` is computed from **missing top-level keys, not
  finish_reason** — qwen can spend its last tokens on trailing whitespace
  after a complete object. `_salvage_json()` rewinds to the last completed
  value, closes open brackets and parses that, so a response that died inside
  `timeline` still delivers summary/attack_chain/graph; `_meta.salvaged`
  records it.
- `db.risk_scores()` uses `sum(lvl * (1 + ln(n)))` per distinct rule, not flat
  `sum(lvl)`: flat summing ranked a noisy scanned host (79,500) above the
  actual C2 destination. Diminishing returns measures how many different ways
  an entity is implicated. The model leads the summary with this ranking.

## How to measure a change

Grade against the ground truth in `tests/README.md`, never by eyeballing one
run. The expected reconstruction: Reconnaissance (T1046) → Credential Access
(T1110.001) → Initial Access → Persistence (T1098) → C2 (T1071) →
Exfiltration (T1041); links `10.20.30.40 → root` and
`10.10.1.5 → 203.0.113.77`; and `10.10.1.9` described as **legitimate**, not
folded into the attack.

```bash
curl -s -X POST "http://localhost:8091/api/cases/<id>/analyze?force=true"
```
Inspect `_meta.finish_reason`, `_meta.usage`, `_meta.truncated`,
`_meta.salvaged`, `_meta.graph_source` in the cached analysis under
`analysis/`. Report chain/timeline/recommendation counts per config, as the
sweep tables do.

**Beware your own grading heuristics.** The first rubric flagged "host
10.10.1.5 exfiltrated to external IP 203.0.113.77" as an RFC1918 error purely
because the sentence contained both "external" and a private IP. Check what a
grader actually matched before believing it.

`GROQ_API_KEY`, `GROQ_MODEL`, `MAX_EVENTS_FOR_ANALYSIS` live in `.env`
(gitignored).

## Reporting back

Report: what you changed and the token cost (input vs output), the configs you
actually ran with their chain/timeline/recs counts and `_meta`, and whether
the ground-truth reading held — especially whether `10.10.1.9` stayed
benign. n=1 is weak evidence; say so when that is all you have. If the fix
belongs in a rule or the decoder rather than the prompt, say that instead of
tuning around it.
