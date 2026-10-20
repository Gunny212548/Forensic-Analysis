# Gotcha #37

**37. The narrative is schema-constrained to the case's own evidence, and
its input is deterministic (2026-10-14).** Telling the model "use only the
rule engine's ids" was measured not to be enough: qwen3.5:9b invented
T1076 / T1552.004 / T1059 and an Execution stage in 3 runs - while the old
schema line literally said "infer from context". `grounding.py` now:

- **Builds a JSON schema per call** from what the prompt carries: technique
  ids (from the events' `mitre`, plus `T1078` / Initial Access for a
  `credential-compromise` escalation), stages = their ATT&CK tactics
  (`rule_meta.TACTICS`), timestamps, levels, addresses and entities as
  enums; caps 4 stages / 6 timeline / 3 recommendations; maxLength on free
  text (a constrained string has no natural end - a `target` ran to a
  paragraph in testing). Ollama 0.34.1 structured outputs (`format` =
  schema) decode inside it, so an off-evidence id cannot be generated.
  Map batches get the same treatment per batch. Groq gets no schema.
- **Checks the free text afterwards** (`_meta.grounding`): any IP (CIDR
  accepted if it covers a prompt IP), technique id (a parent of a supplied
  sub-technique is fine), e-mail, ISO date or distinctive stage name that
  the user prompt does not contain. Shown as a warning on the case, not
  removed. Execution/Discovery/Collection/Impact are not checked in prose -
  as English words they would flag everything.
- **Records** temperature 0, seed 42, SHA-256 of prompt and schema, and the
  allowed ids/stages in `_meta.reproducibility`.

**The evidence the model saw was random - found while testing this.** Two
runs of one case at temperature 0 / seed 42 differed. Ollama was not the
cause (identical requests were byte-identical, even across a model unload);
the prompt was. `top_distinct_findings`, `collapsed_findings`,
`risk_scores` and `source_profiles` ordered by severity/count with no
tiebreak, and `any_value()` picked any row's `descr`/`mitre`/`raw` - so 8
builds of the monsoon prompt gave **8 different prompts and 6 different
sets of events** at the top-50 cutoff. Now every such ORDER BY ends in a
total tiebreak (rid, srcip, username / entity), `any_value` became
`arg_min(..., row_id)` (the first occurrence), and `_chrono()` breaks
timestamp ties. 8 builds -> 1 prompt on all three cases. Any new query that
feeds the prompt needs the same.

Measured (qwen3.5:9b, 3000 / 1200 tokens):
- `tests/bench_llm.py` x3: 0 unsupported stages, 0 invented ids, 0
  grounding warnings, the three runs byte-identical, 33 s (was 52 s).
  Expected stages 3.0 of 6 - Persistence (R1004 is untagged) and Initial
  Access are not reached; the schema allows Initial Access, the model did
  not pick it.
- Real cases, single call: ESXi / Palo Alto / monsoon all `stop`, 0
  off-schema ids; ESXi twice -> byte-identical. Palo Alto map-reduce: 5
  batches all `stop`, 140 s.
- What it cannot catch: a wrong *relation* between real entities. The
  bench summary says root was brute-forced "on 10.10.1.5" - both exist in
  the case, the pairing is wrong. And the monsoon prose said "lateral
  movement" before the stage-name check existed.
- Allowed stages follow ATT&CK, not intuition: R2006 tags T1078, whose four
  tactics include Persistence and Defense Evasion, so those are allowed on
  the Entra/monsoon cases.

**Citations (2026-10-14).** Every quoted finding carries `ref` `F<n>` (its
rank in the pool, `grounding.assign_refs()`; a map-reduce pool is numbered
once, so `F7` is the same finding in its batch, its digest and the reduce
call). Each stage / timeline entry must give `refs` (enum of the prompt's
refs, 1-5) and `basis: fact | inference`; map digests give `refs` too.
`grounding.resolve()` adds `finding_keys`, `_meta.citations` counts them,
and the UI's chips open the finding in Review. Old cached analyses lack the
fields and render as before.

- **The wrong-relation gap is now caught - by `check()`, not the schema.**
  An address an entry names (`source_ip`, or in its description / event /
  target; a CIDR covering a stated one is fine) must be stated by one of its
  own citations (srcip or an IP in the finding's `descr`). Bench x3: every
  run flags "brute-forced root on 10.10.1.5" citing R1000/R2000 - the auth
  log never names its host, so linking it to the firewall's 10.10.1.5 is an
  inference. On monsoon it flagged the Entra spray "succeeded via root login
  from 10.8.1.50" (two unrelated members joined).
- **Don't trust the model's `basis`.** qwen3.5:9b labelled every bench entry
  `fact`, the flagged ones included; on real cases it chose `inference` 2
  times in 29 entries. The relation check is what separates them.
- **`_IPV4` used to miss every address that ends a sentence** - its
  lookahead refused a following `.`, so "...access to 10.10.1.5." was never
  read by `check()` (found building this). Now it refuses only a digit or
  `.digit`.
- Measured: bench x3 byte-identical, 24/24 entries cited, 0 invented ids or
  stages, 36 s. Real cases all `stop`, every entry cited: ESXi 32 s, Entra
  34 s, monsoon zip and Palo Alto map-reduce ~160 s with all 5 batches
  `stop`. Not caught: a citation of the wrong *finding* when the prose names
  no address - on ESXi "attacker used compromised root credentials" cites
  the legitimate 10.9.3.91 login as well. And the Palo Alto chain listed
  Command and Control twice; the schema does not forbid a repeated stage.
- The case id is in the prompt, so the bench's "byte-identical" holds per
  case: a fresh bench store (new case id) can give a different narrative -
  3 vs 4 expected stages between two stores on 2026-10-14.
