# Gotcha #10

**10. The attack graph is SQL, not AI — don't hand it back to the model.**
`db.build_graph()` derives it from `findings` joined to `raw_events`:
`srcip → coalesce(dstip, username)`, grouped per pair, rules merged into one
edge, MITRE IDs unioned, sorted by severity then volume. The graph is not
interpretation — every field an edge needs is already in the findings table,
put there by the rule engine.

Asking the model for it (the original design) cost real damage on qwen's
budget: at 950 output tokens a firewall case returned four narrated stages
and `missing_keys: [graph, recommendations, timeline]` — the picture gone,
the prose intact. It also capped edges at whatever fit, and let node names
drift from the evidence (an invented `Network` node appeared in testing).
Derived in SQL the graph is exact, complete, free, and every edge traces
back to real `row_id`s; the whole output budget goes to the narrative
(measured after the switch: 915 tokens, `finish_reason: stop`, timeline back
to 5 entries).

The prompt now explicitly tells the model *not* to emit a graph, and
`run_analysis(graph=...)` overwrites the key regardless. `_meta.graph_source`
records which produced it (`rules` vs `model` for old cached output).
