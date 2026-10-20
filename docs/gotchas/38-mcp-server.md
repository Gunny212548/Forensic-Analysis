# Gotcha #38

**38. Cases are readable over MCP - read-only, stdio, every call logged
(2026-10-14).** `app/mcp_server.py` is a Model Context Protocol server
(spec 2025-11-25, newline-delimited JSON-RPC 2.0 on stdio) so any MCP
client can investigate a case by asking for it instead of being handed a
pre-cut prompt:

```bash
docker exec -i forensic-analyzer-forensic-analyzer-1 \
    python -m app.mcp_server --actor you@example.com
```

19 tools, all annotated read-only: `list_cases`, `get_case` (custody
status and the Sigma logsource the file was identified as), `list_findings`,
`get_finding_events` (the raw rows behind a finding, with `row_id` and the
original line), `get_source_profiles`, `get_risk_ranking`, `get_attack_graph`,
`get_escalations`, `get_veris`, `get_rule`, `get_custody`, `get_analysis`
(served with an "AI-generated - not evidence" notice). The `initialize`
instructions tell the client it is an assistant, not the judge: quote the
rule engine's levels and tags, cite a finding_key or row_ids for every claim,
and treat uncited claims as hypotheses.

**Since 2026-10-20 (branch `mcp-tools`), what the forensic flow needs:**
`search_events` - the pivot of SP 800-86 §6.4.2: every event sharing an
address (either side), an account (case-insensitive), a host or an event type,
optionally inside a time window (ISO 8601, offsets converted to GMT+7), in time
order; at least one filter is required, so it is never a read-everything call.
`get_events` - rows by `row_id`, what a citation points at, naming the ids
that do not exist. `get_timeline` - the whole case in event-time order, paged.
`list_confirmed` - the finding groups the analyst confirmed (Accepted /
Modified), by first event, with who decided; plus the undecided / rejected
counts - the attack events to build a path from. `get_flow` - the six steps.
Every row carries the event type (`event`, layer A, from `db.EVENT_TYPES` -
the same words the events table shows) and its `context` facts (layer C),
because all lists of events go through one query, `db._events`. The status
workflow (lifecycle) is no longer served: Respond left the flow (story 1).
`get_profile` / `list_unusual` (branch `behaviour-profiles`) serve the behaviour
profiles of gotcha #57 - counted in SQL, so the model reads facts it could not count.

What it deliberately does not do, so don't add it casually:
- **No write tool.** Review, lifecycle and upload take their actor from a
  session; a write over MCP would need its own authorisation story.
- **No free SQL.** A query tool is a read-anything tool.
- **No port.** stdio via `docker exec`: whoever can run that already reads
  `/data`, so it needs no second auth system. `--actor` must be an account
  in `users.json` (exit 2 otherwise) and goes on every access record.
- **No SDK.** stdlib only; the `mcp` package brings its own
  starlette/pydantic and the app pins fastapi 0.115 / starlette 0.38.6.

Every `tools/call` - refusals included - appends to
`DATA_DIR/mcp/access.jsonl` through `hashchain.py` (ISO/IEC 27037: access
to evidence is recorded). Several MCP sessions are several *processes*, and
hashchain's lock is in-process, so the append is wrapped in an `flock`.
That lock is load-bearing, not belt-and-braces: with it removed,
`tests/check_mcp.py`'s 3-server x 25-call burst broke the chain at entry 23
("sequence number is 22"). A case id is regex-checked before it touches a
path (`../users` is refused). A DuckDB file locked by a running pipeline
comes back as a tool error, not a crash.

**A cloud client takes the data off the machine.** The local narrative
model keeps case data on the host; Claude Desktop/Code or any hosted model
reading through this server does not. Decide per customer before wiring one
up - nothing in the server can tell where its client sends what it reads.

Verified with `tests/check_mcp.py` (in the container on a
scratch store: handshake, all 19 tools against the planted gen_usecase
facts - digest equals the uploaded bytes, the brute force -> root
escalation, rows per finding - every refusal, stdout purity, one access
entry per call, chain intact, concurrent writers).
