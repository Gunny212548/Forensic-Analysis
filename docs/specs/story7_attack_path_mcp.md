# Story 7 - the attack path, with external MCP tools

Status: **design draft** (2026-10-20). Nothing built. The user's direction: the attack path
step uses external MCP servers for three things - MITRE ATT&CK knowledge, threat intel on
addresses, and drawing the diagram (option 2 of three offered; the in-app agent over our
own MCP server was not chosen).

## What the step does (case_flow_design.md revision 6, step 5)

Built from the **confirmed** finding groups only (D7; Q5): a node is an address, host or
account as observed, never an identity; an edge is what an event says one node did to
another, citing its events. Today the graph is SQL over every finding (gotcha #10); story 1
left it that way.

## Where MCP fits

The app is an MCP **server** today (`app/mcp_server.py`, read-only, stdio). This story adds
an MCP **client**: the backend starts configured MCP servers as local processes over stdio
and calls their tools. "External MCP" means a server we did not write - not necessarily one
on the internet. What leaves the machine depends on the server, so each one is configured
with what it sends where:

| Use | Candidate servers (from listing sites, **not yet read**) | Runs | Sends out |
|---|---|---|---|
| ATT&CK knowledge: technique -> tactic, tactic order, names, to lay the path out by kill-chain stage and label edges | Montimage/mitre-mcp (mitreattack-python, stdio, `uvx mitre-mcp`); stoyky/mitre-attack-mcp; imouiche/mitre-attack-mcp-server (npm) | local process | **nothing** if it reads a bundled STIX file; the ATT&CK data itself if it downloads it - must be checked |
| Threat intel on external nodes: reputation, owner (WHOIS / ASN), last seen | aplaceforallmystuff/mcp-threatintel (OTX, AbuseIPDB, GreyNoise, abuse.ch); marc-shade/threat-intel-mcp (VirusTotal, AbuseIPDB, Shodan) | local process calling provider APIs | **the case's public IP addresses**, to each provider, with our API keys |
| Diagram for the report: nodes and edges -> Mermaid -> SVG / PNG | tci-nebula/mermaid-mcp (`mermaid-render-mcp`, PNG / SVG / PDF / draw.io); peng-shawn/mermaid-mcp-server (Puppeteer) | local process | **nothing** if it renders locally; draw.io-in-browser variants put the diagram in a URL - excluded |

## Rules the design keeps

1. **Nothing runs on its own.** Threat-intel lookups start only when the analyst presses
   "Look up external addresses", and the page says beforehand which addresses go to which
   provider. ATT&CK and diagram calls send nothing, so they may run without asking.
2. **Only public addresses leave.** RFC 1918, loopback, link-local and the other ranges
   R2007 already excludes are never sent. Accounts and hostnames are never sent.
3. **No contact with the attacker.** A lookup asks a third party about an address; nothing
   is ever sent *to* the address (SP 800-86 §6.4.4: "Organizations should not send network
   traffic to an apparent attacking IP address").
4. **Every external call is a recorded action**: server, tool, the arguments sent, time,
   actor, a digest of the answer - hash-chained like `mcp/access.jsonl` and listed in the
   case's custody view, because data about the evidence left the machine (RFC 3227 §4.1,
   ACPO principle 3).
5. **Answers are facts with a source, never verdicts** (layer C, D12): "AbuseIPDB: 97% abuse
   confidence, reported 1,204 times, as of 2026-10-20" on the node - the analyst decides.
   They are stored with the case, so the report shows what was known at the time.
6. **The in-app graph stays static SVG** (gotcha #10, screenshotted into reports); the
   rendered diagram is an additional export for the report.
7. **Everything still works offline.** With no server configured or the network down, the
   step draws the path from the confirmed events alone and says what was not looked up.

## Changes (outline)

| Where | What |
|---|---|
| `app/services/mcp_client.py` (new, stdlib) | start a configured server (stdio JSON-RPC 2.0), `initialize`, `tools/list`, `tools/call`, timeouts, kill on exit |
| `config` / `.env` | the allowlist of servers: command, `sends` (none / public-ip), provider API keys |
| `app/services/attack_path.py` (new) | nodes and edges from the confirmed groups; ATT&CK lookups for stage ordering; enrichment store per case |
| routes | `GET /attack-path`, `POST /attack-path/enrich` (analyst-triggered), `GET /attack-path/diagram.svg` |
| `Dockerfile` | the servers' runtimes (Node for npm servers, `uv` for Python ones), pinned versions, installed at build time - not fetched at runtime |
| `CaseFlow.jsx` | the step shows the path, the enrichment facts per node, the lookup button with its disclosure, the diagram export |
| tests | a fake MCP server (stdio) for the client; public-only filter; every call logged; offline path |

## Before building: spike (as ADR-006 did for Sigma)

Read each candidate's repository (README, license, last release, whether it downloads data
at runtime), run it in a container, and record the answers in an ADR. Pick one server per
use. No candidate above has been read yet.

## Edge labels (proposed 2026-10-21, case_flow_design revision 7)

Each edge carries the Diamond Model activity-thread label (`docs/standards/practitioner-methods.md`
§2.5): Actual (cites confirmed events) or Hypothesised (cites an analyst's note, drawn dashed),
a confidence, and what the step provides the next. Whether hypothesised edges are drawn at
all is Q30 of `case_flow_design.md`. A node stays "address / account as observed" - the
Diamond's Type 2 infrastructure is "the infrastructure that a victim will see as the
adversary".

## Questions

- **Q24 - threat-intel providers and keys.** Which providers (AbuseIPDB, GreyNoise, OTX,
  VirusTotal, Shodan), and are there API keys? Free tiers are rate-limited. The keys go in
  `.env`, like `GROQ_API_KEY`.
- **Q25 - lookups automatic or on request.** Proposed: on request, per case, with the
  disclosure shown first (rule 1).
- **Q26 - order of work.** Story 7 reads confirmed groups (exists since story 1) but is
  meant to read confirmed *events* (story 5) across the project (story 2). Build the MCP
  part now on confirmed groups, or keep the planned order?
