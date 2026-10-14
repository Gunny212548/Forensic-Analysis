"""Read-only Model Context Protocol server over the case store.

    docker exec -i forensic-analyzer-forensic-analyzer-1 \
        python -m app.mcp_server --actor you@example.com

Any MCP client (Claude Code, Claude Desktop, a local agent) can then ask
questions of a case - findings, the raw rows behind them, profiles, risk,
custody - instead of being handed a pre-cut prompt. The design follows the
rule the narrative already lives by: **the model is an assistant, not the
judge of the evidence.** Every finding comes from the rule engine, every
answer can be traced to a `finding_key` or `row_id`, and the AI narrative is
served labelled as what it is.

Deliberately:
- **stdio only.** No port is opened; whoever can `docker exec` into the
  container can already read /data, so no second auth system is needed. The
  `--actor` must be an account in users.json and is written to every access
  record.
- **Read-only, fixed queries.** No tool writes (review, lifecycle and upload
  stay in the UI, where the session decides the actor) and there is no free
  SQL - a query tool would be a read-anything tool.
- **Every call is logged** to `DATA_DIR/mcp/access.jsonl`, hash-chained
  (hashchain.py): reading evidence is an access the chain of custody should
  show (ISO/IEC 27037).
- **stdlib only.** MCP over stdio is newline-delimited JSON-RPC 2.0; the
  official SDK would pull its own starlette/pydantic and risk the versions
  this app pins. Spec: modelcontextprotocol.io, revision 2025-11-25.

Note for whoever wires a client: a *cloud* model reading through this
server sends case data off the machine, which the local narrative model
does not (CLAUDE.md, Environment).
"""

import argparse
import json
import re
import sys
import threading
from pathlib import Path

from . import config
from .services import (auth, custody, db, hashchain, rule_meta, storage,
                       veris)
from .services.rules import RULE_LABELS
from .services.severity import LEVELS, WEIGHT

SERVER_NAME = "forensic-analyzer"
SERVER_VERSION = "1.0.0"
PROTOCOLS = ["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"]

INSTRUCTIONS = """\
Forensic Analyzer case store, read-only.

You are an assistant to the analyst, not the judge of the evidence:
- Findings, their Sigma levels, ATT&CK ids, escalations and Admiralty
  grades are computed by the rule engine. Quote them; do not re-grade or
  re-tag them.
- Cite every statement: case_id plus a finding_key (rid|srcip|username) or
  row_ids from get_finding_events. A claim you cannot cite is a hypothesis -
  say so and name the evidence that would confirm it.
- get_analysis returns an AI-generated narrative. It is not evidence; check
  it against get_finding_events before repeating it.
- All times are GMT+7 (+07:00); every event was normalised to it at ingest.
- Check get_case's custody status before relying on a case: a broken chain
  or a digest mismatch means the evidence cannot be vouched for.
"""

_CASE_ID = re.compile(r"^case-\d{8}-\d{6}-[0-9a-f]{8}$")
_RULE_ID = re.compile(r"^R\d{4}$")
MAX_ROWS = 200

_write_lock = threading.Lock()


class ToolError(Exception):
    """A refusal the client should see as a tool result (isError), not as a
    protocol failure."""


# ------------------------------------------------------------------ access log

def access_log_path() -> Path:
    return Path(config.DATA_DIR) / "mcp" / "access.jsonl"


def _log_access(actor: str, tool: str, args: dict, outcome: str) -> None:
    """One hash-chained line per call. Several MCP sessions are separate
    processes, so hashchain's in-process lock is not enough: an flock around
    the append keeps two of them from linking to the same previous entry."""
    path = access_log_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    entry = {"actor": actor, "tool": tool, "outcome": outcome,
             "arguments": {k: v for k, v in args.items() if k in
                           ("case_id", "finding_key", "rule_id", "ips", "limit", "offset", "min_level")}}
    with _write_lock, open(path.with_suffix(".lock"), "a") as lock:
        try:
            import fcntl
            fcntl.flock(lock, fcntl.LOCK_EX)
        except ImportError:  # Windows host run: single process is all there is
            pass
        hashchain.append(path, entry)


# ----------------------------------------------------------------------- tools

def _case(case_id) -> dict:
    """Validated before it is ever joined into a path: a case id that is not
    the storage format could otherwise walk out of DATA_DIR."""
    if not isinstance(case_id, str) or not _CASE_ID.match(case_id):
        raise ToolError("case_id must look like case-YYYYMMDD-HHMMSS-xxxxxxxx (see list_cases)")
    manifest = storage.load_manifest(case_id)
    if manifest is None:
        raise ToolError(f"No case {case_id}")
    return manifest


def _ready(manifest: dict) -> None:
    if manifest.get("status") != "ready":
        raise ToolError(f"Case {manifest['case_id']} is {manifest.get('status')}, not ready - "
                        "its findings are missing or incomplete.")


def _evidence_sha(manifest: dict) -> str | None:
    return (manifest.get("evidence") or {}).get("sha256")


def _custody_status(case_id: str, manifest: dict) -> dict:
    intact, problem = custody.verify_chain(case_id)
    entries = custody.entries(case_id)
    checks = [e for e in entries if e.get("action") in ("verified", "unverified", "integrity_failed")]
    ev = manifest.get("evidence") or {}
    return {
        "evidence_sha256": ev.get("sha256"),
        "digest_retroactive": bool(ev.get("retroactive")),
        "chain_intact": intact,
        "chain_problem": problem,
        "entries": len(entries),
        "last_check": ({k: checks[-1].get(k) for k in ("action", "ts", "actor", "sha256")}
                       if checks else None),
    }


def tool_list_cases(args: dict) -> dict:
    customer = (args.get("customer") or "").strip().lower()
    out = []
    for m in storage.list_manifests():
        if customer and customer not in (m.get("company_name") or "").lower():
            continue
        out.append({
            "case_id": m.get("case_id"),
            "file": m.get("original_filename"),
            "customer": m.get("company_name"),
            "status": m.get("status"),
            "uploaded_at": m.get("uploaded_at"),
            "rows": m.get("total_rows"),
            "flagged_rows": m.get("flagged_count"),
            "max_level": (m.get("severity") or {}).get("max_level"),
            "evidence_sha256": _evidence_sha(m),
        })
    return {"cases": out, "count": len(out)}


def tool_get_case(args: dict) -> dict:
    m = _case(args.get("case_id"))
    mapping = m.get("mapping") or {}
    return {
        "case_id": m["case_id"],
        "file": m.get("original_filename"),
        "customer": m.get("company_name"),
        "status": m.get("status"),
        "error": m.get("error"),
        "uploaded_at": m.get("uploaded_at"),
        "rows": m.get("total_rows"),
        "flagged_rows": m.get("flagged_count"),
        "severity": m.get("severity"),
        "rules_matched": m.get("rules_matched"),
        "escalations": m.get("escalations"),
        "mapping": {k: mapping.get(k) for k in ("method", "profile", "name", "fields", "docs")
                    if k in mapping} or None,
        "members": [{k: x.get(k) for k in ("name", "rows", "row_id_first", "row_id_last", "mapping")}
                    for x in (m.get("members") or [])] or None,
        "custody": _custody_status(m["case_id"], m),
    }


def _finding_summary(f: dict) -> dict:
    return {
        "finding_key": f["key"],
        "rule": f["rid"],
        "rule_label": RULE_LABELS.get(f["rid"]),
        "level": f.get("level"),
        "base_level": f.get("base_level"),
        "escalation": [{k: e.get(k) for k in ("pattern", "level", "reason", "evidence")}
                       for e in f.get("escalation") or []] or None,
        "srcip": f.get("srcip"),
        "username": f.get("username"),
        "description": f.get("descr"),
        "mitre": f.get("mitre"),
        "rows": f.get("cnt"),
        "ts_first": f.get("ts_first"),
        "ts_last": f.get("ts_last"),
        "admiralty": (f.get("admiralty") or {}).get("code"),
        "confidence": f.get("confidence"),
        "review": (f.get("review") or {}).get("status"),
        "lifecycle": (f.get("lifecycle") or {}).get("status") if (f.get("lifecycle") or {}).get("tracked") else None,
    }


def tool_list_findings(args: dict) -> dict:
    # Imported here: routers.cases pulls FastAPI, and only this tool needs
    # the exact view the UI and the exports share.
    from .routers.cases import _findings_view
    m = _case(args.get("case_id"))
    _ready(m)
    min_level = args.get("min_level") or "informational"
    limit, offset = _page(args, 50)
    findings = [f for f in _findings_view(m["case_id"], m)
                if (f.get("lvl") or 0) >= WEIGHT[min_level]]
    findings.sort(key=lambda f: (-(f.get("lvl") or 0), -(f.get("cnt") or 0), f["key"]))
    return {"case_id": m["case_id"], "evidence_sha256": _evidence_sha(m),
            "total": len(findings), "offset": offset,
            "findings": [_finding_summary(f) for f in findings[offset:offset + limit]]}


def tool_get_finding_events(args: dict) -> dict:
    m = _case(args.get("case_id"))
    _ready(m)
    key = args.get("finding_key")
    if not isinstance(key, str) or not _RULE_ID.match(key.split("|", 1)[0]):
        raise ToolError("finding_key is rid|srcip|username, as list_findings returns it")
    limit, offset = _page(args, 50)
    res = db.finding_rows(m["case_id"], key, limit, offset)
    if not res["total"]:
        raise ToolError(f"No rows for finding {key} in {m['case_id']}")
    return {"case_id": m["case_id"], "finding_key": key, "evidence_sha256": _evidence_sha(m),
            "total": res["total"], "offset": offset, "rows": res["rows"]}


def tool_get_source_profiles(args: dict) -> dict:
    m = _case(args.get("case_id"))
    _ready(m)
    ips = [str(i) for i in (args.get("ips") or [])][:50]
    return {"case_id": m["case_id"], "profiles": db.source_profiles(m["case_id"], ips, limit=50)}


def tool_get_risk_ranking(args: dict) -> dict:
    m = _case(args.get("case_id"))
    _ready(m)
    return {"case_id": m["case_id"], "method": "sum over rules of level weight x (1 + ln rows); "
            "an ordering, not a probability (docs/STANDARDS.md)",
            "ranking": db.risk_scores(m["case_id"])}


def tool_get_attack_graph(args: dict) -> dict:
    m = _case(args.get("case_id"))
    _ready(m)
    return {"case_id": m["case_id"], "source": "derived in SQL from findings, not by a model",
            "graph": db.build_graph(m["case_id"])}


def tool_get_escalations(args: dict) -> dict:
    m = _case(args.get("case_id"))
    _ready(m)
    return {"case_id": m["case_id"], "escalations": db.escalation_paths(m["case_id"])}


def tool_get_veris(args: dict) -> dict:
    from .routers.cases import _findings_view
    m = _case(args.get("case_id"))
    _ready(m)
    record = veris.build(m["case_id"], m, _findings_view(m["case_id"], m))
    return {"case_id": m["case_id"], "veris": record,
            "note": None if record else "No high or critical finding - no incident record."}


def tool_get_rule(args: dict) -> dict:
    rid = args.get("rule_id")
    if not isinstance(rid, str) or not _RULE_ID.match(rid) or rid not in rule_meta.RULE_META:
        raise ToolError(f"Unknown rule {rid!r}; rule ids look like R2000")
    return rule_meta.describe(rid)


def tool_get_custody(args: dict) -> dict:
    m = _case(args.get("case_id"))
    return {"case_id": m["case_id"], "status": _custody_status(m["case_id"], m),
            "entries": custody.entries(m["case_id"])}


def tool_get_analysis(args: dict) -> dict:
    m = _case(args.get("case_id"))
    a = storage.load_analysis(m["case_id"])
    if not a:
        return {"case_id": m["case_id"], "analysis": None,
                "note": "No narrative has been generated for this case."}
    meta = a.get("_meta") or {}
    return {
        "case_id": m["case_id"],
        "notice": "AI-generated narrative - not evidence. Verify each statement with "
                  "get_finding_events before relying on it.",
        "analysis": {k: a.get(k) for k in ("summary", "attack_chain", "timeline", "recommendations")},
        "generated_by": {k: meta.get(k) for k in ("provider", "model", "events_analyzed", "events_total")},
        "grounding": meta.get("grounding"),
        "reproducibility": meta.get("reproducibility"),
    }


def _page(args: dict, default: int) -> tuple[int, int]:
    limit = args.get("limit", default)
    offset = args.get("offset", 0)
    if not isinstance(limit, int) or not 1 <= limit <= MAX_ROWS:
        raise ToolError(f"limit must be 1-{MAX_ROWS}")
    if not isinstance(offset, int) or offset < 0:
        raise ToolError("offset must be >= 0")
    return limit, offset


_CASE_PROP = {"case_id": {"type": "string", "description": "From list_cases, e.g. case-20261009-083559-c46461a1"}}
_PAGE_PROPS = {"limit": {"type": "integer", "minimum": 1, "maximum": MAX_ROWS},
               "offset": {"type": "integer", "minimum": 0}}


def _schema(props: dict | None = None, required: list[str] | None = None) -> dict:
    return {"type": "object", "properties": props or {}, "required": required or [],
            "additionalProperties": False}


TOOLS = {
    "list_cases": (tool_list_cases, "List cases",
                   "Every case in the store: file, customer, status, row counts, highest Sigma level, evidence SHA-256.",
                   _schema({"customer": {"type": "string", "description": "Substring of the customer name"}})),
    "get_case": (tool_get_case, "Case overview",
                 "One case's manifest: counts, severity, matched rules, escalations, how the log was "
                 "mapped (documented / heuristic / unrecognised), zip members, and custody status "
                 "(acquisition digest, hash-chain check, last verification).",
                 _schema(_CASE_PROP, ["case_id"])),
    "list_findings": (tool_list_findings, "List findings",
                      "Collapsed findings (one per rule|source|account), most severe first, with Sigma "
                      "level, escalation, ATT&CK ids, Admiralty grade, analyst review status and lifecycle.",
                      _schema({**_CASE_PROP, "min_level": {"enum": list(LEVELS)}, **_PAGE_PROPS}, ["case_id"])),
    "get_finding_events": (tool_get_finding_events, "Rows behind a finding",
                           "The raw log rows a finding was raised on, with row_id, timestamp (GMT+7), "
                           "source text and the original line - what any statement must be checked against.",
                           _schema({**_CASE_PROP, "finding_key": {"type": "string",
                                    "description": "rid|srcip|username as list_findings returns it"},
                                    **_PAGE_PROPS}, ["case_id", "finding_key"])),
    "get_source_profiles": (tool_get_source_profiles, "Source profiles",
                            "How each source address behaved across the whole case: auth ok/fail, "
                            "allow/deny, days active, span, first/last seen.",
                            _schema({**_CASE_PROP, "ips": {"type": "array", "items": {"type": "string"},
                                                           "maxItems": 50}}, ["case_id", "ips"])),
    "get_risk_ranking": (tool_get_risk_ranking, "Risk ranking",
                         "Sources, destinations and accounts ranked by accumulated finding severity.",
                         _schema(_CASE_PROP, ["case_id"])),
    "get_attack_graph": (tool_get_attack_graph, "Attack graph",
                         "Source -> target edges derived in SQL from the findings, with rules and ATT&CK ids.",
                         _schema(_CASE_PROP, ["case_id"])),
    "get_escalations": (tool_get_escalations, "Attack-path escalations",
                        "Each credential-compromise / compromised-host pattern that fired, with its "
                        "source, account and rules.",
                        _schema(_CASE_PROP, ["case_id"])),
    "get_veris": (tool_get_veris, "VERIS record",
                  "The case's VERIS 1.4 classification (actor, action, asset, attribute), computed from "
                  "its high/critical findings.",
                  _schema(_CASE_PROP, ["case_id"])),
    "get_rule": (tool_get_rule, "Rule documentation",
                 "A detection rule's Sigma metadata and ADS documentation: goal, strategy, blind spots, "
                 "false positives, validation.",
                 _schema({"rule_id": {"type": "string", "description": "e.g. R2000"}}, ["rule_id"])),
    "get_custody": (tool_get_custody, "Chain of custody",
                    "The full hash-chained custody log of a case and whether the chain verifies.",
                    _schema(_CASE_PROP, ["case_id"])),
    "get_analysis": (tool_get_analysis, "AI narrative",
                     "The cached AI narrative, labelled as AI output, with its grounding check and "
                     "reproducibility record.",
                     _schema(_CASE_PROP, ["case_id"])),
}


def _check_args(schema: dict, args) -> dict:
    """The subset of JSON Schema these tools use - enough that a malformed
    call is refused with a reason instead of failing inside a query."""
    if not isinstance(args, dict):
        raise ToolError("arguments must be an object")
    props = schema["properties"]
    for name in schema["required"]:
        if name not in args:
            raise ToolError(f"missing argument {name}")
    for name, value in args.items():
        if name not in props:
            raise ToolError(f"unknown argument {name}")
        p = props[name]
        kind = p.get("type")
        if kind == "string" and not isinstance(value, str):
            raise ToolError(f"{name} must be a string")
        if kind == "integer" and (not isinstance(value, int) or isinstance(value, bool)):
            raise ToolError(f"{name} must be an integer")
        if kind == "array" and not isinstance(value, list):
            raise ToolError(f"{name} must be an array")
        if "enum" in p and value not in p["enum"]:
            raise ToolError(f"{name} must be one of {p['enum']}")
    return args


# -------------------------------------------------------------------- protocol

class Server:
    def __init__(self, actor: str):
        self.actor = actor

    def handle(self, msg) -> dict | None:
        """One JSON-RPC message in, one response out (None for notifications)."""
        if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0" or "method" not in msg:
            return _error(msg.get("id") if isinstance(msg, dict) else None, -32600, "Invalid Request")
        method, mid = msg["method"], msg.get("id")
        if "id" not in msg:
            return None  # notifications/initialized, notifications/cancelled, ...
        params = msg.get("params") or {}
        if method == "initialize":
            asked = params.get("protocolVersion")
            return _result(mid, {
                "protocolVersion": asked if asked in PROTOCOLS else PROTOCOLS[0],
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": SERVER_NAME, "title": "Forensic Analyzer (read-only)",
                               "version": SERVER_VERSION},
                "instructions": INSTRUCTIONS,
            })
        if method == "ping":
            return _result(mid, {})
        if method == "tools/list":
            return _result(mid, {"tools": [
                {"name": name, "title": title, "description": desc, "inputSchema": schema,
                 "annotations": {"readOnlyHint": True, "destructiveHint": False,
                                 "idempotentHint": True, "openWorldHint": False}}
                for name, (_, title, desc, schema) in TOOLS.items()
            ]})
        if method == "tools/call":
            name = params.get("name")
            if name not in TOOLS:
                return _error(mid, -32602, f"Unknown tool: {name}")
            fn, _, _, schema = TOOLS[name]
            args = params.get("arguments") or {}
            try:
                data = fn(_check_args(schema, args))
                outcome, is_error = "ok", False
            except ToolError as exc:
                data, outcome, is_error = {"error": str(exc)}, "refused", True
            except Exception as exc:  # noqa: BLE001 - e.g. the DuckDB file is locked mid-processing
                data = {"error": f"{type(exc).__name__}: {exc}"[:300]}
                outcome, is_error = "error", True
            _log_access(self.actor, name, args if isinstance(args, dict) else {}, outcome)
            text = json.dumps(data, ensure_ascii=False, default=str)
            result = {"content": [{"type": "text", "text": text}], "isError": is_error}
            if not is_error:
                result["structuredContent"] = json.loads(text)
            return _result(mid, result)
        return _error(mid, -32601, f"Method not found: {method}")


def _result(mid, result: dict) -> dict:
    return {"jsonrpc": "2.0", "id": mid, "result": result}


def _error(mid, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": mid, "error": {"code": code, "message": message}}


def serve(actor: str, stdin=None, stdout=None) -> None:
    """Newline-delimited JSON-RPC on stdin/stdout. stdout carries protocol
    messages only, so anything else that prints during a call (a library's
    warning) is sent to stderr instead."""
    stdin = stdin or sys.stdin
    out = stdout or sys.stdout
    sys.stdout = sys.stderr
    server = Server(actor)
    for line in stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            reply = _error(None, -32700, "Parse error")
        else:
            reply = server.handle(msg)
        if reply is not None:
            out.write(json.dumps(reply, ensure_ascii=False, default=str) + "\n")
            out.flush()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--actor", required=True,
                    help="the account (users.json email) every access is recorded under")
    args = ap.parse_args()
    email = auth.normalize_email(args.actor)
    if email not in auth.load_users():
        print(f"--actor {email}: no such account (tools/create_user.py list)", file=sys.stderr)
        return 2
    serve(email)
    return 0


if __name__ == "__main__":
    sys.exit(main())
