"""Narrative analysis over a case's decoded/ruled events, using Groq's
OpenAI-compatible Chat Completions API.

The model writes the prose - summary, attack chain, timeline,
recommendations. It does NOT draw the attack graph: that comes from
db.build_graph(), straight out of the findings table, and is attached here.
"""

import asyncio
import json
import re

import httpx

from .. import config

SYSTEM_PROMPT = """You are a SOC / digital-forensics analyst assistant.
You are given a chronological list of security events, already decoded and
rule-tagged by a lightweight detection engine, from log files uploaded for
one forensic case. Build an incident timeline and an attack chain from them.

Respond with ONLY a JSON object matching this exact schema, no prose outside it:

Emit the keys in exactly this order. The output budget is tight and will
run out: spend it front-to-back, and if you are running low it is far better
to shorten or drop later timeline entries than to leave attack_chain empty.
Never stop before "recommendations" is written.

Do NOT produce an attack graph or any nodes/edges - the attack graph is
built separately and directly from the detection data, and anything you
emit under a "graph" key is discarded. Spend the budget on the narrative.

{
  "summary": "2-3 sentence summary of what happened in this case",
  "attack_chain": [
    {
      "stage": "one of: Reconnaissance, Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Discovery, Lateral Movement, Collection, Command and Control, Exfiltration, Impact",
      "description": "what happened at this stage, referencing evidence",
      "timestamp_range": "earliest - latest timestamp for this stage",
      "confidence": "low|medium|high",
      "mitre": ["MITRE ATT&CK technique IDs for this stage - REQUIRED, infer from context if the underlying events didn't already have one"]
    }
  ],
  "recommendations": ["short actionable remediation/investigation steps"],
  "timeline": [
    {
      "timestamp": "the event's ts value, verbatim",
      "event": "short description of what happened",
      "severity": "low|medium|high|critical",
      "source_ip": "IP address if present, else null",
      "target": "user/host/asset targeted if identifiable, else null",
      "mitre": ["MITRE ATT&CK technique IDs relevant to this event, e.g. T1110.001 - REQUIRED array, use [] only if truly none apply"]
    }
  ]
}

"timeline": at most 6 entries, the most significant ones only. The full
event list is already available to the analyst in the UI - the timeline here
is a highlight reel, not a dump.

Only include attack_chain stages you have actual evidence for from the
events. If the events don't show a clear multi-stage attack, say so plainly
in the summary and keep attack_chain minimal rather than inventing stages.

BE EXTREMELY CONCISE - the output budget is roughly 900 tokens for the
ENTIRE object, so every field competes with every other one. "summary": max
2 short sentences. Every "description"/"desc" field: one short sentence,
under 15 words. "attack_chain": at most 4 stages. "recommendations": max 3
items, under 10 words each. Do not
restate the same fact in multiple fields. Prioritize filling in EVERY
required key (summary, attack_chain, recommendations, timeline) over
writing long text in any one of them - a complete-but-terse response is far
better than a detailed response that runs out of room before finishing the
JSON.

ALL top-level keys (summary, attack_chain, recommendations, timeline)
are REQUIRED, even when a list ends up empty - never omit a key. Every
timeline entry and every attack_chain stage MUST include a "mitre" array;
infer plausible technique IDs from the event's nature (a repeated failed
login is credential access / brute force, a port scan is discovery /
active scanning, etc.) rather than leaving it empty when a technique clearly
applies.

IMPORTANT about risk ranking: you may also be given "Top risk entities" -
each entity's accumulated finding severity across the whole case. Lead the
summary with the highest-ranked entities; they are where the analyst should
look first. A high score can simply mean high volume, so read it together
with the source profiles rather than as proof of malice on its own.

IMPORTANT about source profiles: alongside the events you may be given a
"Source profiles" table describing how each source IP behaved across the
WHOLE case. Use it before calling anything a compromise:
- A source with many successes, few or no failures, active on several
  different days, is the pattern of the account's own legitimate user.
  Say so plainly instead of reading it as attacker access.
- A source seen on ONE day in a short burst, one that only ever fails, or
  several sources in the same /24 succeeding minutes apart, is the
  suspicious shape - even when the individual events look ordinary.
Judge from this table, not from raw success/failure counts alone.

IMPORTANT about timestamps: the "ts" field on each event is parsed from the
ORIGINAL log line/row, i.e. when the event actually happened - not when it
was uploaded or analyzed. Pay close attention to the actual gap between
timestamps. Do NOT claim one event happened "shortly after" or "in response
to" another unless their timestamps are genuinely close (seconds to
minutes apart). If two events are hours, days, or years apart, say so
explicitly and do not imply causation between them just because they were
uploaded/analyzed together.

/no_think
"""


class AnalysisNotConfigured(Exception):
    pass


class AnalysisError(Exception):
    pass


class AnalysisRateLimited(Exception):
    """Groq refused the request on a per-minute token budget.

    qwen3.8-27b's 1000 OTPM cap is per minute across *all* requests, and the
    API reserves the full max_tokens up front - so one analysis of this size
    consumes almost the whole minute and a second one straight after it is
    rejected outright. That is a wait-and-retry condition, not a failure of
    the analysis, and the analyst needs to be told how long to wait.
    """

    def __init__(self, message: str, retry_after: float | None = None):
        super().__init__(message)
        self.retry_after = retry_after


# Retry a rate-limited call in-place only if the wait is short enough to sit
# inside the HTTP request; anything longer goes back to the analyst as a 429
# telling them when to try again.
AUTO_RETRY_MAX_WAIT = 25.0


def _retry_after_seconds(resp) -> float | None:
    header = resp.headers.get("retry-after")
    if header:
        try:
            return float(header)
        except ValueError:
            pass
    match = re.search(r"try again in ([0-9.]+)s", resp.text)
    return float(match.group(1)) if match else None


def _condense(e: dict) -> dict:
    """Map one SQL row from db.top_distinct_findings() into the compact
    shape sent to the model. Dedup/severity-selection already happened in
    SQL, so this is pure formatting."""
    out = {
        "ts": e.get("ts_first"),
        "rid": e.get("rid"),
        "lvl": e.get("lvl"),
        "desc": e.get("descr") or (e.get("raw") or "")[:150],
    }
    if e.get("srcip"):
        out["srcip"] = e["srcip"]
    if e.get("username"):
        out["user"] = e["username"]
    if e.get("mitre"):
        out["mitre"] = list(e["mitre"])
    cnt = e.get("cnt") or 1
    if cnt > 1:
        out["count"] = cnt
        if e.get("ts_last") and e.get("ts_last") != e.get("ts_first"):
            out["ts_last_seen"] = e["ts_last"]
    return out


_IP_LIKE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def _normalize_graph(graph) -> dict:
    """Expand a model-emitted graph into {nodes, edges}.

    Live analyses no longer use this - the graph is built in SQL by
    db.build_graph(). It stays for the analyses already cached on disk,
    which hold either the flat "src|dst|label|mitre" strings or, older
    still, a nodes/edges object."""
    if isinstance(graph, dict) and (graph.get("nodes") or graph.get("edges")):
        return {"nodes": graph.get("nodes", []), "edges": graph.get("edges", [])}

    edges: list[dict] = []
    nodes: dict[str, dict] = {}

    def node_for(name: str) -> str:
        name = name.strip()
        if not name:
            return ""
        if name not in nodes:
            nodes[name] = {
                "id": name,
                "label": name,
                "type": "ip" if _IP_LIKE.match(name) else "entity",
            }
        return name

    if isinstance(graph, list):
        for item in graph:
            if isinstance(item, dict):  # tolerate a stray object entry
                src, dst = str(item.get("from", "")), str(item.get("to", ""))
                label, mitre = str(item.get("label", "")), item.get("mitre") or []
            elif isinstance(item, str):
                parts = [p.strip() for p in item.split("|")]
                if len(parts) < 2:
                    continue
                src, dst = parts[0], parts[1]
                label = parts[2] if len(parts) > 2 else ""
                mitre = [m.strip() for m in parts[3].split(",")] if len(parts) > 3 and parts[3] else []
            else:
                continue

            if not src or not dst:
                continue
            edges.append({
                "from": node_for(src), "to": node_for(dst),
                "label": label, "mitre": [m for m in mitre if m],
            })

    return {"nodes": list(nodes.values()), "edges": edges}


def _salvage_json(text: str) -> dict | None:
    """Recover the complete part of a JSON object that was cut off mid-write.

    A model working under a hard output cap stops wherever the budget runs
    out, leaving unterminated strings and unclosed brackets. The schema puts
    summary/attack_chain/graph first precisely so a truncated response is
    still worth something, so rather than discarding it, rewind to the last
    point where a value had finished, close the structures that were still
    open, and parse that.

    Returns None if nothing parseable can be recovered.
    """
    start = text.find("{")
    if start < 0:
        return None
    buf = text[start:]

    # Candidate cut points: every position where a value has just completed
    # and the open-bracket stack is known. Recorded newest-last.
    cuts: list[tuple[int, list[str]]] = []
    stack: list[str] = []
    in_str = False
    escaped = False

    for i, ch in enumerate(buf):
        if in_str:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch == "{":
            stack.append("}")
        elif ch == "[":
            stack.append("]")
        elif ch in "}]":
            if stack:
                stack.pop()
            cuts.append((i + 1, list(stack)))
        elif ch == ",":
            cuts.append((i, list(stack)))  # cut before the comma

    for cut, open_stack in reversed(cuts[-60:]):
        candidate = buf[:cut] + "".join(reversed(open_stack))
        try:
            parsed = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            return parsed
    return None


def _format_profiles(profiles: list[dict]) -> str:
    """One compact line per source. Zero-valued fields are dropped so a
    firewall case doesn't carry empty auth columns, and vice versa."""
    lines = []
    for p in profiles:
        bits = [f"events={p['events']}"]
        for key, label in (("auth_ok", "ok"), ("auth_fail", "fail"),
                           ("allowed", "allow"), ("denied", "deny")):
            if p.get(key):
                bits.append(f"{label}={p[key]}")
        bits.append(f"days_active={p.get('days_active') or 0}")
        if p.get("span_days"):
            bits.append(f"span={p['span_days']}d")
        if p.get("first_seen"):
            bits.append(f"first={str(p['first_seen'])[:16]}")
        lines.append(f"  {p['srcip']}: " + " ".join(bits))
    return "\n".join(lines)


def _format_risk(risk: dict) -> str:
    lines = []
    for role, items in (risk or {}).items():
        if not items:
            continue
        entries = ", ".join(
            f"{i['entity']} (score {i['score']}, {i['findings']} findings, "
            + "/".join(i["rules"]) + ")"
            for i in items[:5]
        )
        lines.append(f"  {role}: {entries}")
    return "\n".join(lines)


def _build_prompt(
    case_id: str, events: list[dict], distinct_total: int, flagged_total: int,
    profiles: list[dict] | None = None, risk: dict | None = None,
) -> tuple[str, int, int]:
    selected = [_condense(e) for e in events]
    selected.sort(key=lambda c: str(c.get("ts") or ""))

    note = ""
    if distinct_total > len(selected):
        note = (
            f"\n\nNote: this case has {flagged_total} flagged events "
            f"({distinct_total} distinct after collapsing repeats); the "
            f"{len(selected)} highest-severity distinct ones are included "
            "below (chronological order), the rest were dropped due to size limits."
        )
    elif flagged_total > len(selected):
        note = (
            f"\n\nNote: this case has {flagged_total} flagged events, collapsed "
            f"to {len(selected)} distinct entries below (repeat counts noted "
            "via the 'count'/'ts_last_seen' fields where present)."
        )

    prompt = (
        f"Case ID: {case_id}\n"
        f"Total flagged events in this case: {flagged_total}"
        f"{note}\n\n"
        f"All times are {config.EVENT_TZ_SUFFIX} (GMT+7); every event in this "
        f"case was normalised to that zone at ingest, so they are directly "
        f"comparable. Report times as given - do not convert them.\n\n"
        f"Events (JSON array, chronological, short keys: ts=timestamp, "
        f"rid=internal rule id, lvl=severity 0-15, desc=description, "
        f"srcip, user, mitre=technique ids already tagged by the rule engine "
        f"if any, count/ts_last_seen present when this entry represents "
        f"multiple collapsed repeats):\n"
        f"{json.dumps(selected, default=str, separators=(',', ':'))}"
    )
    if profiles:
        prompt += (
            "\n\nSource profiles (behaviour of each source across the whole "
            "case, not just the events above):\n" + _format_profiles(profiles)
        )
    risk_text = _format_risk(risk) if risk else ""
    if risk_text:
        prompt += (
            "\n\nTop risk entities (accumulated finding severity across the "
            "whole case):\n" + risk_text
        )
    prompt += "\n\n/no_think"
    return prompt, len(selected), flagged_total


async def run_analysis(
    case_id: str,
    events: list[dict],
    distinct_total: int = 0,
    flagged_total: int = 0,
    graph: dict | None = None,
    profiles: list[dict] | None = None,
    risk: dict | None = None,
) -> dict:
    if config.ANALYSIS_PROVIDER != "groq":
        raise AnalysisNotConfigured(
            f"ANALYSIS_PROVIDER is set to '{config.ANALYSIS_PROVIDER}', but only 'groq' is implemented."
        )
    if not config.GROQ_API_KEY:
        raise AnalysisNotConfigured(
            "GROQ_API_KEY is not set. Add it to .env and restart the container."
        )
    if not events:
        raise AnalysisError("This case has no flagged events - nothing to analyze.")

    prompt, sent_count, total_count = _build_prompt(
        case_id, events, distinct_total, flagged_total, profiles, risk
    )

    payload = {
        "model": config.GROQ_MODEL,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ],
        "response_format": {"type": "json_object"},
        "temperature": 0.2,
        # qwen3.8-27b's ~1000 OTPM cap is the ceiling here; asking for more
        # than MAX_COMPLETION_TOKENS just buys a response that stops
        # mid-JSON. The prompt is sized to fit under it instead.
        "max_tokens": config.MAX_COMPLETION_TOKENS,
    }

    async with httpx.AsyncClient(timeout=90.0) as client:
        headers = {"Authorization": f"Bearer {config.GROQ_API_KEY}"}
        resp = await client.post(config.GROQ_API_URL, headers=headers, json=payload)

        if resp.status_code == 429:
            wait = _retry_after_seconds(resp)
            if wait is not None and wait <= AUTO_RETRY_MAX_WAIT:
                await asyncio.sleep(wait + 1.0)
                resp = await client.post(config.GROQ_API_URL, headers=headers, json=payload)

    if resp.status_code == 429:
        wait = _retry_after_seconds(resp)
        when = f" Try again in about {int(wait) + 1}s." if wait else ""
        raise AnalysisRateLimited(
            f"{config.GROQ_MODEL} is out of output tokens for this minute "
            f"(1000 OTPM cap; one analysis uses most of it).{when}",
            wait,
        )

    if resp.status_code != 200:
        raise AnalysisError(f"Groq API error {resp.status_code}: {resp.text[:500]}")

    body = json.loads(resp.content.decode("utf-8"))
    finish_reason = body.get("choices", [{}])[0].get("finish_reason")
    try:
        content = body["choices"][0]["message"]["content"]
    except (KeyError, IndexError) as exc:
        raise AnalysisError(f"Could not parse Groq response: {exc}") from exc

    salvaged = False
    try:
        result = json.loads(content)
    except json.JSONDecodeError as exc:
        # Under a tight output cap the response can stop mid-JSON
        # (finish_reason=length). The schema is ordered so the valuable keys
        # land first, so keep what did arrive rather than throwing the whole
        # analysis away.
        result = _salvage_json(content)
        if result is None:
            raise AnalysisError(
                f"Could not parse Groq response (finish_reason={finish_reason}): {exc}"
            ) from exc
        salvaged = True

    # finish_reason=length on its own is not proof of damage - the model can
    # spend its last tokens on trailing whitespace after a complete object.
    # What matters is whether a required key actually went missing.
    missing = [k for k in ("summary", "attack_chain", "recommendations",
                           "timeline") if k not in result]

    # The graph comes from the rule engine, not the model: whatever the model
    # may have emitted under this key is replaced outright.
    result["graph"] = graph if graph is not None else _normalize_graph(result.get("graph"))
    if risk:
        result["risk"] = risk
    result.setdefault("summary", "")
    result.setdefault("attack_chain", [])
    result.setdefault("timeline", [])
    result.setdefault("recommendations", [])

    result["_meta"] = {
        "provider": "groq",
        "model": config.GROQ_MODEL,
        "graph_source": "rules" if graph is not None else "model",
        "source_profiles": len(profiles or []),
        "risk_ranked": sum(len(v) for v in (risk or {}).values()),
        "events_analyzed": sent_count,
        "events_total": total_count,
        "finish_reason": finish_reason,
        "truncated": bool(missing) or salvaged,
        "missing_keys": missing,
        "salvaged": salvaged,
        "usage": body.get("usage"),
    }
    return result
