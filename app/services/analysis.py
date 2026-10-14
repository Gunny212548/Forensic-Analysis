"""Narrative analysis over a case's decoded/ruled events, using Groq's
OpenAI-compatible Chat Completions API.

The model writes the prose - summary, attack chain, timeline,
recommendations. It does NOT draw the attack graph: that comes from
db.build_graph(), straight out of the findings table, and is attached here.
"""

import asyncio
import json
import re
from typing import Callable

import httpx

from .. import config

SYSTEM_PROMPT = """You are a SOC / digital-forensics analyst assistant.
You are given a chronological list of security events, already decoded and
rule-tagged by a lightweight detection engine, from log files uploaded for
one forensic case. Build a timeline and an attack chain from them.

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
      "severity": "the sev of the event(s) described, verbatim",
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


MAP_SYSTEM_PROMPT = """You are a SOC / digital-forensics analyst assistant
working through ONE BATCH of a large forensic case.

This batch is a slice of the evidence, not the whole case. Do NOT write a case
summary, do NOT build an attack chain, do NOT recommend anything and do NOT
emit a graph - another pass does all of that from your notes. Report only what
THIS batch shows.

Respond with ONLY a JSON object matching this exact schema, no prose outside it:

Emit the keys in exactly this order - "chunk_note" FIRST. The output budget
is small and models generate keys in schema order, so the takeaway must be
written before the event list can eat the budget.

{
  "chunk_note": "1-2 sentences: what this batch shows overall",
  "notable_events": [
    {
      "ts": "the event's ts value, verbatim",
      "event": "short description of what happened",
      "sev": "the event's sev, verbatim",
      "src": "source IP if present, else null",
      "target": "user/host/asset targeted if identifiable, else null",
      "mitre": ["MITRE ATT&CK technique ids - keep the ones the rule engine already supplied"]
    }
  ]
}

This batch may mix several detection rules. When it does, "chunk_note" must
name EVERY distinct kind of activity in it, not just the most severe one -
this note is the only trace of the batch that reaches the final report.

At most 4 "notable_events" - the most significant in this batch only, and
prefer covering different rules over four variations of the same one.
Every "event" is ONE short sentence, under 12 words. Copy "ts" verbatim.
BE EXTREMELY CONCISE: the whole object must fit in about 250 tokens, so a
complete-but-terse object beats a detailed one that runs out of room.

Use the source profiles, when given, before calling anything a compromise: a
source with many successes, few failures, active across several days is the
account's own legitimate user and should be described as such.

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

# A background map-reduce job is not holding an HTTP request open, so it can
# afford to sit out a full OTPM window rather than failing the whole case for
# a wait it was always going to have to do. Still bounded: anything longer
# than this is a quota problem, not a per-minute one.
BACKGROUND_RETRY_MAX_WAIT = 90.0


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
        "sev": e.get("level"),
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


def _format_digests(digests: list[dict]) -> str:
    """Render the map phase's per-batch notes for the reduce prompt.

    Each batch was summarised from events that are NOT repeated in the reduce
    prompt's own event list, so this text is the only trace of them - it is
    written as flat lines rather than JSON because the model only has to read
    it, and lines cost fewer tokens than braces."""
    lines = []
    for d in digests:
        idx = d.get("index")
        head = f"  Batch {idx} ({d.get('events', 0)} evidence entries)"
        if d.get("error"):
            lines.append(f"{head}: [no summary - {d['error']}]")
            continue
        lines.append(f"{head}: {d.get('chunk_note') or ''}".rstrip())
        for ev in d.get("notable_events") or []:
            if not isinstance(ev, dict):
                lines.append(f"    - {ev}")
                continue
            bits = [str(ev.get("ts") or "?"), str(ev.get("event") or "")]
            if ev.get("sev"):
                bits.append(f"sev={ev['sev']}")
            if ev.get("src"):
                bits.append(f"src={ev['src']}")
            if ev.get("target"):
                bits.append(f"target={ev['target']}")
            mitre = [m for m in (ev.get("mitre") or []) if m]
            if mitre:
                bits.append(",".join(str(m) for m in mitre))
            lines.append("    - " + " | ".join(bits))
    return "\n".join(lines)


def _build_prompt(
    case_id: str, events: list[dict], distinct_total: int, flagged_total: int,
    profiles: list[dict] | None = None, risk: dict | None = None,
    digests: list[dict] | None = None, pool_size: int = 0,
    capped: bool = False, veris: str | None = None,
) -> tuple[str, int, int]:
    selected = [_condense(e) for e in events]
    selected.sort(key=lambda c: str(c.get("ts") or ""))

    note = ""
    if digests:
        note = (
            f"\n\nNote: this case has {flagged_total} flagged events "
            f"({distinct_total} distinct after collapsing repeats). It was too "
            f"large for one pass, so the {pool_size} highest-severity distinct "
            f"findings were read in {len(digests)} batches and summarised "
            f"batch by batch; those batch summaries are given below, after the "
            f"events. The event list below is the single most severe batch, "
            f"quoted in full - the other batches exist ONLY as their summaries, "
            f"so use them as evidence too and do not claim the case contains "
            f"nothing beyond the events listed."
        )
        if capped:
            note += (
                f" The case has more distinct findings than the {pool_size} "
                f"read here; the rest were dropped by severity/volume rank."
            )
    elif distinct_total > len(selected):
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
        f"rid=internal rule id, sev=Sigma level computed by the rule engine (informational/low/medium/high/critical; critical means an attack-path pattern showed the attack succeeded) - copy it, do not re-grade, desc=description, "
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
    if digests:
        prompt += (
            "\n\nBatch summaries (the rest of the evidence, already read and "
            "condensed one batch at a time; treat these as first-hand "
            "evidence):\n" + _format_digests(digests)
        )
    if veris:
        # Computed from the findings (veris.py), not inferred: the narrative
        # should use this classification, never invent a different one
        # (gotcha #13 - hand the model the fact).
        prompt += (
            "\n\nIncident classification, computed from the findings with the "
            "VERIS vocabulary (use it as given; do not reclassify):\n" + veris
        )
    prompt += "\n\n/no_think"
    return prompt, (pool_size or len(selected)), flagged_total


def _is_local() -> bool:
    """True when the narrative is written by a model we host ourselves.

    Everything in this module that sleeps, paces or raises AnalysisRateLimited
    exists for Groq's 1000 OTPM reservation. A local Ollama has no such budget
    - throttling it would only make it slower for nothing - so those paths are
    skipped rather than parameterised.
    """
    return config.LLM_PROVIDER == "ollama"


def _client() -> httpx.AsyncClient:
    return httpx.AsyncClient(timeout=config.LLM_TIMEOUT)


def _to_ollama(payload: dict) -> dict:
    """Translate one OpenAI-shaped request into Ollama's native /api/chat.

    Only the transport differs - same messages, same JSON-object mode, same
    temperature. What the native endpoint adds, and the only reason it is used,
    is options.num_ctx: without it the server truncates the prompt at 4096
    tokens and the system prompt is what disappears (see config.OLLAMA_API_URL).
    """
    body = {
        "model": payload["model"],
        "messages": payload["messages"],
        "stream": False,
        # Thinking-capable models (qwen3.5, gemma4) otherwise reason first and
        # that reasoning counts against num_predict: gemma4:12b spent all 2400
        # tokens thinking and returned empty content (finish "length"). The
        # "/no_think" line in the prompt is a Qwen convention other families
        # ignore; this is the API switch. Accepted by non-thinking models too.
        "think": False,
        "options": {
            "temperature": payload.get("temperature", 0.2),
            "num_predict": payload.get("max_tokens", config.MAX_COMPLETION_TOKENS),
            "num_ctx": config.OLLAMA_NUM_CTX,
        },
    }
    if (payload.get("response_format") or {}).get("type") == "json_object":
        body["format"] = "json"
    return body


def _from_ollama(body: dict) -> dict:
    """Map Ollama's native response back into the OpenAI shape, so
    _content_of/_meta/usage downstream stay provider-agnostic."""
    prompt_tokens = body.get("prompt_eval_count") or 0
    completion_tokens = body.get("eval_count") or 0
    done = body.get("done_reason") or "stop"
    return {
        "choices": [{
            "message": {"content": (body.get("message") or {}).get("content", "")},
            # Ollama says "length" when num_predict ran out - same meaning as
            # OpenAI's, and _meta.truncated still judges by missing keys.
            "finish_reason": "length" if done == "length" else done,
        }],
        "usage": {
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens": prompt_tokens + completion_tokens,
            "total_time": round((body.get("total_duration") or 0) / 1e9, 3),
            "num_ctx": config.OLLAMA_NUM_CTX,
        },
    }


async def _chat(client, payload: dict, auto_retry_max_wait: float = AUTO_RETRY_MAX_WAIT) -> dict:
    """One chat completion, with the per-minute-budget handling that every
    call in this module shares.

    Both providers speak the same OpenAI-compatible request/response shape, so
    the only differences are the URL, the auth header, and the fact that a
    local model cannot be rate-limited. A 429 from Groq is the OTPM
    reservation, not an error: it reserves the full max_tokens up front, so a
    second call inside the same minute is refused outright. Retry in place when
    the API says the wait is short enough, otherwise hand the wait back to the
    caller to decide - an HTTP request turns it into a 429 + Retry-After, a
    background job sleeps it off.
    """
    if _is_local():
        resp = await client.post(config.OLLAMA_API_URL, json=_to_ollama(payload))
        if resp.status_code != 200:
            raise AnalysisError(
                f"Ollama API error {resp.status_code} at {config.OLLAMA_API_URL}: "
                f"{resp.text[:500]}"
            )
        return _from_ollama(json.loads(resp.content.decode("utf-8")))

    headers = {"Authorization": f"Bearer {config.GROQ_API_KEY}"}
    resp = await client.post(config.GROQ_API_URL, headers=headers, json=payload)

    if resp.status_code == 429:
        wait = _retry_after_seconds(resp)
        if wait is not None and wait <= auto_retry_max_wait:
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

    return json.loads(resp.content.decode("utf-8"))


def _content_of(body: dict) -> tuple[str, str | None]:
    finish_reason = body.get("choices", [{}])[0].get("finish_reason")
    try:
        return body["choices"][0]["message"]["content"], finish_reason
    except (KeyError, IndexError) as exc:
        raise AnalysisError(f"Could not parse {config.LLM_PROVIDER} response: {exc}") from exc


def _preflight() -> None:
    """Only the selected provider has to be configured - running local must
    not require a Groq key, and vice versa."""
    if config.LLM_PROVIDER == "ollama":
        if not config.OLLAMA_MODEL:
            raise AnalysisNotConfigured(
                "OLLAMA_MODEL is not set. Add it to .env and restart the container."
            )
        return
    if config.LLM_PROVIDER != "groq":
        raise AnalysisNotConfigured(
            f"LLM_PROVIDER is set to '{config.LLM_PROVIDER}'; supported values are 'groq' and 'ollama'."
        )
    if not config.GROQ_API_KEY:
        raise AnalysisNotConfigured(
            "GROQ_API_KEY is not set. Add it to .env and restart the container."
        )


# Above this output budget the concision instructions written for Groq's
# ~950-token ceiling are actively wrong - they would make a model with room to
# spare stop early. Derived from the budget rather than from the provider name
# so the two stay consistent however MAX_COMPLETION_TOKENS is set.
_ROOMY_BUDGET = 1400


def _system_prompt() -> str:
    """The narrative schema prompt, with its size instructions matched to the
    output budget actually in force.

    The caps in SYSTEM_PROMPT (900 tokens, 6 timeline entries, 4 stages) are
    measurements of what fits on Groq, not properties of the schema. A local
    model given 2400 tokens can afford more, and telling it the old numbers
    just wastes the budget it was given.
    """
    prompt = SYSTEM_PROMPT
    budget = config.MAX_COMPLETION_TOKENS
    if budget >= _ROOMY_BUDGET:
        prompt = (
            prompt
            .replace("roughly 900 tokens", f"roughly {budget - 200} tokens")
            .replace('"timeline": at most 6 entries', '"timeline": at most 12 entries')
            .replace('"attack_chain": at most 4 stages', '"attack_chain": at most 6 stages')
            .replace("BE EXTREMELY CONCISE", "BE CONCISE")
        )
    return prompt


async def run_analysis(
    case_id: str,
    events: list[dict],
    distinct_total: int = 0,
    flagged_total: int = 0,
    graph: dict | None = None,
    profiles: list[dict] | None = None,
    risk: dict | None = None,
    digests: list[dict] | None = None,
    pool_size: int = 0,
    capped: bool = False,
    auto_retry_max_wait: float = AUTO_RETRY_MAX_WAIT,
    meta_extra: dict | None = None,
    veris: str | None = None,
) -> dict:
    _preflight()
    if not events:
        raise AnalysisError("This case has no flagged events - nothing to analyze.")

    prompt, sent_count, total_count = _build_prompt(
        case_id, events, distinct_total, flagged_total, profiles, risk,
        digests=digests, pool_size=pool_size, capped=capped, veris=veris,
    )

    payload = {
        "model": config.LLM_MODEL,
        "messages": [
            {"role": "system", "content": _system_prompt()},
            {"role": "user", "content": prompt},
        ],
        "response_format": {"type": "json_object"},
        "temperature": 0.2,
        # On Groq, qwen3.8-27b's ~1000 OTPM cap is the ceiling here; asking for
        # more than MAX_COMPLETION_TOKENS just buys a response that stops
        # mid-JSON. The prompt is sized to fit under it instead. A local model
        # has a bigger budget, and config resolves which one applies.
        "max_tokens": config.MAX_COMPLETION_TOKENS,
    }

    async with _client() as client:
        body = await _chat(client, payload, auto_retry_max_wait)

    content, finish_reason = _content_of(body)

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
                f"Could not parse {config.LLM_PROVIDER} response "
                f"(finish_reason={finish_reason}): {exc}"
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
        "provider": config.LLM_PROVIDER,
        "model": config.LLM_MODEL,
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
    if meta_extra:
        result["_meta"].update(meta_extra)
    return result


# --------------------------------------------------------------- map-reduce

class _OtpmPacer:
    """Spend the per-minute output-token reservation deliberately.

    Groq reserves the full max_tokens of every request against a 1000
    output-tokens-per-minute budget, so what limits a multi-call job is not
    requests per minute but reserved tokens per minute: three 300-token map
    calls fit in one minute, a 950-token reduce call does not fit beside
    anything. Sleeping out the rest of the window before a call that would
    not fit is cheaper and far more predictable than discovering it as a 429
    - which is still handled, in case this estimate is wrong.
    """

    def __init__(self, budget: int | None = None):
        self.budget = budget or config.ANALYSIS_OTPM_BUDGET
        self.window_start: float | None = None
        self.reserved = 0
        self.slept = 0.0

    async def reserve(self, tokens: int) -> None:
        if _is_local():
            return  # a model we host ourselves has no per-minute reservation
        loop = asyncio.get_running_loop()
        now = loop.time()
        if self.window_start is None or now - self.window_start >= 60.0:
            self.window_start, self.reserved = now, 0
        if self.reserved and self.reserved + tokens > self.budget:
            wait = 60.0 - (now - self.window_start) + 1.0
            if wait > 0:
                self.slept += wait
                await asyncio.sleep(wait)
            self.window_start, self.reserved = loop.time(), 0
        self.reserved += tokens

    def note_wait(self, seconds: float) -> None:
        """A 429 means the real window is behind ours; restart from now."""
        self.slept += seconds
        self.window_start, self.reserved = None, 0


# How many ranked candidates to pull before selecting the pool. Severity rank
# alone is not a sample: on the merged FortiGate case the top 75 distinct
# findings were 75 copies of ONE rule, so five batches said the same thing
# five times and the beaconing, large-transfer and threat-intel findings below
# them never reached the model at all.
POOL_CANDIDATE_FACTOR = 8


def diversify_pool(rows: list[dict], target: int) -> list[dict]:
    """Pick `target` findings that span the rules that fired, best first.

    Round-robin across rules, taking each rule's highest-ranked remaining
    finding, with rules ordered by their own best finding. Rank inside a rule
    is untouched (SQL already ordered by severity then volume), so nothing
    outranks anything it used to outrank - the only change is that one noisy
    rule can no longer fill the whole pool. Batch 1 therefore ends up holding
    the single most severe finding of each rule, which is also the batch the
    reduce call quotes verbatim.
    """
    if len(rows) <= target:
        return rows
    by_rule: dict[str, list[dict]] = {}
    for row in rows:
        by_rule.setdefault(row.get("rid") or "", []).append(row)
    # Rule order = the order their best finding appeared in the ranked input.
    order = list(by_rule)
    out: list[dict] = []
    while len(out) < target:
        took = False
        for rid in order:
            bucket = by_rule[rid]
            if not bucket:
                continue
            out.append(bucket.pop(0))
            took = True
            if len(out) >= target:
                break
        if not took:
            break
    return out


def plan_map_reduce(distinct_total: int) -> dict:
    """How many batches this case needs, and whether the pool is capped.

    Returns the plan without touching the API so the HTTP endpoint can decide
    synchronously whether this case needs the slow path at all.
    """
    per_chunk = max(1, config.MAX_EVENTS_FOR_ANALYSIS)
    pool_cap = per_chunk * max(1, config.ANALYSIS_MAP_MAX_CHUNKS)
    pool_size = min(distinct_total, pool_cap)
    chunks = max(1, -(-pool_size // per_chunk))
    return {
        "needed": pool_size > per_chunk,
        "pool_size": pool_size,
        "pool_cap": pool_cap,
        "chunks": chunks,
        "per_chunk": per_chunk,
        "capped": distinct_total > pool_cap,
        # N map calls + 1 reduce, paced against the OTPM budget.
        "calls": chunks + 1,
    }


async def _run_map_call(
    client, case_id: str, index: int, total: int, events: list[dict],
    profiles: list[dict] | None, flagged_total: int, pacer: _OtpmPacer,
    auto_retry_max_wait: float,
) -> dict:
    """Summarise one batch of evidence. Never raises for a batch-level
    failure: a case is not worth abandoning because batch 3 of 5 came back
    unparseable, and the reduce prompt says so explicitly."""
    condensed = [_condense(e) for e in events]
    condensed.sort(key=lambda c: str(c.get("ts") or ""))
    prompt = (
        f"Case ID: {case_id}\n"
        f"Batch {index} of {total} (this case has {flagged_total} flagged "
        f"events in total; you are seeing one batch of the highest-severity "
        f"distinct findings).\n\n"
        f"All times are {config.EVENT_TZ_SUFFIX} (GMT+7). Report times as "
        f"given - do not convert them.\n\n"
        f"Events (JSON array, chronological, short keys: ts=timestamp, "
        f"rid=internal rule id, sev=Sigma level computed by the rule engine (informational/low/medium/high/critical; critical means an attack-path pattern showed the attack succeeded) - copy it, do not re-grade, desc=description, srcip, "
        f"user, mitre=technique ids already tagged by the rule engine, "
        f"count/ts_last_seen present when this entry collapses repeats):\n"
        f"{json.dumps(condensed, default=str, separators=(',', ':'))}"
    )
    if profiles:
        prompt += (
            "\n\nSource profiles (behaviour of each source across the whole "
            "case, not just this batch):\n" + _format_profiles(profiles)
        )
    prompt += "\n\n/no_think"

    payload = {
        "model": config.LLM_MODEL,
        "messages": [
            {"role": "system", "content": MAP_SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ],
        "response_format": {"type": "json_object"},
        "temperature": 0.2,
        "max_tokens": config.MAP_COMPLETION_TOKENS,
    }

    digest: dict = {"index": index, "events": len(events)}
    await pacer.reserve(config.MAP_COMPLETION_TOKENS)
    try:
        body = await _chat(client, payload, auto_retry_max_wait)
    except AnalysisRateLimited as exc:
        # The pacer's window estimate was behind the API's. Sleep what the API
        # asked for and try this batch once more.
        wait = exc.retry_after or 60.0
        pacer.note_wait(wait)
        await asyncio.sleep(wait + 1.0)
        try:
            body = await _chat(client, payload, auto_retry_max_wait)
        except (AnalysisRateLimited, AnalysisError) as exc2:
            digest["error"] = str(exc2)[:200]
            return digest
    except AnalysisError as exc:
        digest["error"] = str(exc)[:200]
        return digest

    content, finish_reason = _content_of(body)
    try:
        parsed = json.loads(content)
    except json.JSONDecodeError:
        parsed = _salvage_json(content)
    if not isinstance(parsed, dict):
        digest["error"] = f"unparseable batch response (finish_reason={finish_reason})"
        return digest

    notable = parsed.get("notable_events")
    digest["notable_events"] = notable if isinstance(notable, list) else []
    digest["chunk_note"] = str(parsed.get("chunk_note") or "")[:400]
    digest["finish_reason"] = finish_reason
    digest["usage"] = body.get("usage")
    return digest


async def run_map_reduce_analysis(
    case_id: str,
    pool: list[dict],
    distinct_total: int = 0,
    flagged_total: int = 0,
    graph: dict | None = None,
    profiles: list[dict] | None = None,
    risk: dict | None = None,
    plan: dict | None = None,
    profiles_for: Callable[[list[str]], list[dict]] | None = None,
    on_progress: Callable[[str, int, int], None] | None = None,
    auto_retry_max_wait: float = AUTO_RETRY_MAX_WAIT,
    veris: str | None = None,
) -> dict:
    """Narrate a case whose evidence does not fit one call.

    Map: each batch of MAX_EVENTS_FOR_ANALYSIS findings gets one cheap call
    producing a tiny digest. Reduce: one call at the normal full budget writes
    the real schema from the most severe batch (quoted in full, exactly as the
    single-call path would) plus every batch digest, plus the same SQL-derived
    profiles and risk ranking. The graph is never asked of the model - it is
    passed straight through from db.build_graph(), per the single-call path.
    """
    _preflight()
    if not pool:
        raise AnalysisError("This case has no flagged events - nothing to analyze.")

    plan = plan or plan_map_reduce(distinct_total or len(pool))
    per_chunk = plan["per_chunk"]
    chunks = [pool[i:i + per_chunk] for i in range(0, len(pool), per_chunk)][
        : max(1, config.ANALYSIS_MAP_MAX_CHUNKS)
    ]

    pacer = _OtpmPacer()
    digests: list[dict] = []
    async with _client() as client:
        for i, chunk in enumerate(chunks, start=1):
            if on_progress:
                on_progress("map", i, len(chunks))
            chunk_profiles = profiles
            if profiles_for is not None:
                ips = list(dict.fromkeys(e["srcip"] for e in chunk if e.get("srcip")))
                chunk_profiles = profiles_for(ips)
            digests.append(await _run_map_call(
                client, case_id, i, len(chunks), chunk, chunk_profiles,
                flagged_total, pacer, auto_retry_max_wait,
            ))
        if on_progress:
            on_progress("reduce", len(chunks), len(chunks))
        # The reduce call needs the whole per-minute budget to itself.
        await pacer.reserve(config.MAX_COMPLETION_TOKENS)

    map_usage = [d.get("usage") for d in digests if d.get("usage")]
    meta_extra = {
        "mode": "map_reduce",
        "map_chunks": len(chunks),
        "map_failed_chunks": [d["index"] for d in digests if d.get("error")],
        "map_reduce_capped": bool(plan.get("capped")),
        "pool_size": len(pool),
        "groq_calls": len(chunks) + 1,
        "map_usage": {
            "prompt_tokens": sum(u.get("prompt_tokens") or 0 for u in map_usage),
            "completion_tokens": sum(u.get("completion_tokens") or 0 for u in map_usage),
        },
    }

    # The reduce call quotes the first (most severe) batch verbatim - the same
    # events the single-call path would have sent - so nothing is second-hand
    # that used to be first-hand.
    result = await run_analysis(
        case_id, chunks[0], distinct_total, flagged_total, graph=graph,
        profiles=profiles, risk=risk, digests=digests, pool_size=len(pool),
        capped=bool(plan.get("capped")), auto_retry_max_wait=auto_retry_max_wait,
        meta_extra=meta_extra, veris=veris,
    )
    result["_meta"]["map_digests"] = digests
    return result
