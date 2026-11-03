"""The report draft's Executive Summary, drafted by the local model (specs/forensic_report.md R-D10).

Thai prose for readers with no IT background, written from the project's **confirmed groups
only** - the same input as the attack timeline and the attack path (gotcha #10). The model
explains, it never decides (gotcha #72): it restates what the analyst confirmed and what the
evidence does not show.

Every group is handed over as one fact line with a reference `F<n>` (its place in time
order, the same number section 7 of the draft gives it - FD ids exist only for high /
critical groups, gotcha #49). The answer is decoded inside a JSON schema whose `refs` enum
holds only those references (gotcha #37), then checked: an address, a host or a time the
paragraph names must be found in the groups it cites. A paragraph that fails is left out and
named in `warnings`; the analyst sees why in the draft.
"""
from __future__ import annotations

import asyncio
import json
import re
import time

from .. import config
from . import llm, rule_meta

MAX_PARAGRAPHS = 6
PARAGRAPH_MAX = 600      # characters - a short paragraph an executive reads in one go
COMPLETION_TOKENS = 1600  # Thai takes several tokens a word; measured, see the module test

SYSTEM = """You write the Executive Summary of a digital forensics report, in Thai.

Readers: executives, the legal team and the insurer. They have no IT background. Write plain
Thai, short sentences, no jargon: say "ทดลองรหัสผ่านซ้ำ ๆ" not "password spraying", explain an
address as "หมายเลข IP" once. Keep technique ids, rule ids and field names out of the text.

You are given the investigation's question, the span of all findings (reference S) and the
findings an analyst has CONFIRMED, each with a reference F1, F2, ... in time order, plus the
paths the attacker took between machines. These are facts. You restate them; you do not
judge, grade, guess motives or name a cause no finding shows - say what was done, never why.
Never call anything "likely" or "probably" an attack - the analyst decided.

Write 3 to 5 paragraphs:
1. what happened, when it started and ended (date and time as given, Thai month names), and
   from where;
2. how the attacker moved between machines and with which account, in order;
3. what the evidence does NOT show - say plainly what cannot be concluded from these findings
   (for example whether data left the organisation, if no finding shows it).
Every paragraph lists in "refs" the findings it rests on, and only those. Name an address,
machine or time only if a cited finding holds it. Use the machine's short name (rds01, not
rds01.mekong.local)."""


def _hhmm(ts: str | None) -> str | None:
    m = re.search(r"\d{4}-\d{2}-\d{2}[ T](\d{2}):(\d{2})", ts or "")
    return f"{m.group(1)}:{m.group(2)}" if m else None


def _short(name: str | None) -> str:
    return (name or "").split(".")[0] if name and not re.fullmatch(r"[\d.]+", name) else (name or "")


def _title(rid: str) -> str:
    try:
        return rule_meta.describe(rid)["title"]
    except KeyError:
        return rid


def facts(question: str | None, groups: list[dict], edges: list[dict]) -> tuple[str, dict]:
    """The prompt's facts and, per reference, the strings a paragraph citing it may name."""
    lines = [f"Question of the investigation: {question or '(none written)'}", ""]
    allowed: dict[str, dict] = {}
    # The whole span as a fact of its own: a paragraph saying "from 02:04 to 02:58" rests on
    # it, not on the first and last finding alone (measured: a correct opening paragraph
    # citing only F1 was refused for naming the end time).
    firsts = [g["ts_first"] for g in groups if g.get("ts_first")]
    lasts = [g.get("ts_last") or g.get("ts_first") for g in groups if g.get("ts_last") or g.get("ts_first")]
    if firsts:
        lines.append(f"S: every confirmed finding together runs from {min(firsts)[:19]} to "
                     f"{max(lasts)[:19]} (GMT+7), {len(groups)} findings")
        allowed["S"] = {"names": set(), "first": min(firsts), "last": max(lasts), "text": lines[-1].lower()}
    lines += ["", "Confirmed findings:"]
    for n, g in enumerate(groups, 1):
        ref = f"F{n}"
        names = {x for x in (g.get("srcip"), g.get("username")) if x}
        names |= {_short(x) for x in names}
        first, last = g.get("ts_first"), g.get("ts_last")
        # No tactics: a SigmaHQ rule's tags list a dozen of them, and the model turned
        # "persistence" into a motive no finding shows ("to keep access") - measured.
        lines.append(
            f"{ref}: {(first or '?')[:19]} to {(last or '?')[:19]} (GMT+7) | {_title(g['rid'])} | "
            f"source {g.get('srcip') or '-'} | account {g.get('username') or '-'} | "
            f"{g.get('cnt') or 0} events | {(g.get('descr') or '')[:300]}")
        allowed[ref] = {"names": {x.lower() for x in names}, "first": first, "last": last,
                        "text": lines[-1].lower()}
    if edges:
        lines += ["", "Paths between machines (from confirmed findings):"]
        for e in edges:
            acc = ", ".join(e.get("accounts") or []) or "-"
            lines.append(f"{_short(e.get('from'))} -> {_short(e.get('to'))} | accounts {acc} | "
                         f"{e.get('count') or 0} events | rules {', '.join(e.get('rules') or [])}")
    paths = {(_short(e.get("from")).lower(), _short(e.get("to")).lower(), tuple(e.get("rules") or []))
             for e in edges}
    return "\n".join(lines), {"refs": allowed, "paths": paths}


def schema(refs: list[str]) -> dict:
    return {
        "type": "object",
        "properties": {
            "paragraphs": {
                "type": "array", "minItems": 1, "maxItems": MAX_PARAGRAPHS,
                "items": {
                    "type": "object",
                    "properties": {
                        "text": {"type": "string", "maxLength": PARAGRAPH_MAX},
                        "refs": {"type": "array", "minItems": 1,
                                 "items": {"type": "string", "enum": refs}},
                    },
                    "required": ["text", "refs"],
                },
            },
        },
        "required": ["paragraphs"],
    }


_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_HOST = re.compile(r"\b[a-z][a-z-]*\d+[a-z0-9-]*\b", re.I)    # rds01, ws023, web-02
_TIME = re.compile(r"\b([01]?\d|2[0-3])[:.]([0-5]\d)\b")
# A dotted Windows / Entra account name (adm.hd) - measured: the model wrote "adm.hu".
_ACCOUNT = re.compile(r"(?<![\w.])[a-z][a-z0-9_-]*\.[a-z][a-z0-9_-]*(?![\w.])", re.I)


def _minutes(hhmm: str) -> int:
    h, m = hhmm.split(":")
    return int(h) * 60 + int(m)


def _within(t: str, first: str | None, last: str | None) -> bool:
    """A time the text names lies in [first, last], a minute either side for rounding
    (02:57:54 written as 02:58)."""
    a, b = _hhmm(first), _hhmm(last) or _hhmm(first)
    if not a:
        return False
    lo, hi, x = _minutes(a) - 1, _minutes(b) + 1, _minutes(t)
    return lo <= x <= hi if hi >= lo else x in (lo + 1,)


def ground(paragraph: dict, known: dict) -> list[str]:
    """Why a paragraph cannot stand: something it names that its cited findings do not hold."""
    refs = [known["refs"][r] for r in paragraph.get("refs") or [] if r in known["refs"]]
    if not refs:
        return ["cites no finding"]
    text = paragraph.get("text") or ""
    problems = []
    cited_names = set().union(*(r["names"] for r in refs))
    cited_text = " ".join(r["text"] for r in refs)
    path_hosts = {h for p in known["paths"] for h in p[:2]}
    for ip in _IP.findall(text):
        if ip.lower() not in cited_names and ip.lower() not in cited_text:
            problems.append(f"names the address {ip}, which no cited finding holds")
    for host in _HOST.findall(text):
        h = host.lower()
        if h in cited_names or h in cited_text:
            continue
        if h in path_hosts:
            continue   # a machine on a confirmed path between two cited findings' ends
        if re.fullmatch(r"(f|fd|t|ta)\d+", h):
            continue   # a citation or an id, not a machine
        problems.append(f"names the machine {host}, which no cited finding or path holds")
    for acc in _ACCOUNT.findall(text):
        a = acc.lower()
        if a in cited_names or a in cited_text or a in path_hosts or _IP.fullmatch(a):
            continue
        problems.append(f"names the account {acc}, which no cited finding holds")
    # Times: an address's "10.20" is not a time - addresses out first. The span's own ends
    # (fact S) are true of the confirmed set whatever the paragraph cites.
    span = known["refs"].get("S")
    for hh, mm in _TIME.findall(_IP.sub(" ", text)):
        t = f"{int(hh):02d}:{mm}"
        if any(_within(t, r["first"], r["last"]) for r in refs):
            continue
        if span and (_within(t, span["first"], span["first"]) or _within(t, span["last"], span["last"])):
            continue
        problems.append(f"names the time {t}, outside every cited finding")
    return problems


async def _ask(prompt: str, sch: dict) -> tuple[dict, dict]:
    payload = {
        "model": config.LLM_MODEL,
        "messages": [{"role": "system", "content": SYSTEM}, {"role": "user", "content": prompt + "\n\n/no_think"}],
        "temperature": 0.2,
        "max_tokens": COMPLETION_TOKENS,
        "response_format": {"type": "json_object"},
        "_schema": sch,
    }
    async with llm._client() as client:
        body = await llm._chat(client, payload)
    content, finish = llm._content_of(body)
    return json.loads(content), {"finish": finish, **(body.get("usage") or {})}


def draft(question: str | None, groups: list[dict], edges: list[dict]) -> dict:
    """{paragraphs: [{text, refs}], warnings, error, model, seconds, usage}. Never raises:
    a draft is made with or without the AI's summary."""
    out = {"paragraphs": [], "warnings": [], "error": None, "model": config.LLM_MODEL,
           "seconds": None, "usage": None}
    if not groups:
        out["error"] = "no confirmed finding to summarise"
        return out
    text, known = facts(question, groups, edges)
    refs = list(known["refs"])
    started = time.monotonic()
    try:
        llm._preflight()
        answer, usage = asyncio.run(_ask(text, schema(refs)))
    except Exception as exc:  # the draft goes on without the summary; say why
        out["error"] = f"{type(exc).__name__}: {str(exc)[:300]}"
        out["seconds"] = round(time.monotonic() - started, 1)
        return out
    out["seconds"] = round(time.monotonic() - started, 1)
    out["usage"] = usage
    for p in answer.get("paragraphs") or []:
        problems = ground(p, known)
        if problems:
            out["warnings"].append({"text": p.get("text"), "refs": p.get("refs"), "problems": problems})
        else:
            out["paragraphs"].append({"text": (p.get("text") or "").strip(), "refs": p.get("refs")})
    if not out["paragraphs"] and not out["error"]:
        out["error"] = "every paragraph the model wrote named something its findings do not hold"
    return out
