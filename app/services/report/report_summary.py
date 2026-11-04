"""The report draft's Executive Summary and recommendations, drafted by the local model
(specs/forensic_report.md R-D10). The recommendations (section 9) came from each case's AI
narrative until 2026-11-03; that narrative read suggestions not decided and was made before the
decisions, so the user chose to drop it from the case page and draft them here, from the same
confirmed groups and under the same check.

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
from datetime import datetime, timedelta

from ... import config
from ..ai import llm
from ..detection import rule_meta

MAX_PARAGRAPHS = 6
PARAGRAPH_MAX = 600      # characters - a short paragraph an executive reads in one go
# Thai takes several tokens a word. 1,600 for the summary alone (measured: 671 used on 526
# findings); the recommendations were added to the same answer on 2026-11-03.
COMPLETION_TOKENS = 2400
MAX_RECOMMENDATIONS = 6
RECOMMENDATION_MAX = 300  # characters - one action, one or two sentences
MAX_REFS = 8              # a paragraph's citations: the model listed hundreds and ran out of tokens
# The facts handed over, in characters. The model's window is OLLAMA_NUM_CTX (16,384) tokens,
# shared with the system prompt and the answer; a 526-finding project's one-line-each facts were
# 153,085 characters and the model saw a cut-off prompt (measured 2026-11-03). Over this budget the
# rules with most findings are summed up as one line each (G<n>), largest first.
FACT_BUDGET = 24_000
# Measured on that project once summed up: 6,477 characters of facts + the system prompt were 3,305
# prompt tokens (~2.2 characters a token). Past FACT_LIMIT the facts and the answer no longer fit
# the window, so the model is not asked at all.
FACT_LIMIT = 28_000      # ~12,700 tokens + the system prompt + COMPLETION_TOKENS < 16,384

SYSTEM = """You write the Executive Summary of a digital forensics report, in Thai.

Readers: executives, the legal team and the insurer. They have no IT background. Write plain
Thai, short sentences, no jargon: say "ทดลองรหัสผ่านซ้ำ ๆ" not "password spraying", explain an
address as "หมายเลข IP" once. Keep technique ids, rule ids and field names out of the text.

You are given the investigation's question, the span of all findings (reference S) and the
findings an analyst has CONFIRMED, each with a reference F1, F2, ... in time order (or, when
there are many of one kind, one line G1, G2, ... summing them up), plus the paths the attacker
took between machines. These are facts. You restate them; you do not
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
rds01.mekong.local).

Then write 3 to 6 recommendations, in Thai, for the organisation: each one concrete action
that the confirmed findings call for (for example: change the password of an account a finding
shows was used, restrict remote sign-in to a machine a finding shows was reached), one or two
sentences, with "refs" naming the findings that call for it. Recommend only what those
findings show a need for; name an address, machine or account only if a cited finding holds it.
No product or vendor names."""


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


def _single(ref: str, g: dict, descr: int = 300) -> str:
    first, last = g.get("ts_first"), g.get("ts_last")
    return (f"{ref}: {(first or '?')[:19]} to {(last or '?')[:19]} (GMT+7) | {_title(g['rid'])} | "
            f"source {g.get('srcip') or '-'} | account {g.get('username') or '-'} | "
            f"{g.get('cnt') or 0} events" + (f" | {(g.get('descr') or '')[:descr]}" if descr else ""))


def _top(members: list[dict], field: str, n: int = 5) -> str:
    events: dict[str, int] = {}
    for g in members:
        if g.get(field):
            events[g[field]] = events.get(g[field], 0) + (g.get("cnt") or 0)
    ranked = sorted(events.items(), key=lambda kv: (-kv[1], kv[0]))
    shown = ", ".join(f"{k} ({v} events)" for k, v in ranked[:n]) or "-"
    return shown + (f" and {len(ranked) - n} more" if len(ranked) > n else "")


def _many(ref: str, rid: str, members: list[dict]) -> str:
    first = min(g["ts_first"] for g in members if g.get("ts_first"))
    last = max(g.get("ts_last") or g["ts_first"] for g in members if g.get("ts_first"))
    return (f"{ref}: {first[:19]} to {last[:19]} (GMT+7) | {_title(rid)} | {len(members)} confirmed "
            f"findings of this one kind, {sum(g.get('cnt') or 0 for g in members)} events | "
            f"sources {_top(members, 'srcip')} | accounts {_top(members, 'username')}")


def _plan(groups: list[dict]) -> tuple[set[str], int]:
    """Which rules are summed up (G lines) and how long a single finding's description may be,
    so that the facts fit FACT_BUDGET. Largest rule first; descriptions dropped last."""
    counts: dict[str, int] = {}
    for g in groups:
        counts[g["rid"]] = counts.get(g["rid"], 0) + 1
    order = sorted((r for r, c in counts.items() if c > 1), key=lambda r: (-counts[r], r))

    def size(summed: set[str], descr: int) -> int:
        n = sum(len(_single("F000", g, descr)) for g in groups if g["rid"] not in summed)
        return n + 400 * len(summed)       # a G line is ~300 characters
    summed: set[str] = set()
    for rid in [None, *order]:
        if rid:
            summed.add(rid)
        if size(summed, 300) <= FACT_BUDGET:
            return summed, 300
    return summed, 0


def facts(question: str | None, groups: list[dict], edges: list[dict]) -> tuple[str, dict]:
    """The prompt's facts and, per reference, the strings a paragraph citing it may name.

    A finding is one line F<n> - n its place in time order, the number section 7 gives it -
    unless the facts would not fit the model's window (FACT_BUDGET): then the rules with most
    findings are one line each, G<n>, naming how many findings, their span and their busiest
    sources and accounts. A paragraph citing G<n> may name any source or account of its
    findings. known["labels"] says what a G reference stands for in the draft."""
    lines = [f"Question of the investigation: {question or '(none written)'}", ""]
    allowed: dict[str, dict] = {}
    labels: dict[str, str] = {}
    summed, descr = _plan(groups)
    if summed:
        lines += [f"There are {len(groups)} confirmed findings. Findings of the same kind are "
                  "summed up as one line G1, G2, ...; the others are one line each, F<n>.", ""]
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
    # No tactics: a SigmaHQ rule's tags list a dozen of them, and the model turned
    # "persistence" into a motive no finding shows ("to keep access") - measured.
    done: set[str] = set()
    for n, g in enumerate(groups, 1):
        rid = g["rid"]
        if rid in summed:
            if rid in done:
                continue
            done.add(rid)
            ref = f"G{len(done)}"
            members = [x for x in groups if x["rid"] == rid]
            lines.append(_many(ref, rid, members))
            first = min(x["ts_first"] for x in members if x.get("ts_first"))
            last = max(x.get("ts_last") or x["ts_first"] for x in members if x.get("ts_first"))
            labels[ref] = f"{rid} ทั้ง {len(members)} รายการ"
        else:
            ref, members = f"F{n}", [g]
            lines.append(_single(ref, g, descr))
            first, last = g.get("ts_first"), g.get("ts_last")
        names = {x for m in members for x in (m.get("srcip"), m.get("username")) if x}
        names |= {_short(x) for x in names}
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
    return "\n".join(lines), {"refs": allowed, "paths": paths, "labels": labels}


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
                        "refs": {"type": "array", "minItems": 1, "maxItems": MAX_REFS,
                                 "items": {"type": "string", "enum": refs}},
                    },
                    "required": ["text", "refs"],
                },
            },
            "recommendations": {
                "type": "array", "minItems": 1, "maxItems": MAX_RECOMMENDATIONS,
                "items": {
                    "type": "object",
                    "properties": {
                        "text": {"type": "string", "maxLength": RECOMMENDATION_MAX},
                        "refs": {"type": "array", "minItems": 1, "maxItems": MAX_REFS,
                                 "items": {"type": "string", "enum": refs}},
                    },
                    "required": ["text", "refs"],
                },
            },
        },
        "required": ["paragraphs", "recommendations"],
    }


_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_HOST = re.compile(r"\b[a-z][a-z-]*\d+[a-z0-9-]*\b", re.I)    # rds01, ws023, web-02
# Words that look like a machine name to _HOST but are not one (code review, 2026-11-03: "IPv4",
# "Win32", "SHA256", "x64", an FD id "FD-2026-0003" were refused as machines no finding holds).
_NOT_A_MACHINE = re.compile(r"ipv[46]|win(32|64)|sha(1|256|384|512)|md5|x(64|86)|utf-?(8|16)|aes\d+|tls\d*|"
                            r"rfc\d+|cve-[\d-]+|fd-[\d-]+|kb\d+|ntlmv?\d|smbv?\d|http\d?")
_TIME = re.compile(r"\b([01]?\d|2[0-3])[:.]([0-5]\d)\b")
# A dotted Windows / Entra account name (adm.hd) - measured: the model wrote "adm.hu".
_ACCOUNT = re.compile(r"(?<![\w.])[a-z][a-z0-9_-]*\.[a-z][a-z0-9_-]*(?![\w.])", re.I)


def _minutes(hhmm: str) -> int:
    h, m = hhmm.split(":")
    return int(h) * 60 + int(m)


def _when(ts: str | None) -> datetime | None:
    try:
        return datetime.fromisoformat((ts or "").strip()[:19].replace("T", " "))
    except ValueError:
        return None


def _within(t: str, first: str | None, last: str | None) -> bool:
    """A time of day the text names (it carries no date) falls in [first, last], a minute
    either side for rounding (02:57:54 written as 02:58). Across midnight the window wraps;
    a span of a day or more holds every time of day. Code review, 2026-11-03: comparing
    HH:MM alone refused 00:01 in 23:58-00:03 and every time but one of a G line's months."""
    a = _when(first)
    b = _when(last) or a
    if a is None:
        return False
    if b < a:
        a, b = b, a
    if b - a >= timedelta(days=1) - timedelta(minutes=2):
        return True
    lo, hi, x = (a.hour * 60 + a.minute - 1) % 1440, (b.hour * 60 + b.minute + 1) % 1440, _minutes(t)
    if a.date() == b.date() and lo <= hi:
        return lo <= x <= hi
    return x >= lo or x <= hi


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
        if re.fullmatch(r"(f|fd|g|t|ta)\d+", h) or _NOT_A_MACHINE.fullmatch(h):
            continue   # a citation, an id or a technical word, not a machine
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


# ground()'s reasons as the Thai draft states them - the reasons stay English on the project
# log and in the bench; only the document a Thai reader gets is in Thai.
_THAI = [
    (re.compile(r"cites no finding"), "ไม่ได้อ้างอิงข้อค้นพบใดเลย"),
    (re.compile(r"names the address (\S+?)(?:, which .*)?$"), "อ้างถึงหมายเลข IP {} ซึ่งไม่มีในข้อค้นพบที่อ้างอิง"),
    (re.compile(r"names the machine (\S+?)(?:, which .*)?$"),
     "อ้างถึงเครื่อง {} ซึ่งไม่มีในข้อค้นพบหรือเส้นทางการโจมตีที่อ้างอิง"),
    (re.compile(r"names the account (\S+?)(?:, which .*)?$"), "อ้างถึงบัญชี {} ซึ่งไม่มีในข้อค้นพบที่อ้างอิง"),
    (re.compile(r"names the time (\S+?)(?:, outside .*)?$"), "อ้างถึงเวลา {} ซึ่งอยู่นอกช่วงเวลาของข้อค้นพบที่อ้างอิง"),
]


def thai(problem: str) -> str:
    """One of ground()'s reasons in Thai; a reason it does not know is kept as written."""
    for pattern, text in _THAI:
        m = pattern.fullmatch(problem)
        if m:
            return text.format(*m.groups())
    return problem


class CutOff(Exception):
    """The model's answer ended before its JSON did."""


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
    usage = {"finish": finish, **(body.get("usage") or {})}
    try:
        return json.loads(content), usage
    except json.JSONDecodeError as exc:
        raise CutOff(f"the answer is not whole JSON (finish {finish}, prompt "
                     f"{usage.get('prompt_tokens')} tokens, answer {usage.get('completion_tokens')}): "
                     f"{exc}") from exc


def draft(question: str | None, groups: list[dict], edges: list[dict]) -> dict:
    """{paragraphs: [{text, refs}], warnings, recommendations: [{text, refs}],
    recommendation_warnings, error, model, seconds, usage, labels}. Never raises: a draft is
    made with or without the AI's text. A recommendation is checked as a paragraph is."""
    out = {"paragraphs": [], "warnings": [], "error": None, "model": config.LLM_MODEL,
           "seconds": None, "usage": None, "labels": {}, "recommendations": [],
           "recommendation_warnings": []}
    if not groups:
        out["error"] = "no confirmed finding to summarise"
        return out
    text, known = facts(question, groups, edges)
    out["labels"] = known["labels"]
    if len(text) > FACT_LIMIT:   # never hand the model a prompt it would see cut off
        out["error"] = (f"{len(groups)} confirmed findings of {len(known['refs'])} kinds do not fit "
                        f"the model's window ({len(text)} characters of facts)")
        return out
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
    for r in answer.get("recommendations") or []:
        problems = ground(r, known)
        if problems:
            out["recommendation_warnings"].append({"text": r.get("text"), "refs": r.get("refs"),
                                                   "problems": problems})
        else:
            out["recommendations"].append({"text": (r.get("text") or "").strip(), "refs": r.get("refs")})
    if not out["paragraphs"] and not out["error"]:
        out["error"] = "every paragraph the model wrote named something its findings do not hold"
    return out
