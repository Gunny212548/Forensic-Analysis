"""The AI's review of each suggestion, before the analyst decides (specs/ai_triage.md).

The user (2026-10-22): before the analyst accepts or rejects a suggestion, an AI
says why the finding fired and what caused it, as advice that makes the
decision easier - run automatically while the case is processed, before its
findings are shown (Q78, Q79). The analyst still decides (gotcha #54), and the
AI's assessment at that moment is kept on the review line (Q80).

How it is kept honest - the lessons of the narrative (gotchas #13, #37):
- **Facts, not rows.** Every wrong narrative measured was missing input, never
  reasoning, so the discriminating facts are computed here in SQL and handed
  over, each with an id: the rule's behaviour and its documented false
  positives (rule_meta.py), the line it crossed, the source (internal or not,
  its other findings), each destination and **how many internal hosts reach
  it** (one host to an unknown storage site vs thirteen staff to OneDrive), the
  application and domain names the log carries, bytes, time span.
- **A schema.** The model decodes inside a JSON schema whose enums are this
  batch's suggestion ids, fact ids and false-positive texts, so it cannot cite a
  fact it was not given.
- **A check.** An address in a reason that none of the suggestion's facts holds
  is listed as ungrounded and shown.

Kept in the case's analysis directory (`<case>.triage.json`), deleted with it.
A model that cannot be reached leaves the case ready, with the reason recorded.
"""

import asyncio
import json
import logging
import re
from datetime import datetime, timezone

from .. import config
from . import db, llm, rule_meta, storage
from .rules import NON_PUBLIC_IPV4_RE, RULE_LABELS

log = logging.getLogger(__name__)

MAX_SUGGESTIONS = 80   # reviewed per case, highest level first
BATCH = 5              # suggestions per model call
ASSESSMENTS = ("likely attack", "likely benign", "uncertain")
DECISIONS = ("accept", "reject", "undecided")
REJECT_REASONS = ("misinterpretation", "insufficient_evidence", "better_technique", "other", "none")
_LEVEL_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
_IPV4 = re.compile(r"(?<![\d.])\d{1,3}(?:\.\d{1,3}){3}(?![\d.])")
_INTERNAL = re.compile(NON_PUBLIC_IPV4_RE)


def path(case_id: str):
    return storage.case_dir(case_id, "analysis") / f"{case_id}.triage.json"


def load(case_id: str) -> dict:
    p = path(case_id)
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _side(ip: str | None) -> str:
    if not ip:
        return "no address"
    if not _IPV4.fullmatch(ip):
        # A Windows attempt with no address is sourced by its workstation name or host (rules_windows).
        return "an IPv6 address" if ":" in ip else "a host name, not an address"
    return "internal" if _INTERNAL.match(ip) else "external"


HISTORY = 8   # the account's other findings listed, earliest first


def _norm_account(expr: str) -> str:
    # As the Windows rules compare accounts: lower case, no DOMAIN\, no @realm.
    return f"lower(regexp_replace(split_part({expr}, '@', 1), '^.*\\\\', ''))"


def _field_sql(name: str) -> str:
    # A Log Exporter field of the record in `raw` (checkpoint_le.py); '' elsewhere.
    return f"nullif(regexp_extract(raw, '{name}:\"+([^\";]*)', 1), '')"


def facts(con, f: dict) -> list[str]:
    """The facts of one suggestion (a collapsed finding: rid, srcip, username)."""
    rid, src, user = f["rid"], f.get("srcip"), f.get("username")
    meta = rule_meta.RULE_META.get(rid, {})
    k_src, k_user = db.entity_sql(con)
    where = f"f.rid = ? AND {k_src} IS NOT DISTINCT FROM ? AND {k_user} IS NOT DISTINCT FROM ?"
    args = [rid, src, user]
    out = [
        f"Rule {rid} ({RULE_LABELS.get(rid, rid)}): {meta.get('ads', {}).get('goal', '')} "
        f"ATT&CK: {', '.join(f.get('mitre') or []) or 'none'}. Level {f.get('level')}.",
        "Documented false positives of this rule: "
        + ("; ".join(meta.get("falsepositives") or []) or "none listed") + ".",
        f"Finding text: {f.get('descr') or ''}",
    ]
    n, first, last, verdicts, users = con.execute(f"""
        SELECT count(*), min(r.ts), max(r.ts),
               string_agg(DISTINCT coalesce(r.verdict, 'no verdict'), ', '),
               string_agg(DISTINCT r.username, ', ')
        FROM findings f JOIN raw_events r USING (row_id) WHERE {where}""", args).fetchone()
    out.append(f"Source {src or '(none)'} is {_side(src)}"
               + (f", account {user!r}" if user else "")
               + f"; {n} events from {first} to {last} (GMT+7); verdicts: {verdicts}.")
    for dst, cnt, others, apps, domains, sent in con.execute(f"""
        WITH fr AS (SELECT r.* FROM findings f JOIN raw_events r USING (row_id) WHERE {where})
        SELECT fr.dstip, count(*),
               (SELECT count(DISTINCT e.srcip) FROM raw_events e
                 WHERE e.dstip = fr.dstip AND regexp_matches(coalesce(e.srcip, ''), '{NON_PUBLIC_IPV4_RE}')),
               string_agg(DISTINCT coalesce({_field_sql('appi_name')}, app), ', '),
               string_agg(DISTINCT {_field_sql('destination_domain_name')}, ', '),
               sum(bytes_sent)
        FROM fr WHERE fr.dstip IS NOT NULL GROUP BY fr.dstip ORDER BY count(*) DESC, fr.dstip LIMIT 3""",
            args).fetchall():
        out.append(f"Destination {dst} ({_side(dst)}): {cnt} of these events; reached by {others} "
                   f"internal host(s) in the whole evidence"
                   + (f"; application {apps}" if apps else "")
                   + (f"; domain {domains}" if domains else "")
                   + (f"; {int(sent):,} bytes sent" if sent else "") + ".")
    other = con.execute(f"""
        SELECT f.rid, count(*) FROM findings f JOIN raw_events r USING (row_id)
        WHERE {k_src} IS NOT DISTINCT FROM ? AND f.rid <> ? AND ? IS NOT NULL
        GROUP BY f.rid ORDER BY 2 DESC, 1""", [src, rid, src]).fetchall()
    out.append("Other findings of this source: "
               + (", ".join(f"{r} ({RULE_LABELS.get(r, r)}) x{c}" for r, c in other) or "none") + ".")
    # The account's history, every source (specs/finding_entities.md E-D2): a session or a dump
    # by an account that was guessed and then signed in is not an administrator's habit, and the
    # source's own findings cannot say so when the rows have no source.
    if user:
        acct = _norm_account(k_user)
        here = con.execute(f"SELECT min(r.ts) FROM findings f JOIN raw_events r USING (row_id) WHERE {where}",
                           args).fetchone()[0]
        hist = con.execute(f"""
            SELECT f.rid, {k_src} AS s, count(*), min(r.ts), max(r.ts)
            FROM findings f JOIN raw_events r USING (row_id)
            WHERE {k_user} IS NOT NULL AND {acct} = {_norm_account('?')}
              AND NOT (f.rid = ? AND {k_src} IS NOT DISTINCT FROM ? AND {k_user} IS NOT DISTINCT FROM ?)
            GROUP BY ALL ORDER BY min(r.ts), f.rid, s NULLS FIRST LIMIT {HISTORY}""",
                           [user, rid, src, user]).fetchall()
        items = []
        for r, s_, n, t0, t1 in hist:
            when = ""
            if here and t0:
                days = (here - t0).total_seconds() / 86400
                when = (f", {abs(days):.0f} days {'before' if days > 0 else 'after'} this suggestion"
                        if abs(days) >= 1 else ", the same day as this suggestion")
            items.append(f"{r} ({RULE_LABELS.get(r, r)}) from {s_ or 'no source'}, {n} events "
                         f"{str(t0)[:19]} - {str(t1)[:19]}{when}")
        out.append(f"Other findings of account {user!r}, any source, earliest first: "
                   + ("; ".join(items) or "none") + ".")
    for e in f.get("escalation") or []:
        out.append(f"Level raised: {e.get('reason', '')}")
    return out


SYSTEM = (
    "You assist a forensic analyst who must accept or reject each suggestion a detection rule "
    "made on firewall or system logs. For each suggestion, explain why the rule fired and what most "
    "likely caused it, then advise. Use only the facts given for that suggestion and cite their ids. "
    "A documented false positive matches only when the facts show it - for example many internal "
    "hosts use the destination, or the application or domain names a known service. Network "
    "scanning from the internet that the firewall refused is still an attack event to accept. "
    "When the facts cannot tell, say uncertain and what the analyst should check. Be brief and plain."
)


def _schema(batch: list[tuple[str, list[str], list[str]]]) -> dict:
    ids = [sid for sid, _, _ in batch]
    fact_ids = [f"{sid}.f{i + 1}" for sid, fs, _ in batch for i in range(len(fs))]
    fps = sorted({fp for _, _, fpl in batch for fp in fpl} | {"none"})
    item = {
        "type": "object",
        "properties": {
            "suggestion": {"type": "string", "enum": ids},
            "why_it_fired": {"type": "string"},
            "cause": {"type": "string"},
            "assessment": {"type": "string", "enum": list(ASSESSMENTS)},
            "reasons": {"type": "array", "minItems": 1, "maxItems": 4, "items": {
                "type": "object",
                "properties": {"text": {"type": "string"},
                               "facts": {"type": "array", "minItems": 1,
                                         "items": {"type": "string", "enum": fact_ids}}},
                "required": ["text", "facts"]}},
            "matches_false_positive": {"type": "string", "enum": fps},
            "suggested_decision": {"type": "string", "enum": list(DECISIONS)},
            "reject_reason": {"type": "string", "enum": list(REJECT_REASONS)},
            "check_next": {"type": "string"},
        },
        "required": ["suggestion", "why_it_fired", "cause", "assessment", "reasons",
                     "matches_false_positive", "suggested_decision", "reject_reason", "check_next"],
    }
    return {"type": "object", "properties": {"reviews": {
        "type": "array", "minItems": len(batch), "maxItems": len(batch), "items": item}},
        "required": ["reviews"]}


def _prompt(batch: list[tuple[str, list[str], list[str]]]) -> str:
    parts = []
    for sid, fs, _ in batch:
        parts.append(f"Suggestion {sid}:\n" + "\n".join(f"  {sid}.f{i + 1}: {t}" for i, t in enumerate(fs)))
    return "/no_think\nReview each suggestion below, one entry per suggestion.\n\n" + "\n\n".join(parts)


def _ground(review: dict, fact_text: str) -> list[str]:
    """Addresses the AI wrote that none of the suggestion's facts holds."""
    text = " ".join([review.get("why_it_fired", ""), review.get("cause", ""), review.get("check_next", "")]
                    + [r.get("text", "") for r in review.get("reasons") or []])
    return sorted({ip for ip in _IPV4.findall(text) if ip not in fact_text})


async def _review_batch(client, batch) -> list[dict]:
    payload = {
        "model": config.LLM_MODEL, "_schema": _schema(batch),
        "messages": [{"role": "system", "content": SYSTEM}, {"role": "user", "content": _prompt(batch)}],
        "response_format": {"type": "json_object"}, "temperature": 0.2,
        "max_tokens": config.MAX_COMPLETION_TOKENS,
    }
    body = await llm._chat(client, payload)
    content, finish = llm._content_of(body)
    out = json.loads(content).get("reviews") or []
    return out


async def _run(case_id: str, findings: list[dict], on_progress=None) -> dict:
    con = db.connect(case_id, read_only=True)
    try:
        todo = sorted(findings, key=lambda f: (_LEVEL_ORDER.get(f.get("level"), 9), -f.get("cnt", 0), f["key"]))
        todo = todo[:MAX_SUGGESTIONS]
        prepared = []
        for i, f in enumerate(todo, 1):
            fs = facts(con, f)
            prepared.append((f"S{i}", fs, rule_meta.RULE_META.get(f["rid"], {}).get("falsepositives") or [], f))
    finally:
        con.close()
    items, errors = {}, []
    # on_progress(done, total, failed batches): the case's progress shows the count (Upload page).
    if on_progress:
        on_progress(0, len(prepared), 0)
    async with llm._client() as client:
        for start in range(0, len(prepared), BATCH):
            chunk = prepared[start:start + BATCH]
            batch = [(sid, fs, fpl) for sid, fs, fpl, _ in chunk]
            try:
                reviews = await _review_batch(client, batch)
            except Exception as exc:  # noqa: BLE001 - one batch failing is recorded, not fatal
                errors.append(f"suggestions {chunk[0][0]}-{chunk[-1][0]}: {type(exc).__name__}: {exc}"[:300])
                reviews = []
            by_sid = {r.get("suggestion"): r for r in reviews}
            for sid, fs, _, f in chunk:
                r = by_sid.get(sid)
                if not r:
                    continue
                fact_text = " ".join(fs)
                r["facts"] = {f"{sid}.f{i + 1}": t for i, t in enumerate(fs)}
                r["ungrounded"] = _ground(r, fact_text)
                # The schema's fact enum spans the batch, so a reason can cite another
                # suggestion's fact (seen on the quarter: the beacon cited S2's). Listed.
                r["cited_elsewhere"] = sorted({c for x in r.get("reasons") or [] for c in x.get("facts") or []
                                               if not c.startswith(f"{sid}.")})
                items[f["key"]] = r
            if on_progress:
                on_progress(start + len(chunk), len(prepared), len(errors))
    return {"model": config.LLM_MODEL, "provider": config.LLM_PROVIDER,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "reviewed": len(items), "suggestions": len(findings),
            "skipped": max(0, len(findings) - len(todo)), "errors": errors, "items": items}


def review_case(case_id: str, findings: list[dict], on_progress=None) -> dict:
    """Review a processed case's suggestions and keep the result. Never raises:
    a model that cannot be reached is recorded and the case stays usable."""
    if not config.TRIAGE_ENABLED:
        result = {"skipped_all": "AI review is switched off (TRIAGE_ENABLED)"}
    else:
        try:
            llm._preflight()
            result = asyncio.run(_run(case_id, findings, on_progress))
        except Exception as exc:  # noqa: BLE001
            log.warning("case %s: AI review failed", case_id, exc_info=True)
            result = {"error": f"{type(exc).__name__}: {exc}"[:500],
                      "created_at": datetime.now(timezone.utc).isoformat()}
    p = path(case_id)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(result, ensure_ascii=False, indent=1), encoding="utf-8")
    tmp.replace(p)
    return result


def assessment_of(case_id: str, key: str) -> dict | None:
    """What the AI advised for one suggestion, for the review line (Q80)."""
    data = load(case_id)
    r = (data.get("items") or {}).get(key)
    if not r:
        return None
    return {"assessment": r.get("assessment"), "suggested_decision": r.get("suggested_decision"),
            "model": data.get("model"), "reviewed_at": data.get("created_at")}
