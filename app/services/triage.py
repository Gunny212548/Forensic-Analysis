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
import queue
import re
import threading
from datetime import datetime, timezone

from .. import config
from . import db, llm, rule_meta, storage
from .rules import NON_PUBLIC_IPV4_RE, RULE_LABELS

log = logging.getLogger(__name__)

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


def _order(findings: list[dict]) -> list[dict]:
    """Every rule first, then round by round (specs/ai_review_coverage.md C-D3, Q102): the first
    batches cover every kind of behaviour instead of one rule's volume. Within a rule, and among
    the rules, highest level first, then the most events."""
    def rank(f):
        return (_LEVEL_ORDER.get(f.get("level"), 9), -(f.get("cnt") or 0), f["key"])

    by_rule: dict[str, list[dict]] = {}
    for f in sorted(findings, key=rank):
        by_rule.setdefault(f["rid"], []).append(f)
    rules = sorted(by_rule, key=lambda r: rank(by_rule[r][0]))
    out, i = [], 0
    while len(out) < len(findings):
        for r in rules:
            if i < len(by_rule[r]):
                out.append(by_rule[r][i])
        i += 1
    return out


def _accept(r: dict, sid: str, fs: list[str]) -> dict:
    fact_text = " ".join(fs)
    r["facts"] = {f"{sid}.f{i + 1}": t for i, t in enumerate(fs)}
    r["ungrounded"] = _ground(r, fact_text)
    # The schema's fact enum spans the batch, so a reason can cite another
    # suggestion's fact (seen on the quarter: the beacon cited S2's). Listed.
    r["cited_elsewhere"] = sorted({c for x in r.get("reasons") or [] for c in x.get("facts") or []
                                   if not c.startswith(f"{sid}.")})
    return r


async def _review_chunk(client, chunk) -> tuple[dict, dict, list[str]]:
    """One batch, so that every suggestion in it ends with advice or an error (C-D4, Q103): the
    batch, once more if it failed or left some out, then each one left on its own.
    Returns ({key: advice}, {key: error}, [batch-level error lines])."""
    items, failed, notes = {}, {}, []
    left = list(chunk)
    for attempt in ("batch", "retry", "single"):
        if not left:
            break
        groups = [left] if attempt != "single" else [[x] for x in left]
        still = []
        for g in groups:
            batch = [(sid, fs, fpl) for sid, fs, fpl, _ in g]
            try:
                reviews = await _review_batch(client, batch)
                err = None
            except Exception as exc:  # noqa: BLE001 - recorded, then retried smaller
                reviews, err = [], f"{type(exc).__name__}: {exc}"[:300]
                notes.append(f"suggestions {g[0][0]}-{g[-1][0]} ({attempt}): {err}")
            by_sid = {r.get("suggestion"): r for r in reviews}
            for sid, fs, _, f in g:
                r = by_sid.get(sid)
                if r:
                    items[f["key"]] = _accept(r, sid, fs)
                else:
                    still.append((sid, fs, _, f))
                    if attempt == "single":
                        failed[f["key"]] = err or "the model's answer left this suggestion out"
        left = still
    return items, failed, notes


async def _run(case_id: str, findings: list[dict], on_progress=None, done: dict | None = None,
               on_batch=None) -> dict:
    """Review every suggestion not in `done` (no cap - the user: every finding is reviewed by
    the AI, C-D1). `on_batch(items, failed, notes)` is called after each batch, so the advice is
    kept and shown as it arrives; `on_progress(reviewed, total, failed)` counts suggestions."""
    items = dict(done or {})
    todo = [f for f in _order(findings) if f["key"] not in items]
    con = db.connect(case_id, read_only=True)
    try:
        prepared = []
        for i, f in enumerate(todo, 1):
            fs = facts(con, f)
            prepared.append((f"S{i}", fs, rule_meta.RULE_META.get(f["rid"], {}).get("falsepositives") or [], f))
    finally:
        con.close()
    failed: dict = {}
    notes: list[str] = []
    if on_progress:
        on_progress(len(items), len(findings), 0)
    async with llm._client() as client:
        for start in range(0, len(prepared), config.TRIAGE_BATCH):
            got, bad, why = await _review_chunk(client, prepared[start:start + config.TRIAGE_BATCH])
            items.update(got)
            failed.update(bad)
            notes += why
            if on_batch and on_batch(items, failed, notes) is False:
                break   # the case was re-processed or deleted under the review
            if on_progress:
                on_progress(len(items), len(findings), len(failed))
    return {"items": items, "failed": failed, "errors": notes}


def _write(case_id: str, result: dict) -> None:
    p = path(case_id)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(result, ensure_ascii=False, indent=1), encoding="utf-8")
    tmp.replace(p)


def review_case(case_id: str, findings: list[dict], on_progress=None, again: bool = False,
                should_continue=None) -> dict:
    """Review the case's suggestions and keep the result, written after every batch. With
    `again`, only those without advice yet (a failure, a review cut short) are sent - "Review
    again" (C-D4). Never raises: a model that cannot be reached is recorded and the case stays
    usable. `should_continue()` returning False stops it between batches."""
    keep = load(case_id) if again else {}
    started = keep.get("created_at") or datetime.now(timezone.utc).isoformat()
    base = {"model": config.LLM_MODEL, "provider": config.LLM_PROVIDER, "created_at": started,
            "suggestions": len(findings)}
    if not config.TRIAGE_ENABLED:
        result = {"skipped_all": "AI review is switched off (TRIAGE_ENABLED)"}
        _write(case_id, result)
        return result
    keys = {f["key"] for f in findings}
    done = {k: v for k, v in (keep.get("items") or {}).items() if k in keys}

    def snapshot(items, failed, notes, status):
        return {**base, "status": status, "updated_at": datetime.now(timezone.utc).isoformat(),
                "reviewed": len(items), "items": items,
                "failed": {k: v for k, v in failed.items() if k not in items}, "errors": notes}

    def on_batch(items, failed, notes):
        # Checked before writing: a case deleted under the review must not get its file back.
        if should_continue and not should_continue():
            return False
        _write(case_id, snapshot(items, failed, notes, "running"))
        return True

    try:
        llm._preflight()
        out = asyncio.run(_run(case_id, findings, on_progress, done, on_batch))
        result = snapshot(out["items"], out["failed"], out["errors"], "done")
    except Exception as exc:  # noqa: BLE001
        log.warning("case %s: AI review failed", case_id, exc_info=True)
        result = {**snapshot(done, {}, [], "failed"), "error": f"{type(exc).__name__}: {exc}"[:500]}
    if should_continue is None or should_continue():
        _write(case_id, result)
    return result


# --- in the background (C-D2, Q101): the case is ready after the rules; the review runs on ------

_queue: "queue.Queue[tuple[str, bool]]" = queue.Queue()
_worker: threading.Thread | None = None
_guard = threading.Lock()


def _set(case_id: str, **fields) -> None:
    m = storage.load_manifest(case_id)
    if m is None:
        return
    storage.update_case(case_id, ai_review={**(m.get("ai_review") or {}), **fields})


def enqueue(case_id: str, again: bool = False) -> None:
    """Queue the case's AI review. A fresh review (after processing) starts from nothing - the
    old advice belonged to the old findings; `again` sends only what has no advice yet."""
    global _worker
    if not config.TRIAGE_ENABLED:
        _set(case_id, status="off", reason="AI review is switched off (TRIAGE_ENABLED)")
        return
    run = datetime.now(timezone.utc).isoformat()
    if not again:
        path(case_id).unlink(missing_ok=True)
    _set(case_id, status="queued", run=run, model=config.LLM_MODEL, error=None)
    _queue.put((case_id, run))
    with _guard:
        if _worker is None or not _worker.is_alive():
            _worker = threading.Thread(target=_work, name="ai-review", daemon=True)
            _worker.start()


def _work() -> None:
    # One review at a time: one model on this machine (specs/ai_review_coverage.md C-D5).
    while True:
        case_id, run = _queue.get()
        try:
            _review_queued(case_id, run)
        except Exception:  # noqa: BLE001 - the worker outlives any one case
            log.exception("AI review of %s failed", case_id)
            _set(case_id, status="failed", error="the review stopped on an internal error")
        finally:
            _queue.task_done()


def _review_queued(case_id: str, run: str) -> None:
    from . import case_views  # imported here: case_views imports this module

    def current() -> bool:
        m = storage.load_manifest(case_id)
        return bool(m) and m.get("status") == "ready" and (m.get("ai_review") or {}).get("run") == run

    if not current():
        return  # deleted, re-processed or queued again since
    manifest = storage.load_manifest(case_id)
    findings = case_views.findings_view(case_id, manifest, assign_ids=False)
    again = bool(load(case_id).get("items"))
    _set(case_id, status="running", total=len(findings), done=0, failed=0, started_at=datetime.now(timezone.utc).isoformat())

    def progress(done, total, failed):
        if current():
            _set(case_id, done=done, total=total, failed=failed)

    result = review_case(case_id, findings, on_progress=progress, again=again, should_continue=current)
    if current():
        _set(case_id, status="done" if result.get("status") == "done" else "failed",
             done=result.get("reviewed", 0), total=len(findings), failed=len(result.get("failed") or {}),
             error=result.get("error"), finished_at=datetime.now(timezone.utc).isoformat())


def resume() -> list[str]:
    """At startup: every case whose review was queued or running when the process stopped is
    queued again, sending only what has no advice yet."""
    out = []
    root = storage.customers_dir()
    for store in (sorted(root.iterdir()) if root.is_dir() else []):
        for mp in sorted((store / "cases").glob("case-*.json")):
            try:
                m = json.loads(mp.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            if m.get("status") == "ready" and (m.get("ai_review") or {}).get("status") in ("queued", "running"):
                enqueue(m["case_id"], again=True)
                out.append(m["case_id"])
    return out


def wait_idle(timeout: float = 60.0) -> bool:
    """Block until the queue is empty (tests)."""
    import time
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if _queue.unfinished_tasks == 0:
            return True
        time.sleep(0.05)
    return False


def state_of(case_id: str, manifest: dict, key: str, items: dict, failed: dict) -> str:
    """'done', 'pending' or 'failed' for one suggestion - what its page says when there is no advice."""
    if key in items:
        return "done"
    if key in failed:
        return "failed"
    status = (manifest.get("ai_review") or {}).get("status")
    return "pending" if status in ("queued", "running") else ("off" if status == "off" else "failed")


def assessment_of(case_id: str, key: str) -> dict | None:
    """What the AI advised for one suggestion, for the review line (Q80)."""
    data = load(case_id)
    r = (data.get("items") or {}).get(key)
    if not r:
        return None
    return {"assessment": r.get("assessment"), "suggested_decision": r.get("suggested_decision"),
            "model": data.get("model"), "reviewed_at": data.get("created_at")}
