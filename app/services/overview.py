"""The Overview page's numbers, across every case (interim, before the
finding lifecycle).

figma-export/Overview.svg is built around open findings with a status - open
findings, MTTC, an open-findings table - and that lifecycle (Open ->
Investigating -> Contained -> Closed) does not exist until Sprint 3
(IAI-45..49). Until then this fills the same layout with what the system does
hold: cases, findings, severities, review state, ATT&CK techniques and
risk-ranked hosts. Nothing here is invented; every number traces to a
manifest, a case DuckDB or a review log. When the lifecycle lands, the
status-shaped parts replace these (IAI-65..70).

Per-case facts that need the case's DuckDB are cached on the file's mtime
(and the review log's), so the page does not reopen every database on every
refresh - only cases that changed.
"""

import threading
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

from .. import config
from . import (areas, case_views, custody, db, filestamp, finding_ids, findings_index, lifecycle, products,
               review, rule_meta, rules, storage)
from .severity import level_of

TZ = timezone(timedelta(hours=config.EVENT_TZ_OFFSET_HOURS))

# Names for the techniques the rule engine emits (rules.py). Offline on
# purpose - nothing is fetched at runtime - and an unknown id shows bare.
TECHNIQUE_NAMES = {
    "T1041": "Exfiltration Over C2 Channel",
    "T1046": "Network Service Discovery",
    "T1071": "Application Layer Protocol",
    "T1078": "Valid Accounts",
    "T1078.003": "Local Accounts",
    "T1087": "Account Discovery",
    "T1098": "Account Manipulation",
    "T1105": "Ingress Tool Transfer",
    "T1110": "Brute Force",
    "T1110.001": "Password Guessing",
    "T1110.003": "Password Spraying",
    "T1133": "External Remote Services",
    "T1595": "Active Scanning",
}

_cache: dict[str, tuple[tuple, dict]] = {}
_lock = threading.Lock()


def bucket(sev: dict | None) -> str | None:
    """Same buckets as the case list (format.js severityBucket). A case whose
    findings are all informational is "none": Sigma defines that level as
    enrichment that should never raise an alert."""
    if not sev:
        return None
    for name in ("critical", "high", "medium", "low"):
        if sev.get(name, 0) > 0:
            return name
    return "none"


def _case_facts(case_id: str) -> dict:
    """Techniques, review backlog and top entities for one ready case."""
    # The id registry is in the stamp: "findings created per day" reads it, and
    # it changes when ids are first handed out to a case that predates them.
    company_id = storage.case_company(case_id)
    stamp = filestamp.of(db.db_path(case_id), review.review_path(case_id),
                         custody.custody_path(case_id),
                         *([finding_ids.registry_path(company_id)] if company_id else []))
    with _lock:
        hit = _cache.get(case_id)
        if hit and hit[0] == stamp:
            return hit[1]

    techniques: dict[str, int] = {}
    # The days each log source's events fall on, for the evidence coverage: a day
    # with no event of any file of that source is a gap (period.py, NIST SP 800-92 §2.3).
    coverage: dict = {}
    con = db.connect(case_id, read_only=True)
    try:
        for tid, n in con.execute(
            "SELECT t, count(*) FROM (SELECT unnest(mitre) AS t FROM findings) GROUP BY t"
        ).fetchall():
            techniques[tid] = n
        # A case processed before every row carried its product (gotcha #61) has no
        # column: its events are one source of unknown product until it is re-processed.
        has_product = con.execute("SELECT count(*) FROM duckdb_columns() WHERE table_name = 'raw_events' "
                                  "AND column_name = 'product'").fetchone()[0]
        for product, first, last, days in con.execute(
            f"SELECT {'product' if has_product else 'NULL'} AS p, min(ts), max(ts), "
            "list(DISTINCT CAST(ts AS DATE)) FROM raw_events WHERE ts IS NOT NULL GROUP BY p"
        ).fetchall():
            coverage[product] = {"first": str(first), "last": str(last),
                                 "days": sorted(d.isoformat() for d in days)}
    finally:
        con.close()

    collapsed = db.collapsed_findings(case_id)
    keys = [f["key"] for f in collapsed]
    state = review.current(case_id)
    open_lvls = [f["lvl"] or 0 for f in collapsed
                 if state.get(f["key"], {}).get("status", review.UNREVIEWED) == review.UNREVIEWED]
    unreviewed = len(open_lvls)

    # The status workflow (lifecycle.py): only high/critical findings enter it,
    # and one is open until it is Resolved. This - not the review backlog -
    # decides whether a case is open on the Customers page (FR-6.1).
    flow = lifecycle.state(case_id)
    wf_tracked, wf_open_lvls = 0, []
    for f in collapsed:
        if lifecycle.tracked(f):
            wf_tracked += 1
            if flow.get(f["key"], {}).get("status", lifecycle.OPEN) != lifecycle.RESOLVED:
                wf_open_lvls.append(f["lvl"] or 0)
    review_ts = [e["ts"] for e in review.log(case_id) if e.get("ts")]

    # Per rule, its suggestions by the analyst's decision (Top rules); per ATT&CK
    # tactic, the suggestions whose techniques reach it - one suggestion can reach
    # several tactics.
    by_rule: dict[str, Counter] = {}
    tactics: Counter = Counter()
    for f in collapsed:
        by_rule.setdefault(f["rid"], Counter())[state.get(f["key"], {}).get("status", review.UNREVIEWED)] += 1
        for t in rule_meta.tactics_of(f.get("mitre") or []):
            tactics[t] += 1

    entities = []
    ranked = db.risk_scores(case_id, limit=5)
    # An account is named with the computers it was seen on and the addresses it
    # came from (db.account_origins).
    origins = db.account_origins(case_id, [r["entity"] for r in ranked.get("accounts", [])])
    for role, rows in ranked.items():
        for r in rows:
            seen = origins.get(r["entity"], {}) if role == "accounts" else {}
            entities.append({"entity": r["entity"], "role": role,
                             "score": r["score"], "max_lvl": r["max_lvl"],
                             "hosts": seen.get("hosts", []), "sources": seen.get("sources", [])})

    # Per detection area (areas.py): findings by level - all of them, and the
    # ones still Open in the workflow - how many are not Resolved, how many the
    # analyst has not decided, and when each was first seen, for the card's trend.
    area_facts: dict = {}
    for f in collapsed:
        aid = areas.AREA_OF.get(f["rid"])
        if aid is None:
            continue
        a = area_facts.setdefault(aid, {"total": {}, "new": {}, "open": 0, "open_lv": {}, "days": {},
                                        "undecided": 0})
        c = areas.chip(f["level"])
        a["total"][c] = a["total"].get(c, 0) + 1
        if state.get(f["key"], {}).get("status", review.UNREVIEWED) == review.UNREVIEWED:
            a["undecided"] += 1
        if lifecycle.tracked(f):
            status = flow.get(f["key"], {}).get("status", lifecycle.OPEN)
            if status == lifecycle.OPEN:
                a["new"][c] = a["new"].get(c, 0) + 1
            if status != lifecycle.RESOLVED:
                a["open"] += 1
                a["open_lv"][c] = a["open_lv"].get(c, 0) + 1
        if f.get("ts_min"):
            day = str(f["ts_min"])[:10]
            a["days"][day] = a["days"].get(day, 0) + 1

    # What needs attention: a custody chain that no longer verifies, or whose last
    # integrity check failed (a later passing check clears it), and an altered
    # review log.
    custody_issue = custody.problem(case_id)
    rv = review.verify(case_id)
    review_issue = None if rv.get("intact", True) else f"decision history: {rv.get('problem')}"

    # When each workflow finding was created (registry) and mean time to contain:
    # created -> Contained, true positives only (lifecycle.summary).
    reg = finding_ids.created(case_id)
    created = []
    summ_in = []
    for f in collapsed:
        if not lifecycle.tracked(f):
            continue
        if f["key"] in reg:
            created.append((datetime.fromisoformat(reg[f["key"]]).astimezone(TZ).date().isoformat(),
                            areas.chip(f["level"])))
        st = flow.get(f["key"])
        summ_in.append({"lifecycle": {"tracked": True, "status": (st or {}).get("status", lifecycle.OPEN),
                                      "contained_at": (st or {}).get("contained_at"),
                                      "classification": (st or {}).get("classification")}})
    ms = lifecycle.summary(summ_in, custody.created_at(case_id))

    # The Overview's "awaiting review" is the workflow's backlog: a high or
    # critical finding nobody has decided on. Informational ones never ask for an
    # alert (Sigma), and counting them kept the banner up after every workflow
    # finding was Resolved.
    wf_unreviewed = sum(1 for f in collapsed if lifecycle.tracked(f)
                        and state.get(f["key"], {}).get("status", review.UNREVIEWED) == review.UNREVIEWED)

    facts = {"techniques": techniques, "unreviewed": unreviewed, "findings": len(keys),
             "wf_unreviewed": wf_unreviewed,
             "custody_issue": custody_issue, "review_issue": review_issue, "created": created,
             "mttc_total": (ms["mttc_seconds"] or 0) * ms["mttc_n"], "mttc_n": ms["mttc_n"],
             "entities": entities,
             "open_max_lvl": max(open_lvls) if open_lvls else None,
             "wf_tracked": wf_tracked, "wf_open": len(wf_open_lvls), "areas": area_facts,
             "wf_open_max_lvl": max(wf_open_lvls) if wf_open_lvls else None,
             "last_review": max(review_ts) if review_ts else None,
             "rules": by_rule, "tactics": tactics, "coverage": coverage}
    with _lock:
        _cache[case_id] = (stamp, facts)
    return facts


def _ago_key(iso: str) -> str:
    return iso or ""


def attention_reason(mapping: dict | None) -> str | None:
    """Why a file's reading needs the analyst's attention, or None - the same test
    as the Ingest step's Files read (Mapping.jsx needsAttention); change both."""
    if not mapping:
        return None
    method = mapping.get("method")
    if method == "no_reader":
        return "no reader - kept, not analysed"
    if method == "unrecognised":
        return "not recognised - not analysed"
    if method != "documented" and not mapping.get("line_profiles"):
        return "columns guessed"
    if mapping.get("heuristic_fields"):
        return "columns guessed"
    if mapping.get("missing_fields"):
        return "documented columns missing"
    j = mapping.get("json") or {}
    if j.get("unparseable") or j.get("broken_at_byte") is not None:
        return "JSON not read whole"
    w = mapping.get("windows") or {}
    if w.get("unreadable") or w.get("unreadable_chunks") or w.get("reader_errors") or w.get("unmatched_messages"):
        return "Windows records not read"
    if (mapping.get("syslog") or {}).get("year_inferred"):
        return "year inferred"
    c = mapping.get("coverage") or {}
    if (c.get("not_loaded") or 0) > 0:
        return "rows not loaded"
    if (c.get("time_unparsed") or 0) > 0:
        return "time unreadable"
    return None


def _coverage_row(company_id, customer, product, agg) -> dict:
    """One customer's one log source: its files, first and last event, and the days
    between them with no event of that source (the gaps, longest first)."""
    days = sorted(agg["days"])
    first, last = datetime.fromisoformat(days[0]).date(), datetime.fromisoformat(days[-1]).date()
    gaps = []
    for a, b in zip(days, days[1:]):
        d0, d1 = datetime.fromisoformat(a).date(), datetime.fromisoformat(b).date()
        if (d1 - d0).days > 1:
            gaps.append({"from": (d0 + timedelta(days=1)).isoformat(),
                         "to": (d1 - timedelta(days=1)).isoformat(), "days": (d1 - d0).days - 1})
    gaps.sort(key=lambda g: (-g["days"], g["from"]))
    return {"company_id": company_id, "customer": customer, "product": product,
            "product_name": products.PRODUCTS.get(product, {}).get("name") or product or "Other",
            "files": agg["files"], "cases": len(agg["cases"]),
            "first": agg["first"], "last": agg["last"],
            "span_days": (last - first).days + 1, "days": len(days),
            "gap_days": sum(g["days"] for g in gaps), "longest_gap": gaps[0] if gaps else None}


def build(company_id: str | None = None) -> dict:
    """The Overview page - of one customer when `company_id` is given (each
    read from that customer's own store), otherwise of all of them."""
    manifests = storage.list_manifests(company_id)
    all_companies = storage.list_companies()
    companies = [c for c in all_companies if company_id in (None, c["company_id"])]
    now = datetime.now(TZ)
    today = now.date()

    totals = Counter()
    case_sev = Counter()
    daily = {today - timedelta(days=i): Counter() for i in range(13, -1, -1)}
    tech_cases: Counter = Counter()
    tech_findings: Counter = Counter()
    tech_customers: dict[str, set] = {}
    entity_agg: dict[tuple, dict] = {}
    area_agg = {aid: {"total": Counter(), "new": Counter(), "open": 0, "open_lv": Counter(),
                      "days": Counter(), "undecided": 0, "cases": Counter()}
                for aid in areas.AREA_IDS}
    created_days: Counter = Counter()      # (date, level) -> workflow findings created
    mttc_total, mttc_n = 0.0, 0
    attention: list[dict] = []             # cases with a custody / audit-log problem
    review_case = None                     # the case with the most workflow findings awaiting review
    failed_case = None                     # the newest failed case, for the banner's link
    urgent_rows: list[dict] = []           # workflow findings the analyst has not decided
    open_cases = 0
    recent = []
    # Each customer's own figures, counted as the page's totals count them (the
    # user, 2026-10-28: unscoped, the page must say what each customer holds).
    # Every customer is listed, one with no case too; cases from before FR-2.1
    # made a customer mandatory are one "No customer" row, so the rows add up.
    by_customer: dict = {}

    def customer_row(cid, name):
        return by_customer.setdefault(cid, {"company_id": cid, "name": name, "cases": 0, "ready": 0,
                                            "unreviewed": 0, "reviewable": 0, "open_cases": 0,
                                            "open_max_lvl": None, "areas": Counter()})

    for c in companies:
        customer_row(c["company_id"], c["name"])

    cov_agg: dict[tuple, dict] = {}        # (company, product) -> files, cases, first, last, days
    attention_files: list[dict] = []       # files whose reading needs the analyst's attention
    tactic_agg: Counter = Counter()
    tactic_customers: dict[str, set] = {}
    rule_agg: dict[str, dict] = {}         # rid -> decisions, customers, suggestions per case

    for m in manifests:
        # Every listed item names its customer, so an unscoped page never
        # leaves the reader guessing whose data a line is.
        customer = m.get("company_name") or "No customer"
        crow = customer_row(m.get("company_id"), customer)
        crow["cases"] += 1
        if m.get("status") == "ready":
            crow["ready"] += 1
        totals["cases"] += 1
        totals[m.get("status") or "unknown"] += 1
        sev = m.get("severity") or {}
        b = bucket(sev) if m.get("status") == "ready" else None
        if b:
            case_sev[b] += 1
        for name in ("critical", "high", "medium", "low"):
            totals[f"findings_{name}"] += sev.get(name, 0)

        up = m.get("uploaded_at")
        if up:
            try:
                d = datetime.fromisoformat(up).astimezone(TZ).date()
            except ValueError:
                d = None
            if d == today:
                totals["uploaded_today"] += 1
            if d in daily:
                daily[d][b or "pending"] += 1
            recent.append({"ts": up, "kind": "upload", "case_id": m["case_id"], "level": b,
                           "customer": customer,
                           "text": f"{m.get('original_filename')} uploaded"})

        if m.get("status") == "failed" and failed_case is None:
            failed_case = m["case_id"]
        if not case_views.holds_findings(m):
            continue
        facts = _case_facts(m["case_id"])
        totals["awaiting_review"] += facts["wf_unreviewed"]
        totals["unreviewed"] += facts["unreviewed"]
        totals["reviewable"] += facts["findings"]
        if facts["unreviewed"]:
            totals["cases_with_unreviewed"] += 1
        for tid, n in facts["techniques"].items():
            tech_cases[tid] += 1
            tech_findings[tid] += n
            tech_customers.setdefault(tid, set()).add(customer)
        mttc_total += facts["mttc_total"]
        mttc_n += facts["mttc_n"]
        for day, lvl in facts["created"]:
            created_days[(day, lvl)] += 1
        for reason in (facts["custody_issue"], facts["review_issue"]):
            if reason:
                attention.append({"case_id": m["case_id"], "file": m.get("original_filename"),
                                  "customer": customer, "reason": reason})
        if facts["wf_unreviewed"] and (review_case is None or facts["wf_unreviewed"] > review_case[1]):
            review_case = (m["case_id"], facts["wf_unreviewed"])
        # A case is open while any suggestion in it is not decided - the report
        # gate (2026-10-27; it was "while a workflow finding is not Resolved", but
        # nothing on screen moves a status since the Respond step went).
        if facts["unreviewed"]:
            open_cases += 1
        crow["unreviewed"] += facts["unreviewed"]
        crow["reviewable"] += facts["findings"]
        if facts["unreviewed"]:
            crow["open_cases"] += 1
            lvl = facts["open_max_lvl"]
            if lvl is not None and (crow["open_max_lvl"] is None or lvl > crow["open_max_lvl"]):
                crow["open_max_lvl"] = lvl
        for aid, a in facts["areas"].items():
            crow["areas"][aid] += sum(a["total"].values())

        # Evidence coverage: files per log source from the case's periods (one per file
        # or zip member, period.py), days from the events themselves.
        files_of = Counter(p.get("product") for p in m.get("periods") or [])
        for product, cov in facts["coverage"].items():
            agg = cov_agg.setdefault((m.get("company_id"), product), {
                "customer": customer, "files": 0, "cases": set(), "first": cov["first"],
                "last": cov["last"], "days": set()})
            agg["files"] += files_of.get(product, 0)
            agg["cases"].add(m["case_id"])
            agg["first"] = min(agg["first"], cov["first"])
            agg["last"] = max(agg["last"], cov["last"])
            agg["days"].update(cov["days"])
        items = m.get("members") or [{"name": m.get("original_filename"), "mapping": m.get("mapping")}]
        for item in items:
            reason = attention_reason(item.get("mapping"))
            if reason:
                attention_files.append({"case_id": m["case_id"], "customer": customer,
                                        "file": item.get("name"), "reason": reason})
        for t, n in facts["tactics"].items():
            tactic_agg[t] += n
            tactic_customers.setdefault(t, set()).add(customer)
        for rid, decisions in facts["rules"].items():
            r = rule_agg.setdefault(rid, {"decisions": Counter(), "customers": set(), "cases": Counter()})
            r["decisions"].update(decisions)
            r["customers"].add(customer)
            r["cases"][m["case_id"]] += sum(decisions.values())
        if facts["wf_unreviewed"]:
            urgent_rows += [r for r in findings_index.case_rows(m) if r["review"] == review.UNREVIEWED]
        for aid, a in facts["areas"].items():
            agg = area_agg[aid]
            agg["total"].update(a["total"])
            agg["new"].update(a["new"])
            agg["open"] += a["open"]
            agg["open_lv"].update(a["open_lv"])
            agg["days"].update(a["days"])
            agg["undecided"] += a["undecided"]
            agg["cases"][m["case_id"]] += sum(a["total"].values())
        for e in facts["entities"]:
            # Per customer: the same address in two customers' cases is two
            # different hosts, and must not add up into one row.
            k = (m.get("company_id"), e["role"], e["entity"])
            agg = entity_agg.setdefault(k, {"entity": e["entity"], "role": e["role"], "customer": customer,
                                            "cases": 0, "score": 0.0, "max_lvl": 0, "hosts": Counter(),
                                            "sources": Counter()})
            agg["cases"] += 1
            for key in ("hosts", "sources"):
                for value, n in e[key]:
                    agg[key][value] += n
            agg["score"] += e["score"] or 0
            agg["max_lvl"] = max(agg["max_lvl"], e["max_lvl"] or 0)

        for entry in review.log(m["case_id"]):
            rid = entry.get("finding_key", "").split("|")[0]
            who = entry.get("actor") or "someone"
            if entry.get("kind") == "lifecycle":
                # Status changes share the review log (lifecycle.py).
                what = (f"moved {rid} to {entry['to']}" if entry.get("to")
                        else f"assigned {rid} to {entry.get('assignee')}")
                recent.append({"ts": entry.get("ts"), "kind": "lifecycle", "case_id": m["case_id"],
                               "level": "ok" if entry.get("to") == "Resolved" else "info",
                               "customer": customer,
                               "text": f"{who} {what} in {m.get('original_filename')}"})
                continue
            recent.append({"ts": entry.get("ts"), "kind": "review", "case_id": m["case_id"],
                           "level": {"Accepted": "ok", "Rejected": "muted"}.get(entry.get("status"), "info"),
                           "customer": customer,
                           "text": f"{who} marked {rid} {entry.get('status', '').lower()}"
                                   f" in {m.get('original_filename')}"})

    recent.sort(key=lambda r: _ago_key(r["ts"]), reverse=True)
    # By accumulated risk, not by how many cases an entity appears in: ranked
    # by cases, an ordinary admin account seen logging in everywhere (lvl 3)
    # came out above the account actually being brute-forced (gotcha #16).
    top_entities = sorted(entity_agg.values(), key=lambda e: (-e["score"], -e["cases"]))[:5]
    for e in top_entities:
        e["score"] = round(e["score"], 1)
        # The computers an account was seen on and the addresses it came from, most
        # flagged events first (ties by name, so a list does not reorder between
        # loads); [] for an address.
        for key in ("hosts", "sources"):
            e[key] = [[v, n] for v, n in sorted(e[key].items(), key=lambda x: (-x[1], x[0]))]

    # One date axis for every card, so their trends can be compared: every day of
    # event time from the first finding's first event to the last, empty days as 0.
    # The whole span, not the last 30 days (2026-10-27): cut to 30, the Overview's
    # chart counted 110 where the case page's counted 526 of the same suggestions.
    seen = sorted({d for a in area_agg.values() for d in a["days"]})
    trend_days: list[str] = []
    if seen:
        first, last = datetime.fromisoformat(seen[0]).date(), datetime.fromisoformat(seen[-1]).date()
        trend_days = [(first + timedelta(days=i)).isoformat() for i in range((last - first).days + 1)]
    area_cards = []
    for a in areas.AREAS:
        agg = area_agg[a["id"]]
        trend = [agg["days"].get(d, 0) for d in trend_days]
        area_cards.append({
            "id": a["id"], "name": a["name"], "about": a["about"], "rules": list(a["rids"]),
            "open": agg["open"],
            "open_by": {c: agg["open_lv"].get(c, 0) for c in areas.CHIPS},
            "new": {c: agg["new"].get(c, 0) for c in areas.CHIPS},
            "total": {c: agg["total"].get(c, 0) for c in areas.CHIPS},
            # Every suggestion the analyst has not decided - what the case page's
            # Attack events counts - and the case holding most of the area's, which
            # the card opens (the user, 2026-10-27: the Overview must match the case).
            "undecided": agg["undecided"],
            "case_id": agg["cases"].most_common(1)[0][0] if agg["cases"] else None,
            "cases": len(agg["cases"]),
            "trend": trend,
        })
    open_findings = sum(a["open"] for a in area_cards)

    # Findings created per day (the registry's time, GMT+7) - high and critical only, the
    # ones that enter the workflow - and the last 7 days against the 7 before.
    days14 = [(today - timedelta(days=i)).isoformat() for i in range(13, -1, -1)]
    findings_daily = [{"date": d, "critical": created_days[(d, "critical")], "high": created_days[(d, "high")]}
                      for d in days14]
    last7 = sum(r["critical"] + r["high"] for r in findings_daily[7:])
    prev7 = sum(r["critical"] + r["high"] for r in findings_daily[:7])
    # Critical first, then the one that has waited longest.
    urgent_rows.sort(key=lambda r: r["detected_ts"])
    urgent_rows.sort(key=lambda r: -r["lvl"])
    critical_undecided = sum(1 for r in urgent_rows if r["level"] == "critical")
    last_upload = max((m.get("uploaded_at") for m in manifests if m.get("uploaded_at")), default=None)
    new_findings = sum(sum(a["new"].values()) for a in area_cards)

    used_companies = {m.get("company_id") for m in manifests if m.get("company_id")}
    # Worst suggestion not decided first, then the most not decided, then by name -
    # the Customers page's order; "No customer" last unless something in it waits.
    customer_rows = sorted(by_customer.values(), key=lambda r: (
        -(r["open_max_lvl"] if r["open_max_lvl"] is not None else -1),
        r["company_id"] is None, -r["unreviewed"], (r["name"] or "").lower()))
    for r in customer_rows:
        r["highest"] = level_of(r.pop("open_max_lvl"))
        # Every suggestion per area, as the area cards count them; areas in their order.
        r["areas"] = {aid: r["areas"][aid] for aid in areas.AREA_IDS if r["areas"][aid]}

    # Evidence coverage, in the By customer order; a customer with nothing read has
    # one row with no log source, so every customer is accounted for.
    coverage = []
    for r in customer_rows:
        rows = [_coverage_row(cid, agg["customer"], product, agg)
                for (cid, product), agg in cov_agg.items() if cid == r["company_id"]]
        rows.sort(key=lambda x: x["product_name"].lower())
        coverage += rows or [{"company_id": r["company_id"], "customer": r["name"], "product": None,
                              "cases": r["cases"]}]

    # Every ATT&CK Enterprise tactic in ATT&CK's order, the ones nothing reached at 0.
    tactic_cards = [{"id": t, "ta": ta, "name": name, "suggestions": tactic_agg[t],
                     "customers": sorted(tactic_customers.get(t, ()), key=str.lower)}
                    for t, ta, name in rule_meta.TACTIC_ORDER]

    # The rules that suggested most, with what the analysts decided - a rule whose
    # suggestions are mostly rejected is one to re-tune. Ties by rule id, so the list
    # does not reorder between loads.
    top_rules = []
    for rid, r in sorted(rule_agg.items(), key=lambda x: (-sum(x[1]["decisions"].values()), x[0]))[:10]:
        d = r["decisions"]
        top_rules.append({"rid": rid, "label": rules.RULE_LABELS.get(rid, rid),
                          "suggestions": sum(d.values()), "accepted": d[review.ACCEPTED],
                          "modified": d[review.MODIFIED], "rejected": d[review.REJECTED],
                          "undecided": d[review.UNREVIEWED],
                          "customers": sorted(r["customers"], key=str.lower),
                          # The case holding most of its suggestions, opened on Attack events.
                          "case_id": r["cases"].most_common(1)[0][0]})
    return {
        "generated_at": now.isoformat(),
        # What the page is scoped to, and what it can be scoped to.
        "company_id": company_id,
        "customer_options": [{"company_id": c["company_id"], "name": c["name"]} for c in all_companies],
        "totals": {
            "cases": totals["cases"], "ready": totals["ready"],
            "processing": totals["queued"] + totals["processing"], "failed": totals["failed"],
            "uploaded_today": totals["uploaded_today"],
            "customers": len(companies), "customers_with_cases": len(used_companies),
            "findings_critical": totals["findings_critical"], "findings_high": totals["findings_high"],
            "findings_medium": totals["findings_medium"], "findings_low": totals["findings_low"],
            "unreviewed": totals["unreviewed"], "reviewable": totals["reviewable"],
            "cases_with_unreviewed": totals["cases_with_unreviewed"],
            "open_findings": open_findings, "new_findings": new_findings,
            "open_cases": open_cases, "last_upload": last_upload,
            "created_last7": last7, "created_prev7": prev7,
            "mttc_seconds": (mttc_total / mttc_n) if mttc_n else None, "mttc_n": mttc_n,
            "mttc_target_hours": config.MTTC_TARGET_HOURS,
            "critical_undecided": critical_undecided,
            "failed_cases": totals["failed"],
            "awaiting_review": totals["awaiting_review"],
        },
        "failed_case": failed_case,
        "attention": attention,
        "review_case": review_case[0] if review_case else None,
        "findings_daily": findings_daily,
        "urgent": [{k: r[k] for k in ("fd", "key", "case_id", "company_name", "name", "host", "level",
                                      "status", "assignee", "detected", "log_type")}
                   for r in urgent_rows[:5]],
        "areas": area_cards,
        "trend_days": trend_days,
        "case_severity": {k: case_sev[k] for k in ("critical", "high", "medium", "low", "none")},
        "daily": [{"date": d.isoformat(), **{k: c[k] for k in ("critical", "high", "medium", "low", "none", "pending")}}
                  for d, c in daily.items()],
        "top_entities": top_entities,
        "by_customer": customer_rows,
        "coverage": coverage,
        "attention_files": attention_files,
        "tactics": tactic_cards,
        "top_rules": top_rules,
        # One technique is the same behaviour in every customer, so it stays
        # one card - naming each customer it was seen in.
        "techniques": [{"id": t, "name": TECHNIQUE_NAMES.get(t, ""), "cases": n, "findings": tech_findings[t],
                        "customers": sorted(tech_customers[t], key=str.lower)}
                       for t, n in tech_cases.most_common(8)],
        "recent": recent[:8],
        "cases": [{k: m.get(k) for k in ("case_id", "original_filename", "company_name", "project_name",
                                         "file_kind", "status", "error", "severity", "total_rows",
                                         "flagged_count", "uploaded_at", "size_bytes", "progress")}
                  for m in manifests],
    }


def lvl_bucket(lvl: int | None) -> str | None:
    """The Sigma level of a single stored weight (severity.py)."""
    return level_of(lvl)


def customers() -> dict:
    """The Customers page (FR-6.1): case load per customer.

    FR-6.1: a case is **open** while the analyst has not decided at least one
    of its suggestions, and **closed** when every one is decided - the report
    gate (2026-10-27; it used to follow the status workflow, whose buttons left
    with the Respond step). The highest open severity is the worst suggestion
    still not decided. Cases still processing or failed are neither: they count
    only towards the total.
    """
    manifests = storage.list_manifests()
    rows: dict = {}

    def row_for(cid, name):
        return rows.setdefault(cid, {"company_id": cid, "name": name, "cases": 0, "open": 0,
                                     "closed": 0, "open_max_lvl": None, "last_activity": None})

    for c in storage.list_companies():
        row_for(c["company_id"], c["name"])["created_at"] = c.get("created_at")

    for m in manifests:
        # Cases from before FR-2.1 made a customer mandatory have none; they
        # are grouped rather than dropped, so the totals add up.
        r = row_for(m.get("company_id"), m.get("company_name") or "No customer")
        r["cases"] += 1
        stamps = [m.get("uploaded_at")]
        if case_views.holds_findings(m):
            facts = _case_facts(m["case_id"])
            if facts["unreviewed"]:
                r["open"] += 1
                lvl = facts["open_max_lvl"]
                if lvl is not None and (r["open_max_lvl"] is None or lvl > r["open_max_lvl"]):
                    r["open_max_lvl"] = lvl
            else:
                r["closed"] += 1
            stamps.append(facts["last_review"])
        # Both are UTC ISO strings with an offset, so they compare as text.
        latest = max((s for s in stamps if s), default=None)
        if latest and (r["last_activity"] is None or latest > r["last_activity"]):
            r["last_activity"] = latest

    out = []
    for r in rows.values():
        r["open_severity"] = lvl_bucket(r["open_max_lvl"])
        r["last_activity"] = r["last_activity"] or r.get("created_at")
        out.append(r)
    # Most urgent first: worst open severity, then most open cases, then name.
    # The "No customer" bucket goes last unless it has something open.
    out.sort(key=lambda r: (-(r["open_max_lvl"] if r["open_max_lvl"] is not None else -1),
                            r["company_id"] is None,
                            -r["open"], (r["name"] or "").lower()))
    return {"customers": out, "total_cases": len(manifests),
            "accounts": sum(1 for r in out if r["company_id"])}
