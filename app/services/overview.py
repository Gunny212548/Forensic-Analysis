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
from . import db, review, storage
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


def _mtime(path) -> float:
    try:
        return path.stat().st_mtime
    except OSError:
        return 0.0


def _case_facts(case_id: str) -> dict:
    """Techniques, review backlog and top entities for one ready case."""
    stamp = (_mtime(db.db_path(case_id)), _mtime(review.review_path(case_id)))
    with _lock:
        hit = _cache.get(case_id)
        if hit and hit[0] == stamp:
            return hit[1]

    techniques: dict[str, int] = {}
    con = db.connect(case_id, read_only=True)
    try:
        for tid, n in con.execute(
            "SELECT t, count(*) FROM (SELECT unnest(mitre) AS t FROM findings) GROUP BY t"
        ).fetchall():
            techniques[tid] = n
    finally:
        con.close()

    collapsed = db.collapsed_findings(case_id)
    keys = [f["key"] for f in collapsed]
    state = review.current(case_id)
    open_lvls = [f["lvl"] or 0 for f in collapsed
                 if state.get(f["key"], {}).get("status", review.UNREVIEWED) == review.UNREVIEWED]
    unreviewed = len(open_lvls)
    review_ts = [e["ts"] for e in review.log(case_id) if e.get("ts")]

    entities = []
    for role, rows in db.risk_scores(case_id, limit=5).items():
        for r in rows:
            entities.append({"entity": r["entity"], "role": role,
                             "score": r["score"], "max_lvl": r["max_lvl"]})

    facts = {"techniques": techniques, "unreviewed": unreviewed, "findings": len(keys),
             "entities": entities,
             "open_max_lvl": max(open_lvls) if open_lvls else None,
             "last_review": max(review_ts) if review_ts else None}
    with _lock:
        _cache[case_id] = (stamp, facts)
    return facts


def _ago_key(iso: str) -> str:
    return iso or ""


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
    recent = []

    for m in manifests:
        # Every listed item names its customer, so an unscoped page never
        # leaves the reader guessing whose data a line is.
        customer = m.get("company_name") or "No customer"
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

        if m.get("status") != "ready" or not db.db_path(m["case_id"]).exists():
            continue
        facts = _case_facts(m["case_id"])
        totals["unreviewed"] += facts["unreviewed"]
        totals["reviewable"] += facts["findings"]
        if facts["unreviewed"]:
            totals["cases_with_unreviewed"] += 1
        for tid, n in facts["techniques"].items():
            tech_cases[tid] += 1
            tech_findings[tid] += n
            tech_customers.setdefault(tid, set()).add(customer)
        for e in facts["entities"]:
            # Per customer: the same address in two customers' cases is two
            # different hosts, and must not add up into one row.
            k = (m.get("company_id"), e["role"], e["entity"])
            agg = entity_agg.setdefault(k, {"entity": e["entity"], "role": e["role"], "customer": customer,
                                            "cases": 0, "score": 0.0, "max_lvl": 0})
            agg["cases"] += 1
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

    used_companies = {m.get("company_id") for m in manifests if m.get("company_id")}
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
        },
        "case_severity": {k: case_sev[k] for k in ("critical", "high", "medium", "low", "none")},
        "daily": [{"date": d.isoformat(), **{k: c[k] for k in ("critical", "high", "medium", "low", "none", "pending")}}
                  for d, c in daily.items()],
        "top_entities": top_entities,
        # One technique is the same behaviour in every customer, so it stays
        # one card - naming each customer it was seen in.
        "techniques": [{"id": t, "name": TECHNIQUE_NAMES.get(t, ""), "cases": n, "findings": tech_findings[t],
                        "customers": sorted(tech_customers[t])}
                       for t, n in tech_cases.most_common(8)],
        "recent": recent[:8],
        "cases": [{k: m.get(k) for k in ("case_id", "original_filename", "company_name", "file_kind",
                                         "status", "error", "severity", "total_rows", "flagged_count",
                                         "uploaded_at", "size_bytes", "progress")}
                  for m in manifests],
    }


def lvl_bucket(lvl: int | None) -> str | None:
    """The Sigma level of a single stored weight (severity.py)."""
    return level_of(lvl)


def customers() -> dict:
    """The Customers page (FR-6.1): case load per customer.

    FR-6.1 counts a case as open while it has a finding that is not closed,
    and the finding status workflow arrives in Sprint 3. Until then the
    closest thing the system holds is the review backlog: a case is **open** while at least one of its
    findings is unreviewed, **closed** once every finding has a decision (or
    it has none), and the highest open severity is the worst unreviewed
    finding. Cases still processing or failed are neither - they count only
    towards the total. The status-based rule replaces this in IAI-79.
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
        if m.get("status") == "ready" and db.db_path(m["case_id"]).exists():
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
