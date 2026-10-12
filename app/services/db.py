"""Per-case DuckDB storage.

One embedded DuckDB file per case holds everything about that case:
  raw_events  - every row/line from the source file, in a canonical schema
  findings    - what the rule engine flagged (join back via row_id)

Why DuckDB rather than flat JSON (what this replaced) or Elasticsearch:
- columnar + compressed, so a 65k-row Palo Alto CSV costs ~MBs instead of
  the ~217MB the old "one JSON blob with every raw column" approach did
- aggregations (GROUP BY srcip HAVING count(*) >= n) run in milliseconds
  over millions of rows, which is exactly what the correlation rules need
- embedded single file: no server to run, unlike an ES cluster, which would
  be heavy operational baggage for a single-analyst forensic tool
"""

import re
from pathlib import Path

import duckdb

from .. import config
from . import intel
from .rules import DENY_VERDICTS, RULE_LABELS, RULE_LEVEL
from .severity import PATTERNS, level_of

RAW_COLUMNS = [
    "row_id", "ts", "ts_raw", "srcip", "dstip", "dstport", "username",
    "program", "hostname", "action", "verdict", "app", "risk",
    "bytes_sent", "category", "raw",
]

SCHEMA = """
CREATE TABLE IF NOT EXISTS raw_events (
  row_id     BIGINT,
  ts         TIMESTAMP,   -- parsed real event time (NULL if unparseable)
  ts_raw     VARCHAR,     -- original timestamp text, always kept
  srcip      VARCHAR,
  dstip      VARCHAR,
  dstport    VARCHAR,
  username   VARCHAR,
  program    VARCHAR,     -- sshd, passwd... (line logs)
  hostname   VARCHAR,
  action     VARCHAR,     -- semantic: auth_failed, auth_success, ...
  verdict    VARCHAR,     -- firewall: allow, deny, drop, ...
  app        VARCHAR,
  risk       INTEGER,
  bytes_sent BIGINT,
  category   VARCHAR,
  raw        VARCHAR      -- original line / compact row text
);

CREATE TABLE IF NOT EXISTS findings (
  row_id BIGINT,
  rid    VARCHAR,
  lvl    INTEGER,
  descr  VARCHAR,
  mitre  VARCHAR[]
);

-- Findings raised by an attack-path pattern (severity.py). One
-- row per (finding, pattern); the base level is still rules.RULE_LEVEL[rid].
CREATE TABLE IF NOT EXISTS escalations (
  row_id  BIGINT,
  rid     VARCHAR,
  pattern VARCHAR
);
"""


def db_dir() -> Path:
    return Path(config.DATA_DIR) / "db"


def db_path(case_id: str) -> Path:
    return db_dir() / f"{case_id}.duckdb"


def connect(case_id: str, read_only: bool = False) -> duckdb.DuckDBPyConnection:
    db_dir().mkdir(parents=True, exist_ok=True)
    con = duckdb.connect(str(db_path(case_id)), read_only=read_only)
    # Set on every connection, not just the ingest one, so a zone-less
    # timestamp means the same thing wherever it is cast (config.EVENT_TZ_*).
    con.execute(f"SET TimeZone = '{config.EVENT_TZ_NAME}'")
    return con


def init(case_id: str) -> duckdb.DuckDBPyConnection:
    con = connect(case_id)
    con.execute(SCHEMA)
    # The indicator table exists from the start so the rules that join it are
    # always valid; it is filled after ingest (intel.fill) with only the
    # indicators this case's traffic can actually match.
    intel.create_table(con)
    return con


# NOTE: there is deliberately no insert_raw()/insert_findings() helper here.
# Both existed, both used con.executemany(), and nothing had called either
# since the staging-CSV rewrite - so all they did was sit in the module
# offering the one bulk-insert method this codebase benchmarked at ~300
# rows/sec (gotcha #1). Rows enter raw_events through read_csv, findings
# through INSERT ... SELECT. Keep it that way.


def counts(case_id: str) -> tuple[int, int]:
    """(total rows, distinct flagged rows)"""
    if not db_path(case_id).exists():
        return 0, 0
    con = connect(case_id, read_only=True)
    try:
        total = con.execute("SELECT count(*) FROM raw_events").fetchone()[0]
        flagged = con.execute("SELECT count(DISTINCT row_id) FROM findings").fetchone()[0]
        return total, flagged
    finally:
        con.close()


def ts_range(case_id: str) -> tuple[str, str]:
    """(earliest, latest) event time of a processed case, rendered GMT+7.

    min(ts)/max(ts), never min/max of `ts_raw`: comparing the source text as
    strings only happens to order correctly for ISO input (gotcha #21).
    Returns ("", "") when the case has no DuckDB yet or parsed no timestamp.
    """
    if not db_path(case_id).exists():
        return "", ""
    con = connect(case_id, read_only=True)
    try:
        lo, hi = con.execute("SELECT min(ts), max(ts) FROM raw_events").fetchone()
        return _fmt_ts(lo), _fmt_ts(hi)
    finally:
        con.close()


def _escalation_map(con: duckdb.DuckDBPyConnection) -> dict[tuple[str, str | None, str | None], list[str]]:
    """{(rid, srcip, username): [pattern, ...]} for findings an attack-path
    pattern raised. Empty for a case processed before the
    escalations table existed, rather than an error."""
    exists = con.execute(
        "SELECT count(*) FROM duckdb_tables() WHERE table_name = 'escalations'"
    ).fetchone()[0]
    if not exists:
        return {}
    rows = con.execute(
        """
        SELECT e.rid, r.srcip, r.username, list(DISTINCT e.pattern ORDER BY e.pattern)
        FROM escalations e
        JOIN raw_events r USING (row_id)
        GROUP BY e.rid, r.srcip, r.username
        """
    ).fetchall()
    return {(rid, src, user): list(p) for rid, src, user, p in rows}


FINDING_SELECT = """
SELECT r.row_id, r.ts, r.ts_raw, r.srcip, r.dstip, r.username, r.raw,
       f.rid, f.lvl, f.descr, f.mitre
FROM findings f
JOIN raw_events r USING (row_id)
"""


def list_findings(case_id: str, limit: int, offset: int) -> list[dict]:
    if not db_path(case_id).exists():
        return []
    con = connect(case_id, read_only=True)
    try:
        rows = con.execute(
            FINDING_SELECT + " ORDER BY f.lvl DESC, r.ts NULLS LAST, r.row_id LIMIT ? OFFSET ?",
            [limit, offset],
        ).fetchall()
        cols = ["row_id", "ts", "ts_raw", "srcip", "dstip", "username", "raw",
                "rid", "lvl", "descr", "mitre"]
        out = [dict(zip(cols, r)) for r in rows]
        for row in out:
            row["level"] = level_of(row["lvl"])
        return out
    finally:
        con.close()


def list_raw(case_id: str, limit: int, offset: int) -> list[dict]:
    if not db_path(case_id).exists():
        return []
    con = connect(case_id, read_only=True)
    try:
        rows = con.execute(
            "SELECT row_id, ts, ts_raw, srcip, dstip, username, action, verdict, raw "
            "FROM raw_events ORDER BY row_id LIMIT ? OFFSET ?",
            [limit, offset],
        ).fetchall()
        cols = ["row_id", "ts", "ts_raw", "srcip", "dstip", "username",
                "action", "verdict", "raw"]
        return [dict(zip(cols, r)) for r in rows]
    finally:
        con.close()


# A timestamp is only trustworthy if the source said what zone it was in.
# "2026-06-04T10:21:33+07:00" and "2026-06-04 10:21:33Z" do; Palo Alto's
# "04/06/2026 10:21:33" does not, and guessing wrong by an hour reorders the
# timeline (FR-1.6).
_TZ_MARKER = re.compile(r"(?:Z|UTC|GMT|[+-]\d{2}:?\d{2})\s*$", re.I)


def _fmt_ts(value) -> str:
    """Render a stored (naive, GMT+7) event time with its zone spelled out.

    Everything downstream reads these strings - the findings table in the UI
    and the events handed to the model - and neither should have to infer a
    zone. The offset is a constant because ingest made it one.
    """
    if not value:
        return ""
    return f"{value.isoformat(sep=' ')}{config.EVENT_TZ_SUFFIX}"


def _confidence(row: dict) -> tuple[str, list[str]]:
    """Deterministic confidence, following section 6 of the requirements.

    Computed here rather than asked of the model on purpose: every value has
    to be explainable in one sentence (NFR Explainability), and a model
    scoring its own output cannot be audited.
    """
    flags: list[str] = []
    ts_ok = bool(row["ts_parsed"])
    if not ts_ok:
        flags.append("no-parsed-timestamp")
    # Tested against the *source* text, never against the rendered ts: ingest
    # gives every row a GMT+7 offset, so checking the rendered value would
    # report every source as zone-confirmed. What this flag records is that
    # the source itself never said, and the GMT+7 ingest rule was assumed.
    if not _TZ_MARKER.search(str(row.get("ts_raw_first") or "")):
        flags.append("timezone-unconfirmed")

    if not ts_ok:
        return "low", flags

    # Counting distinct rule *ids* over-credits an entity: R2002 (port scan)
    # and R2003 (service sweep) are the same observation counted twice, and
    # R2005 cannot fire without R1000 already having fired. Rule families
    # (R1 auth / R2 correlation / R3 network) are closer to independent
    # evidence, which is what section 6 of the requirements is asking for.
    independent = row["entity_families"] >= 2
    supported = row["cnt"] >= 5
    if not independent:
        flags.append("single-source")
    if not supported:
        flags.append("few-events")
    if independent and supported:
        return "high", flags
    return "medium", flags


def finding_key(rid: str, srcip: str | None, username: str | None) -> str:
    return f"{rid}|{srcip or ''}|{username or ''}"


def collapsed_findings(case_id: str) -> list[dict]:
    """Findings collapsed to one entry per (rule, source, account).

    This is the unit an analyst reviews and the unit the AI is given, so both
    sides of the tool talk about the same objects - a finding the analyst
    rejected is a finding the narrative can be told to drop.
    """
    if not db_path(case_id).exists():
        return []
    con = connect(case_id, read_only=True)
    try:
        rows = con.execute(
            """
            WITH grouped AS (
                SELECT f.rid, r.srcip, r.username,
                       max(f.lvl)            AS lvl,
                       any_value(f.descr)    AS descr,
                       any_value(f.mitre)    AS mitre,
                       count(*)              AS cnt,
                       count(r.ts)           AS ts_parsed,
                       -- Chronological, from the parsed GMT+7 ts. Taking
                       -- min/max of ts_raw instead compares the source text
                       -- as *strings*, which only happens to order correctly
                       -- for ISO input: "Jun 23, 2026" and "04/06/2026" sort
                       -- alphabetically, so a Check Point or Palo Alto case
                       -- reported a time range that was not its earliest and
                       -- latest event.
                       min(r.ts)             AS ts_min,
                       max(r.ts)             AS ts_max,
                       min(coalesce(r.ts_raw, '')) AS ts_raw_first,
                       min(r.row_id)         AS sample_row_id,
                       any_value(r.raw)      AS raw
                FROM findings f
                JOIN raw_events r USING (row_id)
                GROUP BY f.rid, r.srcip, r.username
            ),
            entity_rules AS (
                SELECT coalesce(r.srcip, r.username)   AS entity,
                       count(DISTINCT f.rid)           AS n_rules,
                       count(DISTINCT substr(f.rid, 1, 2)) AS n_families
                FROM findings f
                JOIN raw_events r USING (row_id)
                WHERE coalesce(r.srcip, r.username) IS NOT NULL
                GROUP BY 1
            )
            SELECT g.*, coalesce(e.n_rules, 1) AS entity_rules,
                        coalesce(e.n_families, 1) AS entity_families
            FROM grouped g
            LEFT JOIN entity_rules e
              ON coalesce(g.srcip, g.username) = e.entity
            ORDER BY g.lvl DESC, g.cnt DESC
            """
        ).fetchall()
        escalated = _escalation_map(con)
    finally:
        con.close()

    cols = ["rid", "srcip", "username", "lvl", "descr", "mitre", "cnt",
            "ts_parsed", "ts_min", "ts_max", "ts_raw_first", "sample_row_id",
            "raw", "entity_rules", "entity_families"]
    out = []
    for r in rows:
        row = dict(zip(cols, r))
        row["mitre"] = list(row["mitre"] or [])
        # Fall back to the source text only when nothing parsed, so a row the
        # decoder could not read still shows the analyst something.
        row["ts_first"] = _fmt_ts(row["ts_min"]) or row["ts_raw_first"]
        row["ts_last"] = _fmt_ts(row["ts_max"]) or row["ts_raw_first"]
        row["key"] = finding_key(row["rid"], row["srcip"], row["username"])
        # level is what the finding is now; base_level what its rule says on
        # its own. They differ when the firewall refused it (capped) or an
        # attack-path pattern raised it - the latter named in `escalation`.
        row["level"] = level_of(row["lvl"])
        row["base_level"] = RULE_LEVEL.get(row["rid"])
        row["escalation"] = [
            {"pattern": p, "level": PATTERNS[p][0], "reason": PATTERNS[p][1]}
            for p in escalated.get((row["rid"], row["srcip"], row["username"]), [])
        ]
        confidence, flags = _confidence(row)
        row["confidence"] = confidence
        row["flags"] = flags
        out.append(row)
    return out


def top_distinct_findings(case_id: str, limit: int) -> list[dict]:
    """Collapse repeats of the same (rule, source, user) into one entry with
    a count and time range, highest severity first. This is what gets sent
    to the AI - doing it in SQL means a case with 25k findings still costs
    one fast query instead of loading every event into Python."""
    if not db_path(case_id).exists():
        return []
    con = connect(case_id, read_only=True)
    try:
        rows = con.execute(
            """
            SELECT f.rid,
                   max(f.lvl)                AS lvl,
                   any_value(f.descr)        AS descr,
                   any_value(f.mitre)        AS mitre,
                   r.srcip, r.username,
                   count(*)                  AS cnt,
                   -- Chronological and zone-stamped, for the same reason as
                   -- collapsed_findings: these strings become the model's
                   -- timeline, and it cannot order what it cannot compare.
                   min(r.ts)                 AS ts_min,
                   max(r.ts)                 AS ts_max,
                   min(coalesce(r.ts_raw, '')) AS ts_raw_first,
                   any_value(r.raw)          AS raw
            FROM findings f
            JOIN raw_events r USING (row_id)
            GROUP BY f.rid, r.srcip, r.username
            ORDER BY max(f.lvl) DESC, count(*) DESC
            LIMIT ?
            """,
            [limit],
        ).fetchall()
        cols = ["rid", "lvl", "descr", "mitre", "srcip", "username",
                "cnt", "ts_min", "ts_max", "ts_raw_first", "raw"]
        out = []
        for r in rows:
            row = dict(zip(cols, r))
            row["ts_first"] = _fmt_ts(row["ts_min"]) or row["ts_raw_first"]
            row["ts_last"] = _fmt_ts(row["ts_max"]) or row["ts_raw_first"]
            row["level"] = level_of(row["lvl"])
            out.append(row)
        return out
    finally:
        con.close()


_IP_LIKE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def build_graph(case_id: str, limit: int = 14) -> dict:
    """Build the attack graph directly from findings, in SQL.

    The graph is not interpretation - it is structure that already exists in
    the findings table: who talked to whom, under which rule, how often,
    tagged with which technique. Asking the model to re-emit it cost output
    tokens that the narrative needed, capped the edge count at whatever fit
    the budget, and let node names drift from the evidence. Derived here it
    is exact, complete, free, and every edge traces back to real rows.

    Returns the {nodes, edges} shape the frontend already renders.
    """
    if not db_path(case_id).exists():
        return {"nodes": [], "edges": []}

    con = connect(case_id, read_only=True)
    try:
        rows = con.execute(
            """
            SELECT r.srcip                          AS src,
                   coalesce(r.dstip, r.username)    AS dst,
                   f.rid,
                   max(f.lvl)                       AS lvl,
                   count(*)                         AS n,
                   any_value(f.mitre)               AS mitre
            FROM findings f
            JOIN raw_events r USING (row_id)
            WHERE r.srcip IS NOT NULL
              AND coalesce(r.dstip, r.username) IS NOT NULL
              AND r.srcip <> coalesce(r.dstip, r.username)
            GROUP BY r.srcip, coalesce(r.dstip, r.username), f.rid
            """
        ).fetchall()
    finally:
        con.close()

    # Several rules commonly fire on the same pair (a port scan is also a
    # burst of blocks); merge them into one edge rather than drawing
    # parallel lines between the same two nodes.
    pairs: dict[tuple[str, str], list[dict]] = {}
    for src, dst, rid, lvl, n, mitre in rows:
        pairs.setdefault((src, dst), []).append(
            {"rid": rid, "lvl": lvl, "n": n, "mitre": list(mitre or [])}
        )

    edges = []
    for (src, dst), hits in pairs.items():
        hits.sort(key=lambda h: (-h["lvl"], -h["n"]))
        parts = [f"{RULE_LABELS.get(h['rid'], h['rid'])} x{h['n']}" for h in hits[:2]]
        if len(hits) > 2:
            parts.append(f"+{len(hits) - 2} more")
        mitre: list[str] = []
        for h in hits:
            for m in h["mitre"]:
                if m and m not in mitre:
                    mitre.append(m)
        edges.append({
            "from": src,
            "to": dst,
            "label": " / ".join(parts),
            "mitre": mitre[:4],
            "lvl": hits[0]["lvl"],
            "level": level_of(hits[0]["lvl"]),
            "count": sum(h["n"] for h in hits),
            "rules": [h["rid"] for h in hits],
        })

    # Most severe first, so if a busy case overflows the edge budget it is
    # the informational noise that falls off, never the attack.
    edges.sort(key=lambda e: (-e["lvl"], -e["count"]))
    edges = edges[:limit]

    names: list[str] = []
    for e in edges:
        for n in (e["from"], e["to"]):
            if n not in names:
                names.append(n)
    nodes = [
        {"id": n, "label": n, "type": "ip" if _IP_LIKE.match(n) else "entity"}
        for n in names
    ]
    return {"nodes": nodes, "edges": edges}


# Roles an entity can play in a finding. Scored separately because a
# source-filtered export (see CLAUDE.md gotcha #9) has exactly one srcip -
# ranking sources there is meaningless while ranking destinations is not.
_RISK_ROLES = {"sources": "srcip", "destinations": "dstip", "accounts": "username"}


def risk_scores(case_id: str, limit: int = 8) -> dict:
    """Risk-based ranking: accumulate finding severity per entity.

    Borrowed from how modern SIEMs triage - instead of treating every rule
    hit as its own alert, sum the severity an entity attracts across all
    rules and rank by that. With 25,579 findings on one file, "which rule
    fired" is not an answer to "where do I look first"; this is.

    Returns {"sources": [...], "destinations": [...], "accounts": [...]},
    each a list of {entity, score, findings, rules, max_lvl} sorted by score.
    """
    if not db_path(case_id).exists():
        return {role: [] for role in _RISK_ROLES}

    con = connect(case_id, read_only=True)
    out: dict[str, list[dict]] = {}
    try:
        for role, column in _RISK_ROLES.items():
            # Score per rule, then sum - with the per-rule count dampened by a
            # log. A flat sum(lvl) ranks purely by volume: on the customer's
            # beaconing case it put a scanned host with three noisy rules
            # (score 79,500) above the actual C2 destination. Diminishing
            # returns on repeats, and one term per distinct rule, ranks by
            # "how many different ways is this entity implicated" instead.
            rows = con.execute(
                f"""
                WITH per_rule AS (
                    SELECT r.{column} AS entity,
                           f.rid      AS rid,
                           max(f.lvl) AS lvl,
                           count(*)   AS n
                    FROM findings f
                    JOIN raw_events r USING (row_id)
                    WHERE r.{column} IS NOT NULL AND r.{column} <> ''
                    GROUP BY r.{column}, f.rid
                )
                SELECT entity,
                       cast(round(sum(lvl * (1 + ln(n)))) AS BIGINT) AS score,
                       sum(n)               AS findings,
                       max(lvl)             AS max_lvl,
                       list(DISTINCT rid)   AS rules
                FROM per_rule
                GROUP BY entity
                ORDER BY score DESC
                LIMIT ?
                """,
                [limit],
            ).fetchall()
            out[role] = [
                {"entity": e, "score": sc, "findings": n, "max_lvl": mx,
                 "max_level": level_of(mx),
                 "rules": sorted(rl)}
                for e, sc, n, mx, rl in rows
            ]
    finally:
        con.close()
    return out


def source_profiles(case_id: str, ips: list[str], limit: int = 20) -> list[dict]:
    """Per-source behavioural profile, computed over every row of the case.

    The findings sent to the model say *what* a source did; this says how it
    behaved over time, which is what separates an account's own user from an
    intruder. Without it the model had "login success from 171.100.141.170,
    count 20" and no way to tell 20 logins spread over four working days
    (the owner) from 12 logins inside one hour (not the owner) - so it
    guessed, and guessed alarming.

    Costs one query and ~15 tokens per source in the prompt; the input side
    is not the capped resource.
    """
    if not ips or not db_path(case_id).exists():
        return []
    con = connect(case_id, read_only=True)
    try:
        placeholders = ", ".join("?" * len(ips))
        rows = con.execute(
            f"""
            SELECT srcip,
                   count(*)                                        AS events,
                   count(*) FILTER (WHERE action = 'auth_success') AS auth_ok,
                   count(*) FILTER (WHERE action = 'auth_failed')  AS auth_fail,
                   count(*) FILTER (WHERE verdict = 'allow')       AS allowed,
                   -- Shares rules.DENY_VERDICTS rather than restating it: the
                   -- hand-copied list here was missing reset-both,
                   -- reset-client, reset-server and block-url, so the deny
                   -- counts in the table handed to the model undercounted
                   -- every Palo Alto reset.
                   count(*) FILTER (WHERE verdict IN {DENY_VERDICTS}) AS denied,
                   count(DISTINCT date_trunc('day', ts))           AS days_active,
                   date_diff('day', min(ts), max(ts))              AS span_days,
                   min(ts)::VARCHAR                                AS first_seen,
                   max(ts)::VARCHAR                                AS last_seen
            FROM raw_events
            WHERE srcip IN ({placeholders})
            GROUP BY srcip
            ORDER BY count(*) DESC
            LIMIT ?
            """,
            [*ips, limit],
        ).fetchall()
        cols = ["srcip", "events", "auth_ok", "auth_fail", "allowed", "denied",
                "days_active", "span_days", "first_seen", "last_seen"]
        return [dict(zip(cols, r)) for r in rows]
    finally:
        con.close()


def distinct_finding_count(case_id: str) -> int:
    if not db_path(case_id).exists():
        return 0
    con = connect(case_id, read_only=True)
    try:
        return con.execute(
            "SELECT count(*) FROM (SELECT 1 FROM findings f JOIN raw_events r USING (row_id) "
            "GROUP BY f.rid, r.srcip, r.username)"
        ).fetchone()[0]
    finally:
        con.close()


def drop(case_id: str) -> None:
    p = db_path(case_id)
    if p.exists():
        p.unlink()
