"""Behaviour profiles: layer C facts about each source address of a case.

specs/behaviour_profiles.md (the user, 2026-10-20). A rule compares a count
with a fixed number, and a number taken from one customer's data misfires on a
customer with more traffic. A profile describes instead - how often, how fast,
how widely, when - and ranks each address against the other addresses of the
same evidence, so a busy log is compared with itself. Facts, never verdicts:
nothing here is a finding, a severity or a gate, and no threshold of ours is
applied (SP 800-92 5.2.1 baseline, 5.2.2 newness, time of day, frequency,
source).

Counting is SQL, at ingest, into `profile_source` in the case DuckDB: exact,
fast and reproducible, and recomputed on every re-process. The AI reads these
rows over MCP rather than raw rows it cannot count.

Windows are fixed at 1, 10 and 60 minutes and all three are kept (Q27): with
no single window chosen there is nothing to tune. A rank is only given when
at least MIN_CROWD addresses of that kind are in the evidence (Q28) - ranked
against three others, "top 1%" means nothing.
"""

import duckdb

from .rules import DENY_VERDICTS, IPV4_RE, NON_PUBLIC_IPV4_RE

WINDOWS = (1, 10, 60)  # minutes
MIN_CROWD = 20

FAILED = "('auth_failed', 'invalid_user')"

# The facts a source can be ranked on, and the crowd it is ranked within:
# addresses with sign-in events for the sign-in facts, addresses with a
# firewall verdict for the traffic facts.
RANKED = {
    "fail_max_1m": "auth", "fail_max_10m": "auth", "fail_max_60m": "auth",
    "accounts_failed": "auth",
    "refused_max_1m": "fw", "refused_max_10m": "fw", "refused_max_60m": "fw",
    "refused_ports": "fw", "dst_hosts": "fw", "bytes_public": "fw",
}


def _window_max(event_filter: str, name: str) -> str:
    """Per source, the most events of one kind inside any W-minute window,
    for each W: every event opens a window [t, t + W] and the busiest one
    counts. RANGE over the timestamp, so gaps in time are real gaps."""
    cols = ",\n".join(
        f"count(*) OVER (PARTITION BY srcip ORDER BY ts "
        f"RANGE BETWEEN CURRENT ROW AND INTERVAL {w} MINUTE FOLLOWING) AS w{w}"
        for w in WINDOWS)
    maxes = ", ".join(f"max(w{w}) AS {name}_max_{w}m" for w in WINDOWS)
    return f"""
        SELECT srcip, {maxes} FROM (
            SELECT srcip, {cols}
            FROM raw_events
            WHERE {event_filter} AND srcip IS NOT NULL AND ts IS NOT NULL
        ) GROUP BY srcip
    """


def build(con: duckdb.DuckDBPyConnection) -> int:
    """(Re)build `profile_source` from raw_events. Returns the row count."""
    con.execute("DROP TABLE IF EXISTS profile_source")
    rank_cols = ",\n".join(
        f"CASE WHEN {fact} IS NULL OR crowd_{domain} < {MIN_CROWD} THEN NULL "
        f"ELSE (rank() OVER (PARTITION BY has_{domain} ORDER BY {fact}) - 1)::DOUBLE / crowd_{domain} "
        f"END AS below_{fact}"
        for fact, domain in RANKED.items())
    con.execute(f"""
        CREATE TABLE profile_source AS
        WITH base AS (
            SELECT srcip,
                   count(*) AS events,
                   min(ts) AS first_ts, max(ts) AS last_ts,
                   count(DISTINCT CAST(ts AS DATE)) AS days_active,
                   list(DISTINCT hour(ts) ORDER BY hour(ts)) FILTER (WHERE ts IS NOT NULL) AS hours,
                   count(*) FILTER (WHERE action = 'auth_failed') AS auth_failed,
                   count(*) FILTER (WHERE action = 'invalid_user') AS invalid_user,
                   count(*) FILTER (WHERE action = 'auth_success') AS auth_success,
                   count(DISTINCT lower(username)) FILTER (WHERE action IN {FAILED}) AS accounts_failed,
                   count(DISTINCT lower(username)) FILTER (WHERE action = 'auth_success') AS accounts_succeeded,
                   min(ts) FILTER (WHERE action IN {FAILED}) AS first_fail_ts,
                   count(*) FILTER (WHERE verdict IN {DENY_VERDICTS}) AS refused,
                   count(*) FILTER (WHERE verdict IS NOT NULL AND verdict NOT IN {DENY_VERDICTS}) AS allowed,
                   count(DISTINCT dstip) FILTER (WHERE verdict IS NOT NULL) AS dst_hosts,
                   count(DISTINCT dstport) FILTER (WHERE verdict IN {DENY_VERDICTS}) AS refused_ports,
                   count(DISTINCT app) FILTER (WHERE verdict IN {DENY_VERDICTS}) AS refused_services,
                   sum(bytes_sent) AS bytes_total,
                   max(bytes_sent) AS bytes_max_session,
                   -- NULL only where the log has no byte count at all; a source
                   -- that sent bytes, none of them to a public address, has 0.
                   CASE WHEN sum(bytes_sent) IS NULL THEN NULL
                        ELSE coalesce(sum(bytes_sent) FILTER (
                                 WHERE regexp_matches(dstip, '{IPV4_RE}')
                                   AND NOT regexp_matches(dstip, '{NON_PUBLIC_IPV4_RE}')), 0)
                   END AS bytes_public,
                   bool_or(action IN ('auth_failed', 'invalid_user', 'auth_success')) AS has_auth,
                   bool_or(verdict IS NOT NULL) AS has_fw
            FROM raw_events WHERE srcip IS NOT NULL
            GROUP BY srcip
        ),
        fails AS ({_window_max(f"action IN {FAILED}", "fail")}),
        refusals AS ({_window_max(f"verdict IN {DENY_VERDICTS}", "refused")}),
        after_fail AS (
            SELECT b.srcip, min(e.ts) AS success_after_fail_ts
            FROM base b JOIN raw_events e
              ON e.srcip = b.srcip AND e.action = 'auth_success' AND e.ts > b.first_fail_ts
            GROUP BY b.srcip
        ),
        joined AS (
            SELECT base.*,
                   {", ".join(f"coalesce(fails.fail_max_{w}m, 0) AS fail_max_{w}m" for w in WINDOWS)},
                   {", ".join(f"coalesce(refusals.refused_max_{w}m, 0) AS refused_max_{w}m" for w in WINDOWS)},
                   after_fail.success_after_fail_ts,
                   count(*) FILTER (WHERE base.has_auth) OVER () AS crowd_auth,
                   count(*) FILTER (WHERE base.has_fw) OVER () AS crowd_fw
            FROM base
            LEFT JOIN fails USING (srcip)
            LEFT JOIN refusals USING (srcip)
            LEFT JOIN after_fail USING (srcip)
        )
        SELECT *, {rank_cols}
        FROM joined
    """)
    return con.execute("SELECT count(*) FROM profile_source").fetchone()[0]


_FIELDS_AUTH = ["auth_failed", "invalid_user", "auth_success", "accounts_failed",
                "accounts_succeeded", *[f"fail_max_{w}m" for w in WINDOWS],
                "first_fail_ts", "success_after_fail_ts"]
_FIELDS_FW = ["refused", "allowed", "dst_hosts", "refused_ports", "refused_services",
              *[f"refused_max_{w}m" for w in WINDOWS], "bytes_total", "bytes_max_session", "bytes_public"]


def _shape(row: dict, fmt_ts) -> dict:
    """One profile as served: sign-in and traffic facts only where the
    evidence has that kind of event ("n/a" otherwise - never a 0 that
    means "no field"), ranks only where the crowd is big enough."""
    out = {"srcip": row["srcip"], "events": row["events"],
           "first_seen": fmt_ts(row["first_ts"]) or None, "last_seen": fmt_ts(row["last_ts"]) or None,
           "days_active": row["days_active"], "hours_active": row["hours"] or []}
    for domain, fields in (("auth", _FIELDS_AUTH), ("fw", _FIELDS_FW)):
        crowd = row[f"crowd_{domain}"]
        if not row[f"has_{domain}"]:
            out["sign_ins" if domain == "auth" else "traffic"] = "n/a - no such events from this address"
            continue
        facts = {f: ((fmt_ts(row[f]) or None) if f.endswith("_ts") else row[f]) for f in fields}
        if domain == "auth" and row["first_fail_ts"] and row["success_after_fail_ts"]:
            facts["success_after_fail_gap_s"] = int((row["success_after_fail_ts"]
                                                     - row["first_fail_ts"]).total_seconds())
        ranks = {f: round(row[f"below_{f}"] * 100, 1) for f, d in RANKED.items()
                 if d == domain and row[f"below_{f}"] is not None}
        facts["rank"] = ({"percent_of_addresses_below": ranks, "among": crowd} if crowd >= MIN_CROWD
                         else f"not ranked - {crowd} address(es) with these events here, "
                              f"fewer than {MIN_CROWD}")
        out["sign_ins" if domain == "auth" else "traffic"] = facts
    return out


def get(con, srcip: str, fmt_ts) -> dict | None:
    """One address's profile, or None. A case processed before profiles
    existed raises LookupError - it needs a re-process."""
    try:
        cur = con.execute("SELECT * FROM profile_source WHERE srcip = ?", [srcip])
    except duckdb.CatalogException:
        raise LookupError("no behaviour profiles in this case - re-process it") from None
    row = cur.fetchone()
    if row is None:
        return None
    return _shape(dict(zip([d[0] for d in cur.description], row)), fmt_ts)


def top(con, by: str, limit: int, fmt_ts) -> list[dict]:
    """The addresses highest on one fact, highest first, ties by address."""
    if by not in RANKED:
        raise ValueError(f"by must be one of {sorted(RANKED)}")
    try:
        cur = con.execute(f"SELECT * FROM profile_source WHERE {by} > 0 "
                          f"ORDER BY {by} DESC, srcip LIMIT ?", [limit])
    except duckdb.CatalogException:
        raise LookupError("no behaviour profiles in this case - re-process it") from None
    cols = [d[0] for d in cur.description]
    return [_shape(dict(zip(cols, r)), fmt_ts) for r in cur.fetchall()]


def source(case_id: str, srcip: str) -> dict | None:
    """get() for a case id - what the API route and the MCP tool call."""
    from . import db
    if not db.db_path(case_id).exists():
        return None
    con = db.connect(case_id, read_only=True)
    try:
        return get(con, srcip, db._fmt_ts)
    finally:
        con.close()


def sources_by(case_id: str, by: str, limit: int) -> list[dict]:
    """top() for a case id."""
    from . import db
    if not db.db_path(case_id).exists():
        return []
    con = db.connect(case_id, read_only=True)
    try:
        return top(con, by, limit, db._fmt_ts)
    finally:
        con.close()


def context_lines(con, srcips: set[str]) -> dict[str, str]:
    """address -> one line of its profile for the events table's context
    column, only where there is something to say (failures or refusals)."""
    if not srcips:
        return {}
    try:
        rows = con.execute(
            "SELECT srcip, auth_failed + invalid_user, accounts_failed, fail_max_1m, fail_max_10m, "
            "below_fail_max_10m, crowd_auth, refused, refused_max_10m, below_refused_max_10m, crowd_fw "
            "FROM profile_source WHERE srcip IN (SELECT unnest(?))", [sorted(srcips)]).fetchall()
    except duckdb.CatalogException:
        return {}
    out = {}
    for ip, fails, accts, m1, m10, below_f, crowd_a, refused, r10, below_r, crowd_f in rows:
        parts = []
        if fails:
            rank = f", more than {below_f * 100:.0f}% of {crowd_a} sources here" if below_f is not None else ""
            parts.append(f"source failed {fails} sign-ins on {accts} account(s), "
                         f"most {m1} in 1 min / {m10} in 10 min{rank}")
        if refused:
            rank = f", more than {below_r * 100:.0f}% of {crowd_f} sources here" if below_r is not None else ""
            parts.append(f"source refused {refused} times, most {r10} in 10 min{rank}")
        if parts:
            out[ip] = "; ".join(parts)
    return out
