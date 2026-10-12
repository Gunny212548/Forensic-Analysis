"""Severity: what level a finding is, and why - each step backed by a standard.

Two layers, applied in this order after the rules have run:

1. **Behaviour -> level (Sigma).** Every rule declares one of the five levels
   of the Sigma rules specification (v2.1.0, `level` field), chosen by that
   spec's own definitions:

     informational  enrichment only; "no case or alert should be triggered"
     low            "notable event but rarely an incident"; matters in volume
                    or in combination with other events
     medium         "relevant event that should be reviewed manually on a
                    more frequent basis"
     high           "should trigger an internal alert and requires a prompt
                    review"
     critical       "highly relevant event that indicates an incident" -
                    reserved for when the probability "borders certainty"

   The per-rule choice lives next to the rule (`rules.RULE_LEVEL`). No single
   rule is `critical`: one log event almost never reaches near-certainty on
   its own, which is exactly what layer 2 is for.

   A row the firewall refused is capped at `medium`, whatever the rule. In the
   ODNI Cyber Threat Framework a blocked attempt never crossed the intrusion
   boundary between Engagement and Presence, so it cannot be a prompt-review
   alert on its own (a C2 beacon that was denied every time is an attempt,
   not an established channel).

2. **Attack path -> escalation (ODNI CTF progression).** A finding is raised
   when the path it sits on shows the attack crossed the intrusion boundary
   (Presence) or went on to Effect. Each pattern is a sentence an analyst
   can check against the rows, and raises to the level its evidence earns:

     credential-compromise  high. A source brute-forced an account (R2000)
                            and later logged in to it from that same source -
                            T1110 -> T1078. Not critical: the log cannot tell
                            an attacker who guessed the password from an
                            owner who mistyped it three times, and Sigma keeps
                            critical for near-certainty.
     compromised-host       critical. One source host shows two *different*
                            Presence/Effect behaviours: beaconing (R2007),
                            allowed traffic to a known-bad address (R3003),
                            allowed malware-flagged traffic (R3002) or a large
                            outbound transfer (R3001), counted only where the
                            firewall let them through. Each has an innocent
                            reading alone; two independent ones on the same
                            host do not.

   Escalated rows are recorded in `escalations` (row_id, rid, pattern) and
   their `findings.lvl` raised to the pattern's weight, so everything that
   orders or scores by `lvl` (the graph, risk ranking, the AI's top-N) sees
   the escalation without knowing it exists.

`findings.lvl` holds the level's *weight*, not a free number: each level is
worth twice the one below it, so in `db.risk_scores()` one `high` finding
outweighs a `medium` and a `low` together. The weight only orders and scores;
the label shown anywhere is always `level_of(lvl)`.
"""

import duckdb

LEVELS = ("informational", "low", "medium", "high", "critical")

WEIGHT = {"informational": 1, "low": 2, "medium": 4, "high": 8, "critical": 16}

# Patterns that raise a finding, with the level they raise it to and the
# one-line reason the UI shows. Keep the wording factual - it is quoted to
# the analyst as the why.
PATTERNS = {
    "credential-compromise": (
        "high",
        "This source brute-forced the account, then logged in to it",
    ),
    "compromised-host": (
        "critical",
        "This host shows two or more different post-intrusion behaviours",
    ),
}


def level_of(lvl: int | None) -> str | None:
    """The Sigma level for a stored weight."""
    if lvl is None:
        return None
    for name in reversed(LEVELS):
        if lvl >= WEIGHT[name]:
            return name
    return "informational"


# Everything an authentication attack leaves on the (source, account) pair.
_AUTH_RULES = "('R1000', 'R1001', 'R1002', 'R2000', 'R2005', 'R2006')"


def _escalations() -> list[tuple[str, str]]:
    # Imported here, not at the top: rules imports this module for WEIGHT.
    from .rules import DENY_VERDICTS

    # Rows that make a host's compromise likely, counted only where the
    # firewall let them through - a beacon or malware download that was
    # refused every time never crossed the intrusion boundary.
    post_intrusion = (
        "f.rid IN ('R2007', 'R3003', 'R3002', 'R3001') "
        f"AND (r.verdict IS NULL OR r.verdict NOT IN {DENY_VERDICTS})"
    )
    return [
        # The success must come *after* the attack started, from the
        # attacking source itself: the owner logging in from their usual
        # address while someone else sprays the account is not a compromise
        # (the Azure case, gotcha #13) - which is why this pairs on the
        # source, not the account. And the source must have brute-forced
        # (R2000, >=3 failures), not merely been one of a spray's sources: on
        # the ESXi auth.log, a host that failed twice and got in 9 seconds
        # later was a typo, and R2005 membership alone had escalated it.
        ("credential-compromise", f"""
            INSERT INTO escalations
            SELECT f.row_id, f.rid, 'credential-compromise'
            FROM findings f
            JOIN raw_events r USING (row_id)
            JOIN (
                SELECT DISTINCT a.srcip, a.username
                FROM (
                    SELECT r.srcip, r.username, min(r.ts) AS first_attack
                    FROM findings f
                    JOIN raw_events r USING (row_id)
                    WHERE f.rid = 'R2000'
                      AND r.srcip IS NOT NULL AND r.username IS NOT NULL
                    GROUP BY r.srcip, r.username
                ) a
                JOIN raw_events s
                  ON s.srcip = a.srcip AND s.username = a.username
                WHERE s.action = 'auth_success' AND s.ts > a.first_attack
            ) hit ON r.srcip = hit.srcip AND r.username = hit.username
            WHERE f.rid IN {_AUTH_RULES}
        """),
        # Two *different* rules, not two rows: one beaconing pair produces
        # hundreds of R2007 rows and is still a single behaviour.
        ("compromised-host", f"""
            INSERT INTO escalations
            SELECT f.row_id, f.rid, 'compromised-host'
            FROM findings f
            JOIN raw_events r USING (row_id)
            JOIN (
                SELECT r.srcip
                FROM findings f
                JOIN raw_events r USING (row_id)
                WHERE {post_intrusion} AND r.srcip IS NOT NULL
                GROUP BY r.srcip
                HAVING count(DISTINCT f.rid) >= 2
            ) h ON r.srcip = h.srcip
            WHERE {post_intrusion}
        """),
    ]


def escalate(con: duckdb.DuckDBPyConnection) -> dict[str, int]:
    """Layer 2: raise findings on a successful attack path.
    Returns {pattern: findings escalated} for the manifest."""
    out: dict[str, int] = {}
    for name, sql in _escalations():
        before = con.execute("SELECT count(*) FROM escalations").fetchone()[0]
        con.execute(sql)
        after = con.execute("SELECT count(*) FROM escalations").fetchone()[0]
        if after > before:
            out[name] = after - before
    # Only ever raises: a finding two patterns touch keeps the higher one.
    whens = " ".join(f"WHEN '{p}' THEN {WEIGHT[lvl]}" for p, (lvl, _) in PATTERNS.items())
    con.execute(
        f"""
        UPDATE findings SET lvl = greatest(findings.lvl, e.w)
        FROM (SELECT row_id, rid, max(CASE pattern {whens} END) AS w
              FROM escalations GROUP BY row_id, rid) e
        WHERE findings.row_id = e.row_id AND findings.rid = e.rid
        """
    )
    return out


def summary(con: duckdb.DuckDBPyConnection) -> dict:
    """Rows per level, each row counted once at its highest level (a row can
    match several rules - gotcha #6). Shape kept from the old 0-15 summary so
    manifests written before the change still read."""
    cuts = ", ".join(
        f"count(*) FILTER (WHERE lvl >= {WEIGHT[name]}"
        + (f" AND lvl < {WEIGHT[LEVELS[i + 1]]}" if i + 1 < len(LEVELS) else "")
        + f") AS {name}"
        for i, name in enumerate(LEVELS)
    )
    row = con.execute(
        f"""
        SELECT coalesce(max(lvl), 0) AS max_lvl, {cuts}
        FROM (SELECT row_id, max(lvl) AS lvl FROM findings GROUP BY row_id)
        """
    ).fetchone()
    out = {"max_lvl": row[0], "max_level": level_of(row[0]) if row[0] else None}
    out.update(zip(LEVELS, row[1:]))
    return out
