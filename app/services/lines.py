"""Where a product rule draws its line (specs/per_product_rules.md, D16, Q66-Q70).

Two methods, both read (docs/standards/SOURCES.md):

- **TRW** - Jung, Paxson, Berger & Balakrishnan 2004, §4: for each source, the
  first attempt to each *new* destination host is a success or a failure, and
  Wald's sequential likelihood-ratio test decides scanner / benign / pending.
  The paper's parameters (Q68): a benign source succeeds with probability 0.8,
  a scanner 0.2; false alarms <= 0.01, detection >= 0.99 - which decides after
  4 failures or 4 successes. No population and no time window. A firewall
  refusal is read as a failure and an allowed connection as a success - an
  adaptation, stated: the paper's failure is an attempt to an inactive host or
  service. Any other verdict (Check Point's Detect, a sign-in) is neither.
- **Evidence line** - Javed & Paxson 2013, §3.1: measure how the evidence's own
  *legitimate* members behave and draw the line well above that tail - here
  above twice their 99th percentile (Q66). The members are chosen by a
  criterion that does not depend on the line (Q70), so attackers cannot raise
  it: a 99th percentile over everyone is raised by the attackers unless they
  are under 1% of it. Under MIN_LEGIT legitimate members no tail can be
  measured and no line is drawn (Q67): every entity showing the behaviour goes
  to the analyst. A line is never below the behaviour's own minimum.

Every rule that draws a line returns a record of it - method, value, the
population and its size - which the case keeps (manifest `lines`), so a
reader can check how each finding was decided.
"""

import math

THETA_BENIGN, THETA_SCANNER = 0.8, 0.2  # success probability of a first attempt
ALPHA, BETA = 0.01, 0.99                # false alarm bound, detection bound
TRW_UPPER = math.log(BETA / ALPHA)                # cross it: scanner
TRW_LOWER = math.log((1 - BETA) / (1 - ALPHA))    # cross it: benign
LLR_FAILURE = math.log((1 - THETA_SCANNER) / (1 - THETA_BENIGN))
LLR_SUCCESS = math.log(THETA_SCANNER / THETA_BENIGN)

MIN_LEGIT = 20  # legitimate members needed to measure a tail (Q67, gotcha #57's MIN_CROWD)
TAIL = 0.99
FACTOR = 2

TRW_SOURCE = "Jung, Paxson, Berger & Balakrishnan 2004, §4 (TRW)"
LINE_SOURCE = "Javed & Paxson 2013, §3.1 (legitimate members' tail)"


def trw(con, product: str, deny_verdicts: str, non_public_re: str) -> dict:
    """Decide every source of `product`'s rows with TRW into TEMP TABLE
    trw_<product> (srcip, decision, hosts, n_decided, episode_start).
    Idempotent per run.
    Returns the summary the case shows, with the success ratio measured on
    the sources decided benign beside the paper's 0.8 (Q68)."""
    table = f"trw_{product}"
    con.execute(f"""
        CREATE OR REPLACE TEMP TABLE {table}_walk AS
        WITH tried AS (
          SELECT srcip, dstip, ts, row_id, verdict IN {deny_verdicts} AS failed,
                 row_number() OVER (PARTITION BY srcip, dstip ORDER BY ts, row_id) AS k
          FROM raw_events
          WHERE product = '{product}' AND srcip IS NOT NULL AND dstip IS NOT NULL
            AND ts IS NOT NULL AND (verdict = 'allow' OR verdict IN {deny_verdicts})
            -- The paper tests accesses to the site's own addresses. An internal
            -- host going out to the internet is not scanning the site: a user
            -- refused at four blocked web sites in a row was a "scanner" on the
            -- Check Point quarter. Internal -> public contacts are left out.
            AND NOT (regexp_matches(srcip, '{non_public_re}')
                     AND NOT regexp_matches(dstip, '{non_public_re}')))
        SELECT srcip, dstip, ts, failed,
               row_number() OVER (PARTITION BY srcip ORDER BY ts, row_id) AS n
        FROM tried WHERE k = 1""")
    return decide(con, table)


def decide(con, table: str) -> dict:
    """Walk TEMP TABLE `<table>_walk` (srcip, failed, ts, n: each source's first
    attempt at each new target, numbered in time order) and write the decision
    of every source into TEMP TABLE `<table>`. Shared by the firewall's hosts
    (trw above) and other targets - a sign-in source's accounts (rules_windows)."""
    # The walk itself, per source in time order. **After a benign decision it
    # starts again** (the user's test, 2026-10-22): the paper decides each
    # remote host once, over 24-hour traces; over months a workstation that was
    # ordinary for weeks and then swept the server VLAN (QakBot, 85% of its new
    # hosts refused) was decided benign on its first four contacts and never
    # looked at again. Restarting the test is an adaptation, stated. A scanner
    # decision stands, with the time its episode began.
    sources, decisions, hosts, decided_n, starts = [], [], [], [], []
    for src, failed, times in con.execute(
            f"SELECT srcip, list(failed ORDER BY n), list(ts ORDER BY n) FROM {table}_walk "
            "GROUP BY srcip").fetchall():
        # `first_fail`: the episode's first refused new host - when the scan began.
        walk, start, first_fail, benign, verdict = 0.0, 0, None, False, None
        for k, f in enumerate(failed):
            walk += LLR_FAILURE if f else LLR_SUCCESS
            if f and first_fail is None:
                first_fail = k
            if walk >= TRW_UPPER:
                verdict = (k - start + 1, times[first_fail])
                break
            if walk <= TRW_LOWER:
                benign, walk, start, first_fail = True, 0.0, k + 1, None
        sources.append(src)
        hosts.append(len(failed))
        if verdict:
            decisions.append("scanner")
            decided_n.append(verdict[0])
            starts.append(verdict[1])
        else:
            decisions.append("benign" if benign else "pending")
            decided_n.append(None)
            starts.append(None)
    con.execute(f"""
        CREATE OR REPLACE TEMP TABLE {table} AS
        SELECT unnest($1::VARCHAR[]) AS srcip, unnest($2::VARCHAR[]) AS decision,
               unnest($3::BIGINT[]) AS hosts, unnest($4::BIGINT[]) AS n_decided,
               unnest($5::TIMESTAMP[]) AS episode_start""",
                [sources, decisions, hosts, decided_n, starts])
    counts = dict(con.execute(f"SELECT decision, count(*) FROM {table} GROUP BY 1").fetchall())
    measured = con.execute(
        f"SELECT avg(CASE WHEN failed THEN 0 ELSE 1 END) FROM {table}_walk "
        f"JOIN {table} USING (srcip) WHERE decision = 'benign'").fetchone()[0]
    return {
        "method": "trw", "source": TRW_SOURCE,
        "parameters": {"success_benign": THETA_BENIGN, "success_scanner": THETA_SCANNER,
                       "alpha": ALPHA, "beta": BETA},
        "sources": {k: counts.get(k, 0) for k in ("scanner", "benign", "pending")},
        "measured_success_benign": None if measured is None else round(measured, 4),
        "assumption_holds": None if measured is None else measured >= THETA_BENIGN,
    }


def evidence_line(con, legit_sql: str, minimum: float, population: str, params=None) -> dict:
    """The line over `legit_sql`'s column `v`, one row per legitimate member.
    The rule flags a value when `v > above AND v >= minimum`: `above` is twice
    the members' 99th percentile, or -1 when there are too few members to
    measure one (then the minimum alone decides - every entity showing the
    behaviour)."""
    n, tail = con.execute(
        f"SELECT count(*), quantile_cont(v, {TAIL}) FROM ({legit_sql})", params or []).fetchone()
    if n < MIN_LEGIT:
        return {"method": "no-line", "source": LINE_SOURCE, "population": population,
                "members": n, "above": -1, "minimum": minimum,
                "note": f"{n} legitimate members - under {MIN_LEGIT}, no tail can be measured; "
                        "every entity showing the behaviour goes to the analyst"}
    above = FACTOR * float(tail or 0)
    return {"method": "evidence-line", "source": LINE_SOURCE, "population": population,
            "members": n, "p99": float(tail or 0), "above": above, "minimum": minimum,
            "note": f"flagged above {FACTOR} x the 99th percentile of {n} legitimate members "
                    f"({above:g}), and at least {minimum:g}"}
