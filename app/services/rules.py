"""Detection rules, expressed as SQL over the canonical raw_events table.

Each rule is one INSERT ... SELECT that writes matching rows into findings.
Correlation rules (repeated failures, port scans) are just a join against a
GROUP BY ... HAVING subquery, which is where SQL pays off: they run in
milliseconds over millions of rows instead of building dictionaries of every
event in Python.

A single row can match several rules and get several findings - that is
intentional (a login failure that is also part of a brute-force burst is
both).

Rules insert lvl as NULL. The level is declared once per rule in RULE_LEVEL
(a Sigma level) and written by apply_rules(), then raised by
severity.escalate() for findings on a successful attack path.

Rule id conventions:
  R1xxx  single-event, host/auth logs
  R2xxx  correlation / aggregate
  R3xxx  single-event, network/firewall (CSV)
"""

import duckdb

from .severity import WEIGHT

DENY_VERDICTS = (
    "('deny', 'drop', 'block', 'blocked', 'reject', 'prevent', "
    "'reset-both', 'reset-client', 'reset-server', 'block-url')"
)

RULES: list[tuple[str, str]] = [
    # ---------- R1xxx: single-event, auth / host logs ----------
    ("R1000", """
        INSERT INTO findings
        SELECT row_id, 'R1000', NULL,
               'Authentication failed for ' || coalesce(username, '?') ||
               ' from ' || coalesce(srcip, '?'),
               ['T1110.001']
        FROM raw_events WHERE action = 'auth_failed'
    """),
    ("R1001", """
        INSERT INTO findings
        SELECT row_id, 'R1001', NULL,
               'Login succeeded for ' || coalesce(username, '?') ||
               ' from ' || coalesce(srcip, '?'),
               []::VARCHAR[]
        FROM raw_events WHERE action = 'auth_success'
    """),
    ("R1002", """
        INSERT INTO findings
        SELECT row_id, 'R1002', NULL,
               'Login attempt with invalid user ''' || coalesce(username, '?') ||
               ''' from ' || coalesce(srcip, '?'),
               ['T1110.003', 'T1087']
        FROM raw_events WHERE action = 'invalid_user'
    """),
    ("R1003", """
        INSERT INTO findings
        SELECT row_id, 'R1003', NULL,
               'SSH connection opened from ' || coalesce(srcip, '?'),
               []::VARCHAR[]
        FROM raw_events WHERE action = 'connection'
    """),
    ("R1004", """
        INSERT INTO findings
        SELECT row_id, 'R1004', NULL,
               'Password changed for ' || coalesce(username, '?'),
               []::VARCHAR[]
        FROM raw_events WHERE action = 'password_changed'
    """),

    # ---------- R2xxx: correlation ----------
    ("R2000", """
        INSERT INTO findings
        SELECT e.row_id, 'R2000', NULL,
               'Repeated brute-force from ' || e.srcip ||
               ' (' || a.n || ' attempts)',
               ['T1110.001']
        FROM raw_events e
        JOIN (SELECT srcip, count(*) AS n FROM raw_events
              WHERE action = 'auth_failed' AND srcip IS NOT NULL
              GROUP BY srcip HAVING count(*) >= 3) a ON e.srcip = a.srcip
        WHERE e.action = 'auth_failed'
    """),
    # NOTE: tagged as Active Scanning, not Brute Force. Repeated *blocked*
    # connections are network probing; calling them T1110 made the AI layer
    # narrate port-scan denies as "brute-force attempts" in testing.
    ("R2001", f"""
        INSERT INTO findings
        SELECT e.row_id, 'R2001', NULL,
               'Repeated blocked connections from ' || e.srcip ||
               ' (' || a.n || ' denies)',
               ['T1595']
        FROM raw_events e
        JOIN (SELECT srcip, count(*) AS n FROM raw_events
              WHERE verdict IN {DENY_VERDICTS} AND srcip IS NOT NULL
              GROUP BY srcip HAVING count(*) >= 5) a ON e.srcip = a.srcip
        WHERE e.verdict IN {DENY_VERDICTS}
    """),
    # A scan is a source being *refused* across many ports, so both the count
    # and the rows flagged are restricted to denied traffic. Without that
    # restriction this fired on every row of any source that merely reaches
    # 10 distinct ports - on the corpus it flagged a workstation's 18,972
    # allowed connections as a port scan, and handed db.risk_scores() two
    # lvl-7 terms with n=25,579 that pushed that host above real findings.
    # Measured over 13,666 sources: distinct destination ports per source is
    # median 1 / p90 1, 15 sources reach >=10 and every one of them is
    # ordinary traffic, while deny-dominated sources top out at 1 port. So
    # the deny filter removes 15 false positives and no true ones, and the
    # >=10 threshold stays as it was - the threshold was never the problem,
    # counting rows that were allowed was.
    ("R2002", f"""
        INSERT INTO findings
        SELECT e.row_id, 'R2002', NULL,
               'Port scan pattern from ' || e.srcip ||
               ' (' || a.n || ' distinct destination ports refused)',
               ['T1046']
        FROM raw_events e
        JOIN (SELECT srcip, count(DISTINCT dstport) AS n FROM raw_events
              WHERE dstport IS NOT NULL AND srcip IS NOT NULL
                AND verdict IN {DENY_VERDICTS}
              GROUP BY srcip HAVING count(DISTINCT dstport) >= 10) a
          ON e.srcip = a.srcip
        WHERE e.verdict IN {DENY_VERDICTS}
    """),

    # Service sweep: the equivalent of R2002 for logs that name the service
    # ("http", "FW1_ica_services") instead of a numeric port - Check Point
    # exports have no port column at all, so R2002 can never fire on them.
    # Deny-restricted for the same reason, and the Check Point export shows
    # why it matters: 900 distinct services appear among its denied rows and
    # only 8 among its allowed ones, so the sweep is entirely in the denies.
    # Unrestricted, this rule also claimed the 2,978 accepted rows - which
    # are a policy gap, and R2004's finding, not a sweep.
    ("R2003", f"""
        INSERT INTO findings
        SELECT e.row_id, 'R2003', NULL,
               'Service sweep from ' || e.srcip ||
               ' (' || a.n || ' distinct services refused)',
               ['T1046']
        FROM raw_events e
        JOIN (SELECT srcip, count(DISTINCT app) AS n FROM raw_events
              WHERE app IS NOT NULL AND srcip IS NOT NULL
                AND verdict IN {DENY_VERDICTS}
              GROUP BY srcip HAVING count(DISTINCT app) >= 20) a
          ON e.srcip = a.srcip
        WHERE e.verdict IN {DENY_VERDICTS}
    """),

    # Policy gap: a source the firewall is overwhelmingly blocking still got
    # some traffic through. That is what a bypassed/implied rule looks like
    # from the logs alone, without knowing the vendor's rule semantics. The
    # ratio guard keeps ordinary users (a few blocked sites, lots of normal
    # browsing) from matching.
    ("R2004", f"""
        INSERT INTO findings
        SELECT e.row_id, 'R2004', NULL,
               'Traffic ALLOWED from ' || e.srcip ||
               ' despite ' || a.denies || ' blocks from the same source (possible policy gap)',
               ['T1133']
        FROM raw_events e
        JOIN (SELECT srcip,
                     count(*) FILTER (WHERE verdict IN {DENY_VERDICTS}) AS denies,
                     count(*) FILTER (WHERE verdict = 'allow')          AS allows
              FROM raw_events WHERE srcip IS NOT NULL
              GROUP BY srcip
              HAVING count(*) FILTER (WHERE verdict IN {DENY_VERDICTS}) >= 20
                 AND count(*) FILTER (WHERE verdict = 'allow') >= 1
                 AND count(*) FILTER (WHERE verdict IN {DENY_VERDICTS})
                     >= 3 * count(*) FILTER (WHERE verdict = 'allow')) a
          ON e.srcip = a.srcip
        WHERE e.verdict = 'allow'
    """),

    # Password spray: one account, failures arriving from many different
    # sources. R2000 counts failures per *source* and cannot see this - in a
    # real Azure AD export 14 distinct IPv4/IPv6 addresses each failed
    # exactly once against the same account, so every per-source counter
    # stayed at 1 while the account was plainly under attack.
    ("R2005", """
        INSERT INTO findings
        SELECT e.row_id, 'R2005', NULL,
               'Password spray against ' || e.username || ' from ' ||
               a.n || ' distinct sources',
               ['T1110.003']
        FROM raw_events e
        JOIN (SELECT username, count(DISTINCT srcip) AS n FROM raw_events
              WHERE action = 'auth_failed' AND username IS NOT NULL
                AND srcip IS NOT NULL
              GROUP BY username HAVING count(DISTINCT srcip) >= 5) a
          ON e.username = a.username
        WHERE e.action = 'auth_failed'
    """),

    # Successful logins to one account from many sources inside the same
    # hour. Ordinary users move between a handful of addresses across days;
    # five addresses succeeding minutes apart is an address pool. Bucketing
    # by hour is crude - a burst straddling the boundary splits - but it is
    # one GROUP BY and needs no window functions.
    ("R2006", """
        INSERT INTO findings
        SELECT e.row_id, 'R2006', NULL,
               'Successful logins for ' || e.username || ' from ' || a.n ||
               ' distinct sources within one hour',
               ['T1078']
        FROM raw_events e
        JOIN (SELECT username, date_trunc('hour', ts) AS hr,
                     count(DISTINCT srcip) AS n
              FROM raw_events
              WHERE action = 'auth_success' AND username IS NOT NULL
                AND srcip IS NOT NULL AND ts IS NOT NULL
              GROUP BY username, date_trunc('hour', ts)
              HAVING count(DISTINCT srcip) >= 4) a
          ON e.username = a.username AND date_trunc('hour', e.ts) = a.hr
        WHERE e.action = 'auth_success'
    """),

    # Beaconing: C2 gives itself away by *regularity*, not volume. Measure
    # the interval between consecutive connections for each src->dst pair and
    # flag the pairs whose intervals barely vary (coefficient of variation =
    # stddev/mean, i.e. jitter). Nothing threshold-based can express this -
    # in the customer corpus R3000 flagged 12,281 rows of that host's traffic
    # and buried the four destinations that mattered.
    #
    # Measured on real data: the true beacons sat at CV 0.43-0.55 and ordinary
    # bursty browsing at 0.89-0.94, so 0.6 separates them with room to spare.
    # >=30 connections and a 30s-1h period keep out short bursts and daily
    # jobs.
    #
    # Restricted to egress: the destination must be a public IPv4 address.
    # Internal traffic is periodic by nature and drowns the signal - the
    # first version flagged 16,599 rows of one file that turned out to be
    # Windows Delivery Optimization peer-to-peer updates
    # (ms-update-optimization-p2p, port 7680, 10.x -> 10.x) across 44 host
    # pairs. Beaconing that matters leaves the network; the cost is that
    # internal C2 and lateral beaconing are out of scope.
    #
    # Even on egress, periodic *legitimate* traffic (update checks,
    # telemetry, keepalives) looks identical from the logs alone - this rule
    # localises, the analyst confirms what the destination actually is.
    # NOTE: raw string - the IPv4 regexes below contain \\. and Python treats
    # an unrecognised escape in a normal string as a SyntaxWarning that is
    # scheduled to become a SyntaxError, which would stop this module (and
    # therefore the whole app) from importing at all.
    ("R2007", r"""
        INSERT INTO findings
        SELECT e.row_id, 'R2007', NULL,
               'Beaconing pattern ' || e.srcip || ' -> ' || e.dstip ||
               ' (' || b.n || ' connections at ~' || cast(round(b.avg_gap) AS INT) ||
               's intervals, jitter ' || cast(round(b.cv * 100) AS INT) || '%)',
               ['T1071']
        FROM raw_events e
        JOIN (
          WITH gaps AS (
            SELECT srcip, dstip,
                   date_diff('second',
                             lag(ts) OVER (PARTITION BY srcip, dstip ORDER BY ts),
                             ts) AS gap
            FROM raw_events
            WHERE ts IS NOT NULL AND srcip IS NOT NULL AND dstip IS NOT NULL
          )
          -- count(*) here counts *intervals*, and there is one fewer
          -- interval than there are connections, so n+1 is what the
          -- description should say - it used to report 388 for a pair with
          -- 389 rows.
          SELECT srcip, dstip, count(*) + 1 AS n, avg(gap) AS avg_gap,
                 stddev_pop(gap) / nullif(avg(gap), 0) AS cv
          FROM gaps
          WHERE gap > 0
          GROUP BY srcip, dstip
          HAVING count(*) >= 30
             AND avg(gap) BETWEEN 30 AND 3600
             AND stddev_pop(gap) / nullif(avg(gap), 0) < 0.6
        ) b ON e.srcip = b.srcip AND e.dstip = b.dstip
        WHERE regexp_matches(e.dstip, '^[0-9]{1,3}(\.[0-9]{1,3}){3}$')
          -- Non-public destinations, all of which are periodic by nature or
          -- not a real endpoint: RFC1918, loopback, link-local, multicast,
          -- 0.0.0.0/8, CGNAT 100.64/10 (turns up in ISP-side logs) and the
          -- 240-255 reserved range. The last branch (25[0-5]\.) is also what
          -- already excludes the limited broadcast address 255.255.255.255,
          -- and 169\.254\. covers the link-local directed broadcast
          -- 169.254.255.255 - both appear in the FortiGate corpus as DHCP
          -- and autoconfiguration chatter.
          AND NOT regexp_matches(e.dstip,
              '^(0\.|10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.|22[4-9]\.|23[0-9]\.|24[0-9]\.|25[0-5]\.)')
          -- Same reasoning applied to the *source*, which had no guard at
          -- all: 0.0.0.0 is not a host, it is "no address yet" - a DHCP
          -- client broadcasting DISCOVER on a timer before it has a lease -
          -- and 255.255.255.255 is never a real sender. 214 rows of
          -- 0.0.0.0 -> 255.255.255.255 exist in the corpus; they are caught
          -- today only by the destination branch above, so make the
          -- intent explicit rather than incidental.
          AND e.srcip NOT IN ('0.0.0.0', '255.255.255.255')
          -- Deliberately NOT excluded: a destination merely *ending* in .255.
          -- Without the subnet mask a flow log cannot say whether that is a
          -- directed broadcast, and in this corpus the .255 destinations
          -- R2007 flags (47.246.167.255, 52.123.168.255) are ordinary public
          -- unicast hosts in /16-or-shorter allocations. Subnet-directed
          -- broadcast on a genuinely internal /24 is a known residual gap,
          -- but every internal case of it is already excluded as RFC1918.
    """),

    # ---------- R3xxx: single-event, network / firewall ----------
    ("R3000", """
        INSERT INTO findings
        SELECT row_id, 'R3000', NULL,
               'High-risk application ''' || coalesce(app, 'unknown') ||
               ''' allowed (' || coalesce(srcip, '?') || ' -> ' || coalesce(dstip, '?') || ')',
               ['T1071']
        FROM raw_events WHERE verdict = 'allow' AND risk >= 4
    """),
    ("R3001", """
        INSERT INTO findings
        SELECT row_id, 'R3001', NULL,
               'Large outbound transfer (' || bytes_sent || ' bytes) ' ||
               coalesce(srcip, '?') || ' -> ' || coalesce(dstip, '?'),
               ['T1041']
        FROM raw_events WHERE bytes_sent > 50000000
    """),
    # Known-bad destination: the case's traffic met an address a public or
    # customer-supplied feed already attributes to malware infrastructure.
    # This is the one rule whose verdict comes from outside the log - which
    # is also why the source and note are quoted into the description: an
    # indicator is only as good as the feed behind it, and the analyst has to
    # be able to weigh that.
    #
    # Split by verdict, for the reason gotcha #23 gives for R2002/R2003: the
    # rows that are evidence of a *live* channel are the ones the firewall let
    # through. The original single rule fired at lvl 13 / T1071 regardless of
    # verdict, and on the FortiGate corpus all 24 of its hits were on denied
    # traffic (e.g. six NetBIOS UDP/137 queries to 207.90.244.13, all
    # verdict='deny') - which the AI layer then narrated as hosts that
    # "communicated with a known-bad external IP", Command and Control,
    # confidence high. The firewall had stopped every one of them.
    ("R3003", f"""
        INSERT INTO findings
        SELECT e.row_id, 'R3003', NULL,
               'Traffic ALLOWED to known-bad indicator ' || e.dstip ||
               ' [' || i.source ||
               CASE WHEN i.note <> '' THEN ': ' || i.note ELSE '' END || ']',
               ['T1071']
        FROM raw_events e
        JOIN ioc i ON e.dstip = i.value AND i.type = 'ip'
        WHERE e.verdict IS NULL OR e.verdict NOT IN {DENY_VERDICTS}
    """),

    # Same indicator match, but the firewall refused the connection. Worth
    # knowing - a host trying to reach malware infrastructure is a host to
    # look at (malware beaconing attempt, DNS/NetBIOS leakage, stale config) -
    # but nothing was established, so it is not the emergency R3003 is.
    # Medium, one level below R3003's high (see RULE_LEVEL).
    #
    # Tag kept as T1071 rather than dropped: ATT&CK techniques describe
    # attempted behaviour, not outcomes, so an attempt to speak C2 protocol is
    # still T1071 - but the severity and the word "BLOCKED" leading the
    # description are what the narrative reads, and both now say what actually
    # happened.
    ("R3005", f"""
        INSERT INTO findings
        SELECT e.row_id, 'R3005', NULL,
               'BLOCKED connection attempt to known-bad indicator ' || e.dstip ||
               ' (denied by policy) [' || i.source ||
               CASE WHEN i.note <> '' THEN ': ' || i.note ELSE '' END || ']',
               ['T1071']
        FROM raw_events e
        JOIN ioc i ON e.dstip = i.value AND i.type = 'ip'
        WHERE e.verdict IN {DENY_VERDICTS}
    """),

    # Same, inbound: the source of this traffic is a listed attacker. Lower
    # severity than R3003 because feeds like blocklist.de list any host that
    # has ever probed anyone - being scanned by one is routine background
    # noise, whereas talking *to* C2 infrastructure is not. Split on verdict
    # for the same reason as R3003, one tier down each: traffic from a listed
    # host that was let in is the one to look at.
    ("R3004", f"""
        INSERT INTO findings
        SELECT e.row_id, 'R3004', NULL,
               'Traffic ALLOWED from known-bad indicator ' || e.srcip ||
               ' [' || i.source ||
               CASE WHEN i.note <> '' THEN ': ' || i.note ELSE '' END || ']',
               ['T1595']
        FROM raw_events e
        JOIN ioc i ON e.srcip = i.value AND i.type = 'ip'
        WHERE e.verdict IS NULL OR e.verdict NOT IN {DENY_VERDICTS}
    """),

    # Inbound from a listed host, blocked at the perimeter. This is the most
    # routine event in the whole rule set - the internet scans everything and
    # the firewall dropped it - so it is informational only, kept because an
    # analyst still wants the perimeter's own hit rate visible.
    ("R3006", f"""
        INSERT INTO findings
        SELECT e.row_id, 'R3006', NULL,
               'BLOCKED inbound traffic from known-bad indicator ' || e.srcip ||
               ' (denied at the perimeter) [' || i.source ||
               CASE WHEN i.note <> '' THEN ': ' || i.note ELSE '' END || ']',
               ['T1595']
        FROM raw_events e
        JOIN ioc i ON e.srcip = i.value AND i.type = 'ip'
        WHERE e.verdict IN {DENY_VERDICTS}
    """),

    ("R3002", """
        INSERT INTO findings
        SELECT row_id, 'R3002', NULL,
               'Traffic flagged ''' || category || ''' (' ||
               coalesce(srcip, '?') || ' -> ' || coalesce(dstip, '?') || ')',
               ['T1105']
        FROM raw_events
        WHERE category IS NOT NULL
          AND regexp_matches(lower(category),
                             'malware|virus|spyware|botnet|command-and-control|\\bc2\\b')
    """),
]


# Short human labels per rule, used to name edges in the SQL-built attack
# graph (db.build_graph). R1000-R1002/R2000 are deliberately protocol-neutral:
# they used to say "SSH" because auth.log was the only source, but CSV auth
# exports (Azure AD sign-ins) now set `action` too, and an SSH label on a web
# sign-in propagates straight into the AI narrative. The `descr` written into findings is a full
# sentence with IPs in it - far too long to sit on an edge - so keep a terse
# form here. Add one whenever you add a rule; a rule with no entry falls
# back to its id.
RULE_LABELS: dict[str, str] = {
    "R1000": "auth failed",
    "R1001": "login success",
    "R1002": "invalid user",
    "R1003": "SSH connection",
    "R1004": "password changed",
    "R2000": "brute-force",
    "R2001": "blocked repeatedly",
    "R2002": "port scan",
    "R2003": "service sweep",
    "R2004": "allowed despite blocks",
    "R2005": "password spray",
    "R2006": "multi-source logins",
    "R2007": "beaconing",
    "R3000": "high-risk app allowed",
    "R3001": "large transfer",
    "R3002": "malware-flagged",
    "R3003": "known-bad destination (allowed)",
    "R3004": "known-bad source (allowed)",
    "R3005": "known-bad destination (blocked)",
    "R3006": "known-bad source (blocked)",
}


# Each rule's level, as defined by the Sigma rules specification (see
# severity.py for the definitions quoted). This replaces the hand-picked
# 0-15 numbers the rules used to carry, which had no standard behind them.
# Ask of every new rule: on its own, without any other evidence, is this
# "rarely an incident" (low), "review regularly" (medium) or "alert and
# review promptly" (high)? Nothing here is critical - see severity.py.
RULE_LEVEL: dict[str, str] = {
    # One successful login or one TCP connection is what normal use looks
    # like; they exist to give the other rules context.
    "R1001": "informational",
    "R1003": "informational",
    # A listed scanner the perimeter refused: the firewall doing its job,
    # kept only so its hit rate stays visible.
    "R3006": "informational",
    # Single failures, typos and password changes happen every day; they
    # matter in volume, which is what R2000/R2005 measure.
    "R1000": "low",
    "R1002": "low",
    "R1004": "low",
    # Scanning that the firewall refused: the internet does this to every
    # public address all day, but a sustained sweep is still worth a look.
    "R2001": "low",
    "R2002": "low",
    "R2003": "low",
    # A real attack attempt, but nothing says it worked yet.
    "R2000": "medium",
    "R2005": "medium",
    "R3005": "medium",
    # Risky or unusual on their own, and each has a common innocent reading:
    # a high-risk app a user is allowed to run, a backup upload, a scanner
    # the policy happened to let through.
    "R3000": "medium",
    "R3001": "medium",
    "R3004": "medium",
    # Evidence that something crossed the perimeter or is talking out:
    # each one deserves an alert and a prompt look.
    "R2004": "high",
    "R2006": "high",
    "R2007": "high",
    "R3002": "high",
    "R3003": "high",
}


def apply_rules(con: duckdb.DuckDBPyConnection, on_rule=None) -> dict[str, int]:
    """Runs every rule against the case's raw_events, filling findings.
    Returns {rule_id: rows_matched} so the pipeline can log/report it.
    `on_rule(done, total)` is called after each rule, for progress (FR-2.5)."""
    matched: dict[str, int] = {}
    for i, (rid, sql) in enumerate(RULES, 1):
        before = con.execute("SELECT count(*) FROM findings").fetchone()[0]
        con.execute(sql)
        after = con.execute("SELECT count(*) FROM findings").fetchone()[0]
        if after > before:
            matched[rid] = after - before
        if on_rule:
            on_rule(i, len(RULES))

    whens = " ".join(f"WHEN '{rid}' THEN {WEIGHT[lvl]}" for rid, lvl in RULE_LEVEL.items())
    con.execute(f"UPDATE findings SET lvl = CASE rid {whens} ELSE {WEIGHT['low']} END")
    # A refused connection never crossed the intrusion boundary (ODNI CTF:
    # Engagement, not Presence), so no rule can make it a prompt-review
    # alert - a C2 beacon denied every time is an attempt, not a channel.
    con.execute(
        f"""
        UPDATE findings SET lvl = {WEIGHT['medium']}
        FROM raw_events r
        WHERE findings.row_id = r.row_id
          AND findings.lvl > {WEIGHT['medium']}
          AND r.verdict IN {DENY_VERDICTS}
        """
    )
    return matched
