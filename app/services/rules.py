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
  R2xxx  correlation / aggregate
  R3xxx  single-event, network/firewall

What is a rule and what is not (specs/rules_review.md, the user's D12/D13 of
2026-10-20). A rule answers "does this fit a known attack pattern?" - layer B.
"What is this event?" (layer A) is the event's own `action` / `verdict`,
written by the log source profile; the former R1000-R1004 named exactly that
and made every login a finding to review, so they are gone. "Is it unusual
here?" (layer C) is a fact shown on the event (db.list_raw), never a finding;
R2001 (refused repeatedly), R3000 (the vendor's app risk) and R3006 (a listed
scanner refused) moved there. Their metadata stays in rule_meta.py, status
`deprecated`, so cases processed before still show what their findings were.

Correlation rules still count over the whole evidence item; time windows are
the next story (rules_review.md Q18, measured on our own data).
"""

import duckdb

from .products import PRODUCTS
from .severity import WEIGHT

DENY_VERDICTS = (
    "('deny', 'drop', 'block', 'blocked', 'reject', 'prevent', "
    "'reset-both', 'reset-client', 'reset-server', 'block-url')"
)

# A source counted as brute-forcing: R2000's condition, shared with R2008 so
# "login after brute force" can never disagree with what R2000 flagged.
BRUTE_FORCE_SOURCES = """
    SELECT srcip, count(*) AS n FROM raw_events
    WHERE action = 'auth_failed' AND srcip IS NOT NULL
    GROUP BY srcip HAVING count(*) >= 3
"""

# What R2007 treats as a public IPv4 destination - the same two expressions
# written into its SQL below, kept here so behaviour profiles (profiles.py)
# count "bytes to public addresses" over exactly the same ranges.
# tests/check_profiles.py fails if R2007's SQL stops containing them verbatim.
IPV4_RE = r"^[0-9]{1,3}(\.[0-9]{1,3}){3}$"
NON_PUBLIC_IPV4_RE = (r"^(0\.|10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|"
                      r"100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.|22[4-9]\.|23[0-9]\.|24[0-9]\.|25[0-5]\.)")

# R2009: distinct accounts one source failed against. Measured 2026-10-20 over
# every source with a failed sign-in in the store and in the Entra export
# KM23 (rules_review.md): all 71 sources in the customers' own logs failed
# against exactly 1 account; the recorded attacks reached 4 (both synthetic
# scenarios) and 31 (Splunk's Entra spray capture). 3 sits above everything
# ordinary that was seen and below every attack. 71 sources from two real
# files is a small sample, hence status experimental.
SPRAY_MIN_ACCOUNTS = 3

RULES: list[tuple[str, str]] = [
    # ---------- R2xxx: correlation ----------
    ("R2000", f"""
        INSERT INTO findings
        SELECT e.row_id, 'R2000', NULL,
               'Repeated brute-force from ' || e.srcip ||
               ' (' || a.n || ' attempts)',
               ['T1110.001']
        FROM raw_events e
        JOIN ({BRUTE_FORCE_SOURCES}) a ON e.srcip = a.srcip
        WHERE e.action = 'auth_failed'
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
    # from the logs alone, without knowing the firewall's rule semantics. The
    # ratio guard keeps ordinary users (a few blocked sites, lots of normal
    # browsing) from matching.
    # Untagged: it used to carry T1133, which ATT&CK defines as
    # "external-facing remote services ... such as VPNs, Citrix" - an allowed
    # connection is that only when the service is one, and nothing here knows
    # (rules_review.md). A policy observation, not an adversary technique.
    ("R2004", f"""
        INSERT INTO findings
        SELECT e.row_id, 'R2004', NULL,
               'Traffic ALLOWED from ' || e.srcip ||
               ' despite ' || a.denies || ' blocks from the same source (possible policy gap)',
               []::VARCHAR[]
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

    # Distributed guessing: one account, failures arriving from many different
    # sources. R2000 counts failures per *source* and cannot see this - in a
    # real Azure AD export 14 distinct IPv4/IPv6 addresses each failed
    # exactly once against the same account, so every per-source counter
    # stayed at 1 while the account was plainly under attack.
    # Was called "password spray" (T1110.003) until 2026-10-20; ATT&CK defines
    # spraying as "a small list of commonly used passwords against many
    # different accounts" - the opposite shape. Guessing one account's password
    # is T1110.001 ("systematically guess the password"). Spraying is R2009.
    ("R2005", """
        INSERT INTO findings
        SELECT e.row_id, 'R2005', NULL,
               'Distributed password guessing against ' || e.username || ' from ' ||
               a.n || ' distinct sources',
               ['T1110.001']
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

    # The login that followed the attack: a success for an account from a
    # source that had brute-forced it (R2000's sources) and failed on that
    # account earlier. This is "the attacker got in" - it used to exist only
    # as severity.py raising an R1001 login-success finding, and R1001 is no
    # longer a finding (layer A). Pairs on source *and* account, after the
    # first failure, for the reasons severity.py gives (the owner logging in
    # from home while someone else attacks the account is not this).
    ("R2008", f"""
        INSERT INTO findings
        SELECT s.row_id, 'R2008', NULL,
               'Login succeeded for ' || s.username || ' from ' || s.srcip ||
               ' after ' || p.n || ' failed attempts from the same source',
               ['T1078']
        FROM raw_events s
        JOIN (SELECT f.srcip, f.username, min(f.ts) AS first_fail, count(*) AS n
              FROM raw_events f
              JOIN ({BRUTE_FORCE_SOURCES}) b ON f.srcip = b.srcip
              WHERE f.action = 'auth_failed' AND f.username IS NOT NULL
              GROUP BY f.srcip, f.username) p
          ON s.srcip = p.srcip AND s.username = p.username
        WHERE s.action = 'auth_success' AND s.ts > p.first_fail
    """),

    # Password spraying as ATT&CK T1110.003 defines it: one source failing
    # against many different accounts. A wrong password and a non-existent
    # account both count - trying names that do not exist is part of it.
    # Threshold measured, see SPRAY_MIN_ACCOUNTS. Accounts compared
    # case-insensitively: Entra reports "Joe@x" and "joe@x" as one person.
    ("R2009", f"""
        INSERT INTO findings
        SELECT e.row_id, 'R2009', NULL,
               'Password spray from ' || e.srcip || ' (' || a.n ||
               ' distinct accounts failed)',
               ['T1110.003']
        FROM raw_events e
        JOIN (SELECT srcip, count(DISTINCT lower(username)) AS n FROM raw_events
              WHERE action IN ('auth_failed', 'invalid_user')
                AND srcip IS NOT NULL AND username IS NOT NULL
              GROUP BY srcip
              HAVING count(DISTINCT lower(username)) >= {SPRAY_MIN_ACCOUNTS}) a
          ON e.srcip = a.srcip
        WHERE e.action IN ('auth_failed', 'invalid_user') AND e.username IS NOT NULL
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

    # (R3006, a listed source refused at the perimeter, is a layer C fact now:
    # db.list_raw shows the listing on the event.)

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
# graph (db.build_graph). The sign-in rules are deliberately protocol-neutral:
# they used to say "SSH" because auth.log was the only source, but CSV auth
# exports (Azure AD sign-ins) now set `action` too, and an SSH label on a web
# sign-in propagates straight into the AI narrative. The `descr` written into findings is a full
# sentence with IPs in it - far too long to sit on an edge - so keep a terse
# form here. Add one whenever you add a rule; a rule with no entry falls
# back to its id.
RULE_LABELS: dict[str, str] = {
    "R2000": "brute-force",
    "R2002": "port scan",
    "R2003": "service sweep",
    "R2004": "allowed despite blocks",
    "R2005": "distributed guessing",
    "R2006": "multi-source logins",
    "R2007": "beaconing",
    "R2008": "login after brute force",
    "R2009": "password spray",
    "R3001": "large transfer",
    "R3002": "malware-flagged",
    "R3003": "known-bad destination (allowed)",
    "R3004": "known-bad source (allowed)",
    "R3005": "known-bad destination (blocked)",
}


# Each rule's level, as defined by the Sigma rules specification (see
# severity.py for the definitions quoted). This replaces the hand-picked
# 0-15 numbers the rules used to carry, which had no standard behind them.
# Ask of every new rule: on its own, without any other evidence, is this
# "rarely an incident" (low), "review regularly" (medium) or "alert and
# review promptly" (high)? Nothing here is critical - see severity.py.
RULE_LEVEL: dict[str, str] = {
    # Scanning that the firewall refused: the internet does this to every
    # public address all day, but a sustained sweep is still worth a look.
    "R2002": "low",
    "R2003": "low",
    # A real attack attempt, but nothing says it worked yet.
    "R2000": "medium",
    "R2005": "medium",
    "R2009": "medium",
    "R3005": "medium",
    # Risky or unusual on their own, and each has a common innocent reading:
    # a backup upload, a scanner the policy happened to let through.
    "R3001": "medium",
    "R3004": "medium",
    # Evidence that something crossed the perimeter or is talking out:
    # each one deserves an alert and a prompt look.
    "R2004": "high",
    "R2006": "high",
    "R2007": "high",
    "R2008": "high",
    "R3002": "high",
    "R3003": "high",
}


# What a rule id looks like: a generic R-rule (R2000) or a product rule
# (PAN-SCAN-1, <PRODUCT>-<AREA>-<n>, specs/per_product_rules.md). For checking
# the shape of input; whether the rule exists is rule_meta's to say.
RULE_ID_PATTERN = r"(?:R\d{4}|[A-Z]{2,4}-[A-Z]{3,5}-\d{1,3})"

# The product a rule is written for (specs/per_product_rules.md, D11). Such a
# rule reads `product_events` - the rows of its product only - instead of
# raw_events, so it can never match another product's rows; it is skipped when
# the case holds none. A rule absent here is generic and reads every row: the
# R-rules, until story 4 retires them.
RULE_PRODUCT: dict[str, str] = {}

# The rule family confidence counts (confidence.py, gotcha #20): an R-rule's is
# its first two characters (R2 correlation / R3 network). A product rule is in
# the family of the generic rule it matches the same behaviour as, so a scan
# flagged by both R2002 and PAN-SCAN-1 is one family, not two - until story 4
# retires the generic rules and re-bases families.
RULE_FAMILY: dict[str, str] = {}


def family_sql(rid: str) -> str:
    """SQL for the family of the rule id expression `rid`."""
    whens = " ".join(f"WHEN '{r}' THEN '{f}'" for r, f in sorted(RULE_FAMILY.items()))
    return f"CASE {rid} {whens} ELSE substr({rid}, 1, 2) END" if whens else f"substr({rid}, 1, 2)"


# Story 4 (D13): a generic rule no longer runs on the rows of a product whose
# own rules match the same behaviour - generic rule id -> those products. It
# still runs on every other row (FortiGate, ESXi, sshd, Entra, Windows), which
# have no rule set of their own yet. Filled from the product modules below.
RULE_SUPERSEDED: dict[str, set[str]] = {}

# A product rule -> the generic rule matching the same behaviour, for whatever
# counts behaviours rather than rule ids (escalation patterns, VERIS actions).
RULE_EQUIVALENT: dict[str, str] = {}


def generic_sql(rid: str) -> str:
    """SQL for the generic rule id that the rule id expression `rid` stands for."""
    whens = " ".join(f"WHEN '{r}' THEN '{g}'" for r, g in sorted(RULE_EQUIVALENT.items()))
    return f"CASE {rid} {whens} ELSE {rid} END" if whens else rid


# A rule that draws a line (lines.py, D16): run before its SQL, it returns the
# SQL's named parameters ($above, $minimum) and the line's record, which the
# case keeps (apply_rules' `lines`).
RULE_PREPARE: dict = {}


def apply_rules(con: duckdb.DuckDBPyConnection, on_rule=None, rules=None,
                rule_product=None, lines: dict | None = None,
                rule_superseded=None) -> dict[str, int]:
    """Runs every rule against the case's raw_events, filling findings.
    Returns {rule_id: rows_matched} so the pipeline can log/report it.
    `on_rule(done, total)` is called after each rule, for progress (FR-2.5).
    `lines`, when given, receives each line-drawing rule's record.
    `rules` / `rule_product` / `rule_superseded` replace the module's (tests)."""
    rules = RULES if rules is None else rules
    rule_product = RULE_PRODUCT if rule_product is None else rule_product
    rule_superseded = RULE_SUPERSEDED if rule_superseded is None else rule_superseded
    present = _products_present(con)
    matched: dict[str, int] = {}
    for i, (rid, sql) in enumerate(rules, 1):
        product = rule_product.get(rid)
        if product is not None:
            if product not in present:
                if on_rule:
                    on_rule(i, len(rules))
                continue
            # The value is one of products.PRODUCTS' ids (checked), never input.
            con.execute("CREATE OR REPLACE TEMP VIEW product_events AS "
                        f"SELECT * FROM raw_events WHERE product = '{_product_id(product)}'")
        elif present & rule_superseded.get(rid, set()):
            # A generic rule on every row but the superseding products' (story 4).
            out = ", ".join(f"'{_product_id(p)}'" for p in sorted(rule_superseded[rid]))
            con.execute("CREATE OR REPLACE TEMP VIEW generic_events AS SELECT * FROM raw_events "
                        f"WHERE product IS NULL OR product NOT IN ({out})")
            sql = sql.replace("raw_events", "generic_events")
        params = None
        if rid in RULE_PREPARE:
            params, record = RULE_PREPARE[rid](con)
            # A preparation that draws no line (it builds tables) returns no record.
            if lines is not None and record is not None:
                lines[rid] = record
        before = con.execute("SELECT count(*) FROM findings").fetchone()[0]
        con.execute(sql, params or None)
        after = con.execute("SELECT count(*) FROM findings").fetchone()[0]
        if after > before:
            matched[rid] = after - before
        if on_rule:
            on_rule(i, len(rules))

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


def _product_id(product: str) -> str:
    if product not in PRODUCTS:
        raise ValueError(f"unknown product {product!r}")
    return product


def _products_present(con: duckdb.DuckDBPyConnection) -> set[str]:
    """The products of the case's rows; empty for a store from before the
    product column (pipeline.mark_products)."""
    cols = {r[0] for r in con.execute("DESCRIBE raw_events").fetchall()}
    if "product" not in cols:
        return set()
    return {r[0] for r in con.execute(
        "SELECT DISTINCT product FROM raw_events WHERE product IS NOT NULL").fetchall()}


# Product rule sets (D11), after everything above they import. They run after
# the generic rules, which stay until story 4 retires them.
from . import rules_checkpoint, rules_firewall, rules_paloalto, rules_windows  # noqa: E402

_GENERIC = dict(RULES)
for _mod in (rules_paloalto, rules_checkpoint, rules_windows):
    for _rid, _sql in _mod.RULES + rules_firewall.from_generic(_mod.FROM_GENERIC, _GENERIC):
        RULES.append((_rid, _sql))
        RULE_PRODUCT[_rid] = _mod.PRODUCT
    RULE_PREPARE.update(_mod.PREPARE)
    RULE_FAMILY.update(_mod.FAMILY)
    RULE_EQUIVALENT.update(_mod.EQUIVALENT)
    for _generic in _mod.SUPERSEDES:
        RULE_SUPERSEDED.setdefault(_generic, set()).add(_mod.PRODUCT)
    RULE_LEVEL.update(_mod.LEVEL)
    RULE_LABELS.update(_mod.LABELS)
