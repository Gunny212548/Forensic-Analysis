"""Microsoft Windows rules (specs/windows_rules.md, story 5a: sign-ins).

Read from the Security log as Windows writes it (`win_events.data`, the event's
own items - winevent.py), not from the timeline columns: a sign-in's outcome is
its status code, and the same attempt is often logged twice.

**One attempt, however many events record it** (W-D4, Q84). A domain account's
failed sign-in can show as a 4625 on the host it was tried against *and* a 4771
(Kerberos) or 4776 (NTLM) on the domain controller that checked the password;
on a DC a spray against domain accounts is mostly 4771 / 4776. Counted, from
each event's Microsoft page (SOURCES.md, read 2026-10-26):

  failure  4625 Status / SubStatus 0xC000006A (bad password) or 0xC0000064
           (unknown user name); 4771 Failure Code 0x18 (PREAUTH_FAILED, "the wrong
           password") or 0x6 (client unknown); 4776 Error Code 0xC000006A /
           0xC0000064 - the analytics name failures "for valid or invalid users"
  success  4624 of an interactive, network, unlock, remote-interactive or cached
           logon (types 2, 3, 7, 10, 11); 4768 / 4776 with status 0x0

A 4771 / 4776 / 4768 within one second of a 4625 / 4624 for the same account
and outcome is the same attempt seen by the DC: it joins that attempt instead
of counting again (an internal method, stated). Its address is kept when the
host's own event has none (an interactive failure is logged at 127.0.0.1).

**The source of an attempt** is its address (`IpAddress`, the `::ffff:` IPv4
form read as IPv4); else, for a 4776, which carries no address, the Source
Workstation name; else the host itself - someone at its console. A finding says
which.

The lines (D16): B1 on the evidence's own sign-in episodes that ended in a
success (Javed & Paxson §3.1, Q66), B3 on the accounts' failures that ended in a
success, B2 TRW over accounts instead of hosts - each in lines.py. The time a
window is open is the analytics' and Javed's hour.

Not here (specs/windows_rules.md): a failed 4768 (a TGT request refused -
its page not read for its failure codes yet); low-and-slow guessing over days (B5 - no rule
yet), and everything on a host other than sign-ins (story 5b: lateral movement,
host activity; 5c: Sysmon network).
"""

from . import lines

PRODUCT = "windows"

BAD_PASSWORD = ("0xc000006a", "0xc0000064")   # 4625 / 4776, lower case as Windows writes them
KERBEROS_FAILED = ("0x18", "0x6")             # 4771
SUCCESS_LOGON_TYPES = ("2", "3", "7", "10", "11")
LOOPBACK = ("", "-", "127.0.0.1", "::1")
MIN_FAILURES = 2   # B1: one failed sign-in is an event, not guessing (D14)
MIN_SOURCES = 2    # B3: "from one or more remote IPs" - several, so at least two

_ATTEMPTS = f"""
CREATE OR REPLACE TEMP TABLE win_attempts AS
WITH ev AS (
  SELECT e.row_id, e.ts, w.event_id, upper(split_part(w.computer, '.', 1)) AS host, w.data AS d
  FROM product_events e JOIN win_events w USING (row_id)
  WHERE w.event_id IN (4624, 4625, 4768, 4771, 4776) AND e.ts IS NOT NULL
),
a AS (
  SELECT row_id, ts, event_id, host,
         lower(regexp_replace(split_part(d['TargetUserName'], '@', 1), '^.*\\\\', '')) AS account,
         CASE
           WHEN event_id = 4625 AND (lower(d['SubStatus']) IN {BAD_PASSWORD}
                                     OR lower(d['Status']) IN {BAD_PASSWORD}) THEN 'fail'
           WHEN event_id = 4771 AND lower(d['Status']) IN {KERBEROS_FAILED} THEN 'fail'
           WHEN event_id = 4776 AND lower(d['Status']) IN {BAD_PASSWORD} THEN 'fail'
           WHEN event_id = 4624 AND trim(d['LogonType']) IN {SUCCESS_LOGON_TYPES} THEN 'success'
           WHEN event_id IN (4768, 4776) AND lower(d['Status']) = '0x0' THEN 'success'
         END AS outcome,
         CASE WHEN regexp_replace(lower(trim(coalesce(d['IpAddress'], ''))), '^::ffff:', '')
                   NOT IN {LOOPBACK}
              THEN regexp_replace(lower(trim(d['IpAddress'])), '^::ffff:', '') END AS addr,
         CASE WHEN event_id = 4776 THEN nullif(upper(trim(d['Workstation'])), '') END AS workstation
  FROM ev
),
k AS (SELECT * FROM a WHERE outcome IS NOT NULL AND account NOT IN ('', '-')),
-- The DC's view of an attempt the host also logged: same account and outcome, within a second.
dup AS (
  SELECT s.row_id AS dup_id, arg_min(p.row_id, abs(epoch(p.ts) - epoch(s.ts))) AS prim_id
  FROM k s JOIN k p ON p.event_id IN (4624, 4625) AND s.event_id IN (4768, 4771, 4776)
                   AND p.account = s.account AND p.outcome = s.outcome
                   AND p.ts BETWEEN s.ts - INTERVAL 1 SECOND AND s.ts + INTERVAL 1 SECOND
  GROUP BY s.row_id
),
member AS (
  SELECT k.*, coalesce(dup.prim_id, k.row_id) AS attempt_id
  FROM k LEFT JOIN dup ON dup.dup_id = k.row_id
)
SELECT attempt_id, min(ts) AS ts, any_value(account) AS account, any_value(outcome) AS outcome,
       coalesce(arg_min(addr, CASE WHEN row_id = attempt_id THEN 0 ELSE 1 END) FILTER (WHERE addr IS NOT NULL),
                any_value(workstation) FILTER (WHERE workstation IS NOT NULL),
                any_value(host) FILTER (WHERE row_id = attempt_id)) AS source,
       CASE WHEN count(addr) > 0 THEN 'address'
            WHEN count(workstation) > 0 THEN 'workstation' ELSE 'console' END AS source_kind,
       list(row_id ORDER BY row_id) AS rows
FROM member GROUP BY attempt_id
"""

_ATTEMPT_ROWS = """
CREATE OR REPLACE TEMP TABLE win_attempt_rows AS
SELECT attempt_id, unnest(rows) AS row_id FROM win_attempts
"""


def _attempts(con) -> None:
    con.execute(_ATTEMPTS)
    con.execute(_ATTEMPT_ROWS)


def _params(rec: dict, unit: str) -> dict:
    if rec["method"] == "no-line":
        note = f"no line: {rec['members']} legitimate {unit}, minimum {rec['minimum']:g}"
    else:
        note = f"line above {rec['above']:g} and at least {rec['minimum']:g}, from {rec['members']} legitimate {unit}"
    return {"above": rec["above"], "minimum": rec["minimum"], "note": note}


# B1's legitimate members: each sign-in episode that ended in a success - the
# failures of that account from that source in the hour before the success and
# after its previous one (Q66). Only episodes with a failure in them: an episode
# of none says nothing about how often people mistype.
_EPISODES = """
WITH s AS (
  SELECT account, source, ts,
         lag(ts) OVER (PARTITION BY account, source ORDER BY ts) AS prev
  FROM win_attempts WHERE outcome = 'success'
)
SELECT count(*) AS v
FROM s JOIN win_attempts f
  ON f.outcome = 'fail' AND f.account = s.account AND f.source = s.source
 AND f.ts < s.ts AND f.ts >= s.ts - INTERVAL 1 HOUR AND (s.prev IS NULL OR f.ts > s.prev)
GROUP BY s.account, s.source, s.ts
"""

# B3's legitimate members: accounts (not computers), over the failures that were
# followed by a success of the same account from the same source within the hour
# - the owner's own mistypes; v = the most distinct such sources in any hour.
_OWNER_FAILURES = """
WITH f AS (
  SELECT f.* FROM win_attempts f
  WHERE f.outcome = 'fail' AND NOT f.account LIKE '%$'
    AND EXISTS (SELECT 1 FROM win_attempts s
                WHERE s.outcome = 'success' AND s.account = f.account AND s.source = f.source
                  AND s.ts > f.ts AND s.ts <= f.ts + INTERVAL 1 HOUR)
),
w AS (
  SELECT account, (SELECT count(DISTINCT g.source) FROM f g
                   WHERE g.account = f.account AND g.ts BETWEEN f.ts AND f.ts + INTERVAL 1 HOUR) AS n
  FROM f
)
SELECT max(n) AS v FROM w GROUP BY account
"""


def prepare_brute_1(con):
    _attempts(con)
    rec = lines.evidence_line(con, _EPISODES, MIN_FAILURES,
                              "sign-in episodes (account, source) that ended in a success; value = "
                              "failed attempts in the hour before the success")
    return _params(rec, "episodes"), rec


def prepare_brute_2(con):
    _attempts(con)
    # TRW over accounts (Jung et al. 2004 §4, adapted from hosts to accounts -
    # per_product_rules.md B2): each source's first attempt at each account it
    # tries is a success or a failure.
    con.execute("""
        CREATE OR REPLACE TEMP TABLE trw_win_accounts_walk AS
        WITH tried AS (
          SELECT source AS srcip, account, ts, attempt_id, outcome = 'fail' AS failed,
                 row_number() OVER (PARTITION BY source, account ORDER BY ts, attempt_id) AS k
          FROM win_attempts)
        SELECT srcip, account AS dstip, ts, failed,
               row_number() OVER (PARTITION BY srcip ORDER BY ts, attempt_id) AS n
        FROM tried WHERE k = 1""")
    rec = lines.decide(con, "trw_win_accounts")
    rec["population"] = "sign-in sources; target = each account a source tries (TRW on accounts)"
    return {}, rec


def prepare_brute_3(con):
    _attempts(con)
    rec = lines.evidence_line(con, _OWNER_FAILURES, MIN_SOURCES,
                              "accounts (computer accounts left out) whose failures were followed by a "
                              "success from the same source within the hour; value = most distinct "
                              "such sources in any hour")
    return _params(rec, "accounts"), rec


RULES: list[tuple[str, str]] = [
    # B1 password guessing: one account, one source, failures within an hour
    # (T1110.001, DET0551 AN1521-AN1523; Microsoft 4771 / 4776: many 0x18 /
    # 0xC000006A "in a short window" may indicate brute force).
    ("WIN-BRUTE-1", """
        INSERT INTO findings
        SELECT r.row_id, 'WIN-BRUTE-1', NULL,
               'Password guessing against ' || g.account || ' from ' || g.source_kind || ' ' || g.source ||
               ' (' || g.n || ' failed sign-ins within an hour; ' || $note || ')',
               ['T1110.001']
        FROM (
          WITH f AS (SELECT * FROM win_attempts WHERE outcome = 'fail'),
          w AS (SELECT attempt_id, account, source, ts,
                       count(*) OVER (PARTITION BY account, source ORDER BY ts
                           RANGE BETWEEN CURRENT ROW AND INTERVAL 1 HOUR FOLLOWING) AS n
                FROM f),
          hit AS (SELECT * FROM w WHERE n > $above AND n >= $minimum)
          SELECT f.attempt_id, f.account, f.source, any_value(f.source_kind) AS source_kind, max(h.n) AS n
          FROM f JOIN hit h ON h.account = f.account AND h.source = f.source
                           AND f.ts BETWEEN h.ts AND h.ts + INTERVAL 1 HOUR
          GROUP BY f.attempt_id, f.account, f.source) g
        JOIN win_attempt_rows r USING (attempt_id)
    """),
    # B2 password spraying: one source failing across many accounts - TRW over
    # accounts decides it (T1110.003, DET0487 AN1336 / AN1339).
    ("WIN-BRUTE-2", """
        INSERT INTO findings
        SELECT r.row_id, 'WIN-BRUTE-2', NULL,
               'Password spray from ' || a.source_kind || ' ' || a.source || ': TRW decided sprayer after ' ||
               t.n_decided || ' new accounts from ' || strftime(t.episode_start, '%Y-%m-%d %H:%M') ||
               ' (' || t.hosts || ' accounts tried in the evidence)',
               ['T1110.003']
        FROM win_attempts a
        JOIN trw_win_accounts t ON t.srcip = a.source AND t.decision = 'scanner'
        JOIN win_attempt_rows r USING (attempt_id)
        WHERE a.outcome = 'fail' AND a.ts >= t.episode_start
    """),
    # B3 one account failing from several sources within an hour - guessing
    # spread over many addresses (T1110.001, AN1521 "from one or more remote
    # IPs"). Computer accounts ("...$") left out: a machine signs in from its
    # own addresses.
    ("WIN-BRUTE-3", """
        INSERT INTO findings
        SELECT r.row_id, 'WIN-BRUTE-3', NULL,
               'Distributed guessing against ' || g.account || ' from ' || g.n ||
               ' sources within an hour (' || $note || ')',
               ['T1110.001']
        FROM (
          WITH f AS (SELECT * FROM win_attempts WHERE outcome = 'fail' AND NOT account LIKE '%$'),
          w AS (SELECT f.attempt_id, f.account, f.ts,
                       (SELECT count(DISTINCT g.source) FROM f g
                        WHERE g.account = f.account AND g.ts BETWEEN f.ts AND f.ts + INTERVAL 1 HOUR) AS n
                FROM f),
          hit AS (SELECT * FROM w WHERE n > $above AND n >= $minimum)
          SELECT f.attempt_id, f.account, max(h.n) AS n
          FROM f JOIN hit h ON h.account = f.account AND f.ts BETWEEN h.ts AND h.ts + INTERVAL 1 HOUR
          GROUP BY f.attempt_id, f.account) g
        JOIN win_attempt_rows r USING (attempt_id)
    """),
    # B4 failures, then a success: an account signed in from a source the rules
    # above flagged - for that account (guessing), or for any account the
    # sprayer tried (T1110 DET0463 AN1275 / AN1276, AN1522, AN1524). A pair that
    # signed in before the failures began is said to be likely the owner
    # (Javed & Paxson §4.2) - flagged all the same, the analyst decides.
    ("WIN-AUTH-1", """
        INSERT INTO findings
        SELECT r.row_id, 'WIN-AUTH-1', NULL,
               'Signed in as ' || s.account || ' from ' || s.source || ' after ' || p.rids ||
               ' flagged failures from that source' ||
               CASE WHEN EXISTS (SELECT 1 FROM win_attempts o
                                 WHERE o.outcome = 'success' AND o.account = s.account
                                   AND o.source = s.source AND o.ts < p.first_flag)
                    THEN ' - this account had signed in from this source before the failures began '
                         || '(likely the owner)'
                    ELSE '' END,
               ['T1078']
        FROM win_attempts s
        JOIN (SELECT a.source, a.account, min(a.ts) AS first_flag,
                     string_agg(DISTINCT f.rid, ', ' ORDER BY f.rid) AS rids,
                     bool_or(f.rid = 'WIN-BRUTE-2') AS spray
              FROM findings f
              JOIN win_attempt_rows ar ON ar.row_id = f.row_id
              JOIN win_attempts a ON a.attempt_id = ar.attempt_id
              WHERE f.rid IN ('WIN-BRUTE-1', 'WIN-BRUTE-2', 'WIN-BRUTE-3')
              GROUP BY a.source, a.account) p
          ON p.source = s.source AND (p.account = s.account OR p.spray)
        JOIN win_attempt_rows r ON r.attempt_id = s.attempt_id
        WHERE s.outcome = 'success' AND s.ts > p.first_flag
        QUALIFY row_number() OVER (PARTITION BY r.row_id ORDER BY p.first_flag) = 1
    """),
]

# WIN-AUTH-1 reads the attempts the BRUTE rules' preparation built, and their findings.
PREPARE = {"WIN-BRUTE-1": prepare_brute_1, "WIN-BRUTE-2": prepare_brute_2,
           "WIN-BRUTE-3": prepare_brute_3}
LEVEL = {"WIN-BRUTE-1": "medium", "WIN-BRUTE-2": "medium", "WIN-BRUTE-3": "medium",
         "WIN-AUTH-1": "high"}
LABELS = {"WIN-BRUTE-1": "password guessing", "WIN-BRUTE-2": "password spray",
          "WIN-BRUTE-3": "distributed guessing", "WIN-AUTH-1": "login after failures"}
FAMILY = {r: "R2" for r in LEVEL}
EQUIVALENT = {"WIN-BRUTE-1": "R2000", "WIN-BRUTE-2": "R2009", "WIN-BRUTE-3": "R2005",
              "WIN-AUTH-1": "R2008"}
# The generic sign-in rules stop on Windows rows. R2006 (one account, many
# sources succeeding within an hour) goes with them: on Windows it flagged a
# domain controller's own machine account signing in from its addresses.
SUPERSEDES = ("R2000", "R2005", "R2006", "R2008", "R2009")
FROM_GENERIC: tuple = ()
