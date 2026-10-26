"""Microsoft Windows rules (specs/windows_rules.md, stories 5a sign-ins, 5b lateral movement and host activity).

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

**Lateral movement and host activity (story 5b) link by the session, not by a
clock** (W-D2, Q82). A 4624's `TargetLogonId` is the `SubjectLogonId` of every
4688 / 4697 / 4698 that logon session causes on that host, and Sysmon 1's
`LogonId` the same value; a Sysmon process is its `ProcessGuid`, which a Sysmon 10
names `SourceProcessGUID`. A logon id is unique on a host until it restarts, so an
event belongs to the latest 4624 of that id on that host before it (ASOF JOIN).
Each sequence is an ATT&CK analytic's (SOURCES.md, read 2026-10-26); none needs a
window or a number.

Not here (specs/windows_rules.md): a failed 4768 (a TGT request refused -
its page not read for its failure codes yet); low-and-slow guessing over days (B5 - no rule
yet); a sequence across two hosts (AN1468's share access on the target, 5140 /
5145 - not read yet); Sysmon network (story 5c).
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

HOST = "upper(split_part(w.computer, '.', 1))"
SECURITY = "Microsoft-Windows-Security-Auditing"
SYSMON = "Microsoft-Windows-Sysmon"
STRONG_TICKETS = ("0x11", "0x12")   # 4769: "monitor for a Ticket Encryption Type other than 0x11 and 0x12"
SYSTEM_SESSIONS = ("0x3e7", "0x3e4", "0x3e5", "0x0")   # SYSTEM, NETWORK SERVICE, LOCAL SERVICE, none
MIN_SERVICES = 2   # Kerberoasting: one weak ticket is an event (a legacy application) - several services


def _addr(expr: str) -> str:
    return (f"CASE WHEN regexp_replace(lower(trim(coalesce({expr}, ''))), '^::ffff:', '') NOT IN {LOOPBACK} "
            f"THEN regexp_replace(lower(trim({expr})), '^::ffff:', '') END")


def _account(expr: str) -> str:
    return f"lower(regexp_replace(split_part({expr}, '@', 1), '^.*\\\\', ''))"


# Every logon session (4624) and what was done in it: processes (4688, Sysmon 1),
# services and scheduled tasks (4697, 4698), each joined to its session.
_SESSIONS = f"""
CREATE OR REPLACE TEMP TABLE win_logons AS
SELECT e.row_id, e.ts, {HOST} AS host, lower(trim(w.data['TargetLogonId'])) AS lid,
       {_account("w.data['TargetUserName']")} AS account, trim(w.data['LogonType']) AS ltype,
       {_addr("w.data['IpAddress']")} AS source,
       upper(trim(coalesce(w.data['AuthenticationPackageName'], ''))) AS pkg
FROM product_events e JOIN win_events w USING (row_id)
WHERE w.provider = '{SECURITY}' AND w.event_id = 4624 AND e.ts IS NOT NULL;

CREATE OR REPLACE TEMP TABLE win_session_acts AS
WITH x AS (
  SELECT e.row_id, e.ts, {HOST} AS host, w.event_id,
         lower(trim(CASE WHEN w.provider = '{SYSMON}' THEN w.data['LogonId'] ELSE w.data['SubjectLogonId'] END)) AS lid,
         coalesce(e.program, w.data['ServiceName'], w.data['TaskName']) AS what
  FROM product_events e JOIN win_events w USING (row_id)
  WHERE e.ts IS NOT NULL
    AND ((w.provider = '{SECURITY}' AND w.event_id IN (4688, 4697, 4698))
         OR (w.provider = '{SYSMON}' AND w.event_id = 1)))
SELECT x.*, l.row_id AS logon_row
FROM x ASOF JOIN win_logons l ON x.host = l.host AND x.lid = l.lid AND x.ts >= l.ts
WHERE x.lid NOT IN {SYSTEM_SESSIONS};
"""


def prepare_sessions(con):
    con.execute(_SESSIONS)
    return {}, None


# Kerberoasting's legitimate members: each account's most distinct services asked
# for in any hour with strong (AES) tickets only - the weak-ticket requests, the
# behaviour, are not among them (Q70). Computer accounts' services ("...$") and
# krbtgt left out: roasting targets the service accounts of people.
_TICKETS = f"""
SELECT e.row_id, e.ts, {_account("w.data['TargetUserName']")} AS account,
       lower(trim(w.data['ServiceName'])) AS svc, lower(trim(w.data['TicketEncryptionType'])) AS etype
FROM product_events e JOIN win_events w USING (row_id)
WHERE w.provider = '{SECURITY}' AND w.event_id = 4769 AND lower(trim(w.data['Status'])) = '0x0'
  AND e.ts IS NOT NULL AND NOT lower(trim(w.data['ServiceName'])) LIKE '%$'
  AND NOT lower(trim(w.data['ServiceName'])) LIKE 'krbtgt%'
"""
_STRONG_HOURS = f"""
WITH t AS ({_TICKETS}),
s AS (SELECT account, count(DISTINCT svc) OVER (PARTITION BY account ORDER BY ts
          RANGE BETWEEN CURRENT ROW AND INTERVAL 1 HOUR FOLLOWING) AS n
      FROM t WHERE etype IN {STRONG_TICKETS})
SELECT max(n) AS v FROM s GROUP BY account
"""


def prepare_host_1(con):
    rec = lines.evidence_line(con, _STRONG_HOURS, MIN_SERVICES,
                              "accounts asking for service tickets with AES only; value = most distinct "
                              "services (not computers, not krbtgt) asked for in any hour")
    return _params(rec, "accounts"), rec


RULES += [
    # RDP, then processes in that session, for a (source, account, host) seen on one
    # day of the evidence only (T1021.001 DET0327 AN0931 - its HostAccessPatterns:
    # "first-time source/destination pairs"; the user's choice of 2026-10-26). A
    # pair seen on two or more days is someone's habit.
    ("WIN-LAT-1", """
        INSERT INTO findings
        WITH l AS (SELECT * FROM win_logons WHERE ltype = '10' AND source IS NOT NULL),
        pd AS (SELECT source, account, host, count(DISTINCT CAST(ts AS DATE)) AS days FROM l GROUP BY ALL),
        span AS (SELECT count(DISTINCT CAST(ts AS DATE)) AS days FROM win_logons),
        p AS (SELECT logon_row, string_agg(DISTINCT what, ', ' ORDER BY what) AS progs
              FROM win_session_acts WHERE event_id IN (4688, 1) GROUP BY logon_row),
        hit AS (SELECT l.*, p.progs FROM l JOIN p ON p.logon_row = l.row_id
                JOIN pd USING (source, account, host) WHERE pd.days = 1),
        r AS (SELECT row_id, row_id AS logon_row FROM win_logons
              UNION ALL SELECT row_id, logon_row FROM win_session_acts)
        SELECT r.row_id, 'WIN-LAT-1', NULL,
               'RDP to ' || hit.host || ' as ' || hit.account || ' from ' || hit.source ||
               ' - a pair seen on 1 of the ' || span.days || ' days of the evidence - then ran: ' || hit.progs,
               ['T1021.001']
        FROM hit CROSS JOIN span JOIN r ON r.logon_row = hit.row_id
    """),
    # A network logon, then a service or a scheduled task created in that session -
    # PsExec's shape (T1021.002 DET0530 AN1468 "remote service creation, task
    # scheduling"; a service: T1569.002 DET0421 AN1185, PsExec "creating temporary
    # services").
    ("WIN-LAT-2", """
        INSERT INTO findings
        WITH a AS (SELECT a.*, l.account, l.source FROM win_session_acts a
                   JOIN win_logons l ON l.row_id = a.logon_row
                   WHERE a.event_id IN (4697, 4698) AND l.ltype = '3'),
        r AS (SELECT row_id, row_id AS act FROM a UNION ALL SELECT logon_row, row_id FROM a)
        SELECT DISTINCT r.row_id, 'WIN-LAT-2', NULL,
               'Network logon to ' || a.host || ' as ' || a.account || ' from ' || coalesce(a.source, '?') ||
               ', then ' || CASE a.event_id WHEN 4697 THEN 'service' ELSE 'scheduled task' END || ' "' ||
               a.what || '" created in that session',
               ['T1021.002'] || CASE WHEN a.event_id = 4697 THEN ['T1569.002'] ELSE []::VARCHAR[] END
        FROM a JOIN r ON r.act = a.row_id
    """),
    # An NTLM network logon for an account that uses Kerberos in this evidence, but
    # never from this source - "NTLM LogonType 3 authentications with no
    # accompanying domain logon events" (T1550.002 DET0409 AN1144). Needs the
    # domain controller's 4768 / 4769 in the case; an account with no Kerberos at
    # all (a scanner signing in to a share) is not anomalous by this test.
    ("WIN-LAT-3", f"""
        INSERT INTO findings
        WITH k AS (SELECT DISTINCT {_account("w.data['TargetUserName']")} AS account,
                          {_addr("w.data['IpAddress']")} AS source
                   FROM product_events e JOIN win_events w USING (row_id)
                   WHERE w.provider = '{SECURITY}' AND w.event_id IN (4768, 4769)
                     AND lower(trim(w.data['Status'])) = '0x0'),
        ka AS (SELECT DISTINCT account FROM k)
        SELECT l.row_id, 'WIN-LAT-3', NULL,
               'NTLM network logon to ' || l.host || ' as ' || l.account || ' from ' || l.source ||
               ' - the account uses Kerberos in this evidence, never from this source (possible pass-the-hash)',
               ['T1550.002']
        FROM win_logons l JOIN ka USING (account)
        WHERE l.ltype = '3' AND l.pkg = 'NTLM' AND l.source IS NOT NULL
          AND NOT l.account LIKE '%$' AND l.account <> 'anonymous logon'
          AND NOT EXISTS (SELECT 1 FROM k WHERE k.account = l.account AND k.source = l.source)
    """),
    # Kerberoasting: one account asking for weak-encryption service tickets for
    # several services within an hour (T1558.003 DET0157 AN0444, "an unusual number
    # of service tickets in a short period"; 4769: other than 0x11 / 0x12).
    ("WIN-HOST-1", f"""
        INSERT INTO findings
        SELECT * FROM (
          WITH t AS ({_TICKETS}),
          weak AS (SELECT *, count(DISTINCT svc) OVER (PARTITION BY account ORDER BY ts
                       RANGE BETWEEN CURRENT ROW AND INTERVAL 1 HOUR FOLLOWING) AS n
                   FROM t WHERE etype NOT IN {STRONG_TICKETS}),
          hit AS (SELECT * FROM weak WHERE n > $above AND n >= $minimum)
          SELECT w.row_id, 'WIN-HOST-1', NULL,
                 'Weak-encryption service tickets for ' || max(h.n) || ' services within an hour, asked by ' ||
                 w.account || ' (possible Kerberoasting; ' || $note || ')',
                 ['T1558.003']
          FROM weak w JOIN hit h ON h.account = w.account AND w.ts BETWEEN h.ts AND h.ts + INTERVAL 1 HOUR
          GROUP BY w.row_id, w.account)
    """),
    # LSASS dump: a process opens lsass.exe, then writes a file (T1003.001 DET0363
    # AN1030 - "then invokes memory dump, file creation"), joined by the process's
    # Sysmon GUID. Registry writes are left out: an antivirus reads lsass and writes
    # its own keys all day.
    ("WIN-HOST-2", f"""
        INSERT INTO findings
        WITH acc AS (SELECT e.row_id, e.ts, {HOST} AS host, lower(w.data['SourceProcessGUID']) AS g,
                            w.data['SourceImage'] AS img, w.data['GrantedAccess'] AS access
                     FROM product_events e JOIN win_events w USING (row_id)
                     WHERE w.provider = '{SYSMON}' AND w.event_id = 10
                       AND lower(w.data['TargetImage']) LIKE '%\\lsass.exe'),
        wr AS (SELECT e.row_id, e.ts, {HOST} AS host, lower(w.data['ProcessGuid']) AS g,
                      w.data['TargetFilename'] AS f
               FROM product_events e JOIN win_events w USING (row_id)
               WHERE w.provider = '{SYSMON}' AND w.event_id = 11),
        pairs AS (SELECT a.row_id AS arow, wr.row_id AS wrow, a.host, a.img, a.access, wr.f
                  FROM acc a JOIN wr ON wr.host = a.host AND wr.g = a.g AND wr.ts >= a.ts),
        r AS (SELECT arow AS row_id, arow, wrow FROM pairs UNION ALL SELECT wrow, arow, wrow FROM pairs)
        SELECT DISTINCT r.row_id, 'WIN-HOST-2', NULL,
               'LSASS opened by ' || p.img || ' (access ' || p.access || ') on ' || p.host ||
               ', which then wrote ' || p.f,
               ['T1003.001']
        FROM pairs p JOIN r ON r.arow = p.arow AND r.wrow = p.wrow
    """),
]

# WIN-AUTH-1 reads the attempts the BRUTE rules' preparation built, and their findings.
# WIN-LAT-2 / -3 read the sessions WIN-LAT-1's preparation built.
PREPARE = {"WIN-BRUTE-1": prepare_brute_1, "WIN-BRUTE-2": prepare_brute_2,
           "WIN-BRUTE-3": prepare_brute_3, "WIN-LAT-1": prepare_sessions, "WIN-HOST-1": prepare_host_1}
LEVEL = {"WIN-BRUTE-1": "medium", "WIN-BRUTE-2": "medium", "WIN-BRUTE-3": "medium",
         "WIN-AUTH-1": "high", "WIN-LAT-1": "medium", "WIN-LAT-2": "medium", "WIN-LAT-3": "high",
         "WIN-HOST-1": "high", "WIN-HOST-2": "high"}
LABELS = {"WIN-BRUTE-1": "password guessing", "WIN-BRUTE-2": "password spray",
          "WIN-BRUTE-3": "distributed guessing", "WIN-AUTH-1": "login after failures",
          "WIN-LAT-1": "uncommon RDP, then commands", "WIN-LAT-2": "remote service or task",
          "WIN-LAT-3": "NTLM without Kerberos", "WIN-HOST-1": "Kerberoasting", "WIN-HOST-2": "LSASS dump"}
# The sign-in rules count in the generic sign-in rules' family; a host behaviour has none to share.
FAMILY = {r: ("R2" if r.startswith(("WIN-BRUTE", "WIN-AUTH")) else r.split("-")[1]) for r in LEVEL}
EQUIVALENT = {"WIN-BRUTE-1": "R2000", "WIN-BRUTE-2": "R2009", "WIN-BRUTE-3": "R2005",
              "WIN-AUTH-1": "R2008"}
# The generic sign-in rules stop on Windows rows. R2006 (one account, many
# sources succeeding within an hour) goes with them: on Windows it flagged a
# domain controller's own machine account signing in from its addresses.
SUPERSEDES = ("R2000", "R2005", "R2006", "R2008", "R2009")
FROM_GENERIC: tuple = ()
