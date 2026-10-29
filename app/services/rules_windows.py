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
           0xC0000064; 4768 Result Code 0x6 ("The username doesn't exist", story
           5d) - the analytics name failures "for valid or invalid users"
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

Story 5d (specs/windows_rules.md W-D5..W-D9): low-and-slow guessing (B5) by Javed &
Paxson's CUSUM over the site's failures per 100 attempts, then who took part
(WIN-BRUTE-4); an RDP reconnect (4778) starts a session for WIN-LAT-1; ADMIN$ / C$
opened (5140) in WIN-LAT-2's session, and a file written there (5145) then run
(WIN-LAT-4). Not here: the source host's side of a share access (it needs a time
window); System 7045 (no Microsoft page found - not typed).
"""

import math

from . import lines
from .rules import IPV4_RE, NON_PUBLIC_IPV4_RE
from .severity import WEIGHT

PRODUCT = "windows"

BAD_PASSWORD = ("0xc000006a", "0xc0000064")   # 4625 / 4776, lower case as Windows writes them
KERBEROS_FAILED = ("0x18", "0x6")             # 4771
# 4768: 0x6 "The username doesn't exist"; 0x18 cannot occur in it (4771 carries a wrong
# password). 0x12 (disabled, expired, locked out) and 0x17 (password expired) are refusals,
# not guesses - Timeline events (W-D6, Q89).
TGT_UNKNOWN_USER = "0x6"
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
           WHEN event_id = 4768 AND lower(d['Status']) = '{TGT_UNKNOWN_USER}' THEN 'fail'
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


B5_DELTA = 1   # the shift to detect: one more failure per 100 attempts (Q88; the paper's 10 never sees W3)


def prepare_brute_4(con):
    """B5 low-and-slow (W-D5, Q88): Javed & Paxson's site analyzer over the case's attempts.
    Writes TEMP TABLE win_b5_epochs (epoch, first_event, last_event, start_ts, end_ts) - the
    coordinated attack epochs - and win_b5_attempts (attempt_id, event_no)."""
    _attempts(con)
    n, delta = lines.CUSUM_N, B5_DELTA
    # The paper runs on data "filtered to remove high-rate brute-forcers that can be detected
    # pointwise" (§3.1, Fig. 5, footnote 3): the attempts WIN-BRUTE-1..3 flagged are left out.
    att = con.execute("""
        SELECT attempt_id, ts, source, outcome = 'fail' FROM win_attempts a
        WHERE NOT EXISTS (SELECT 1 FROM findings f JOIN win_attempt_rows r ON r.row_id = f.row_id
                          WHERE r.attempt_id = a.attempt_id
                            AND f.rid IN ('WIN-BRUTE-1', 'WIN-BRUTE-2', 'WIN-BRUTE-3'))
        ORDER BY ts, attempt_id""").fetchall()
    # §5's cleaning: sources that never succeed, and sources failing >= 95% of >= 20 attempts.
    per = {}
    for _, _, src, failed in att:
        f, t = per.get(src, (0, 0))
        per[src] = (f + failed, t + 1)
    dropped = {s for s, (f, t) in per.items() if f == t or (t >= 20 and f / t >= 0.95)}
    # ... and automations (§5): a source's attempts in a 3-day window, when there are >= 50 and
    # their clock is not a person's - a job with a stale password is a misconfigured automation.
    t0 = att[0][1] if att else None
    windows = {}
    for a in att:
        windows.setdefault((a[2], (a[1] - t0).days // lines.AUTOMATION_WINDOW_DAYS), []).append(a[1])
    machine = {k for k, ts in windows.items() if len(ts) >= lines.AUTOMATION_MIN and lines.automated(ts)}
    clean = [a[3] for a in att if a[2] not in dropped
             and (a[2], (a[1] - t0).days // lines.AUTOMATION_WINDOW_DAYS) not in machine]
    ys_clean = [sum(clean[i:i + n]) for i in range(0, len(clean) - n + 1, n)]
    events = len(att) // n
    rec = {"method": "cusum", "source": lines.CUSUM_SOURCE, "attempts": len(att), "events": events,
           "normal_events": len(ys_clean), "sources_left_out_of_normal": len(dropped),
           "automation_windows_left_out_of_normal": len(machine),
           "parameters": {"n": n, "delta": delta, "in_control_arl_target": lines.CUSUM_ARL}}
    con.execute("CREATE OR REPLACE TEMP TABLE win_b5_epochs (epoch INT, first_event INT, last_event INT, "
                "start_ts TIMESTAMP, end_ts TIMESTAMP)")
    con.execute("CREATE OR REPLACE TEMP TABLE win_b5_attempts AS "
                "SELECT unnest($1::BIGINT[]) AS attempt_id, unnest($2::INT[]) AS event_no",
                [[a[0] for a in att[:events * n]], [i // n for i in range(events * n)]])
    if len(ys_clean) < lines.MIN_LEGIT:
        rec.update(note=f"{len(ys_clean)} events of {n} ordinary attempts - under {lines.MIN_LEGIT}, "
                        "the normal failure rate cannot be modelled; not run", epochs=0)
        return {"note": rec["note"]}, rec
    fit = lines.beta_binomial(ys_clean, n)
    mu = fit["mean"]
    m = lines.CUSUM_SCALE
    c = max(1, round(m * (mu + delta / 2)))   # m (mu + k), k = delta / 2 to the nearest 1/m (§4.1)
    h, arl_in = lines.cusum_h(fit["pmf"], c, m)
    arl_out = lines.cusum_arl(fit["pmf"], c - m * delta, h, m)
    back = 0 if math.isinf(arl_out) else max(0, round(arl_out) - 1)
    ys = [sum(a[3] for a in att[i * n:(i + 1) * n]) for i in range(events)]
    _, runs = lines.cusum_run(ys, mu, c, h, m)
    epochs = []
    for first, last in runs:
        first = max(0, first - back)
        if epochs and first <= epochs[-1][1] + 1:
            epochs[-1] = (epochs[-1][0], last)
        else:
            epochs.append((first, last))
    # §4.1's singleton filter: still alarming without the source of most failures in the epoch?
    kept = []
    for first, last in epochs:
        fails = {}
        for a in att[first * n:(last + 1) * n]:
            if a[3]:
                fails[a[2]] = fails.get(a[2], 0) + 1
        top = max(fails, key=fails.get)
        ys_minus = [sum(a[3] and a[2] != top for a in att[i * n:(i + 1) * n]) for i in range(events)]
        flags, _ = lines.cusum_run(ys_minus, mu, c, h, m)
        if any(flags[first:last + 1]):
            kept.append((first, last))
    if kept:
        con.execute("INSERT INTO win_b5_epochs SELECT unnest($1::INT[]), unnest($2::INT[]), unnest($3::INT[]), "
                    "unnest($4::TIMESTAMP[]), unnest($5::TIMESTAMP[])",
                    [list(range(1, len(kept) + 1)), [f for f, _ in kept], [l for _, l in kept],
                     [att[f * n][1] for f, _ in kept], [att[(l + 1) * n - 1][1] for _, l in kept]])
    note = (f"CUSUM over failures per {n} attempts: normal mean {mu:.2f} from {len(ys_clean)} events "
            f"({fit['fit']}), k = {c / m - mu:.2f}, H = {h / m:g} (in-control ARL {arl_in:.0f} events)")
    rec.update(fit=fit["fit"], mean=round(mu, 4), var=round(fit["var"], 4), rho=round(fit["rho"], 4),
               k=round(c / m - mu, 4), H=h / m, in_control_arl=None if math.isinf(arl_in) else round(arl_in, 1),
               out_of_control_arl=None if math.isinf(arl_out) else round(arl_out, 2),
               epochs=len(kept), singleton_epochs=len(epochs) - len(kept), note=note)
    return {"note": note}, rec


RULES: list[tuple[str, str]] = [
    # B1 password guessing: one account, one source, failures within an hour
    # (T1110.001, DET0551 AN1521-AN1523; Microsoft 4771 / 4776: many 0x18 /
    # 0xC000006A "in a short window" may indicate brute force).
    ("WIN-BRUTE-1", """
        INSERT INTO findings
        SELECT r.row_id, 'WIN-BRUTE-1', NULL,
               'Password guessing against ' || g.account || ' from ' || g.source_kind || ' ' || g.source ||
               ' (' || g.n || ' failed sign-ins within an hour; ' || $note || ')',
               ['T1110.001'], g.source, g.account
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
               ['T1110.003'], a.source, ''
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
               ['T1110.001'], '', g.account
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
    # B5 low-and-slow guessing (T1110.001; Javed & Paxson §4.1-4.2): the failed attempts of a
    # coordinated epoch whose (source, account) never signs in in the evidence, nor the source
    # as an account one letter away (a forgotten user name, §4.2). The paper finds the
    # "coordination glue" by hand: the analyst decides who took part.
    ("WIN-BRUTE-4", """
        INSERT INTO findings
        WITH ok AS (SELECT DISTINCT source, account FROM win_attempts WHERE outcome = 'success'),
        p AS (SELECT a.attempt_id, a.account, a.source, a.source_kind, e.epoch, e.start_ts, e.end_ts
              FROM win_attempts a JOIN win_b5_attempts b USING (attempt_id)
              JOIN win_b5_epochs e ON b.event_no BETWEEN e.first_event AND e.last_event
              WHERE a.outcome = 'fail'
                AND NOT EXISTS (SELECT 1 FROM ok WHERE ok.source = a.source
                                AND (ok.account = a.account OR levenshtein(ok.account, a.account) = 1))),
        s AS (SELECT epoch, count(*) AS n, count(DISTINCT source) AS sources, count(DISTINCT account) AS accounts
              FROM p GROUP BY epoch)
        SELECT r.row_id, 'WIN-BRUTE-4', NULL,
               'Low-and-slow guessing: failed sign-in for ' || p.account || ' from ' || p.source_kind || ' ' ||
               p.source || ' during a site-wide rise in failures ' || strftime(p.start_ts, '%Y-%m-%d %H:%M') ||
               ' - ' || strftime(p.end_ts, '%Y-%m-%d %H:%M') || ' (' || s.n || ' such failures from ' ||
               s.sources || ' sources against ' || s.accounts || ' accounts; this pair never signed in; ' ||
               $note || ')',
               ['T1110.001'], '', p.account
        FROM p JOIN s USING (epoch) JOIN win_attempt_rows r USING (attempt_id)
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
               ['T1078'], s.source, s.account
        FROM win_attempts s
        JOIN (SELECT a.source, a.account, min(a.ts) AS first_flag,
                     string_agg(DISTINCT f.rid, ', ' ORDER BY f.rid) AS rids,
                     bool_or(f.rid = 'WIN-BRUTE-2') AS spray
              FROM findings f
              JOIN win_attempt_rows ar ON ar.row_id = f.row_id
              JOIN win_attempts a ON a.attempt_id = ar.attempt_id
              WHERE f.rid IN ('WIN-BRUTE-1', 'WIN-BRUTE-2', 'WIN-BRUTE-3')
              GROUP BY a.source, a.account) p
          ON p.source = s.source
         -- A sprayer's own computer account signs in from its address all day (W-D10, Q98):
         -- the spray branch leaves out computer accounts ("...$", Microsoft 4769).
         AND (p.account = s.account OR (p.spray AND coalesce(s.account, '') NOT LIKE '%$'))
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


def _admin_share(expr: str) -> str:
    # 5140 / 5145 write a share as \\*\ADMIN$; AN1468 names ADMIN$ and C$.
    return (f"(ends_with(upper(trim({expr})), '\\ADMIN$') "
            f"OR ends_with(upper(trim({expr})), '\\C$'))")


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
         coalesce(e.program, w.data['ServiceName'], w.data['TaskName'], w.data['ShareName']) AS what
  FROM product_events e JOIN win_events w USING (row_id)
  WHERE e.ts IS NOT NULL
    AND ((w.provider = '{SECURITY}' AND w.event_id IN (4688, 4697, 4698, 5140))
         OR (w.provider = '{SYSMON}' AND w.event_id = 1)))
SELECT x.*, l.row_id AS logon_row
FROM x ASOF JOIN win_logons l ON x.host = l.host AND x.lid = l.lid AND x.ts >= l.ts
WHERE x.lid NOT IN {SYSTEM_SESSIONS};

-- RDP sessions as they start: a RemoteInteractive logon (4624 type 10), or a reconnect to an
-- existing session (4778, SessionName RDP-Tcp#N - "Console" is Fast User Switching). A
-- reconnect's LogonID is the session's own: what runs after it carries that id (W-D7, Q90).
CREATE OR REPLACE TEMP TABLE win_rdp_starts AS
SELECT row_id, ts, host, lid, account, source, 'logon' AS how FROM win_logons WHERE ltype = '10'
UNION ALL
SELECT e.row_id, e.ts, {HOST}, lower(trim(w.data['LogonID'])), {_account("w.data['AccountName']")},
       CASE WHEN upper(trim(w.data['ClientAddress'])) <> 'LOCAL' THEN {_addr("w.data['ClientAddress']")} END,
       'reconnect'
FROM product_events e JOIN win_events w USING (row_id)
WHERE w.provider = '{SECURITY}' AND w.event_id = 4778 AND e.ts IS NOT NULL
  AND upper(trim(w.data['SessionName'])) LIKE 'RDP-TCP#%';

-- Each process to the latest RDP start of its session before it.
CREATE OR REPLACE TEMP TABLE win_rdp_acts AS
WITH x AS (
  SELECT e.row_id, e.ts, {HOST} AS host,
         lower(trim(CASE WHEN w.provider = '{SYSMON}' THEN w.data['LogonId'] ELSE w.data['SubjectLogonId'] END)) AS lid,
         e.program AS what
  FROM product_events e JOIN win_events w USING (row_id)
  WHERE e.ts IS NOT NULL
    AND ((w.provider = '{SECURITY}' AND w.event_id = 4688) OR (w.provider = '{SYSMON}' AND w.event_id = 1)))
SELECT x.*, s.row_id AS start_row
FROM x ASOF JOIN win_rdp_starts s ON x.host = s.host AND x.lid = s.lid AND x.ts >= s.ts
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
    # A reconnect (4778) starts a session as a logon does (W-D7, Q90).
    ("WIN-LAT-1", """
        INSERT INTO findings
        WITH l AS (SELECT * FROM win_rdp_starts WHERE source IS NOT NULL),
        pd AS (SELECT source, account, host, count(DISTINCT CAST(ts AS DATE)) AS days FROM l GROUP BY ALL),
        span AS (SELECT count(DISTINCT CAST(ts AS DATE)) AS days FROM win_logons),
        p AS (SELECT start_row, string_agg(DISTINCT what, ', ' ORDER BY what) AS progs
              FROM win_rdp_acts GROUP BY start_row),
        hit AS (SELECT l.*, p.progs FROM l JOIN p ON p.start_row = l.row_id
                JOIN pd USING (source, account, host) WHERE pd.days = 1),
        r AS (SELECT row_id, row_id AS start_row FROM win_rdp_starts
              UNION ALL SELECT row_id, start_row FROM win_rdp_acts)
        SELECT r.row_id, 'WIN-LAT-1', NULL,
               CASE hit.how WHEN 'logon' THEN 'RDP to ' ELSE 'RDP session reconnected on ' END ||
               hit.host || ' as ' || hit.account || ' from ' || hit.source ||
               ' - a pair seen on 1 of the ' || span.days || ' days of the evidence - then ran: ' || hit.progs,
               ['T1021.001'], coalesce(hit.source, ''), hit.account
        FROM hit CROSS JOIN span JOIN r ON r.start_row = hit.row_id
    """),
    # A network logon, then a service or a scheduled task created in that session -
    # PsExec's shape (T1021.002 DET0530 AN1468 "remote service creation, task
    # scheduling"; a service: T1569.002 DET0421 AN1185, PsExec "creating temporary
    # services").
    # Only a (source, account, service or task) created on one day of the evidence: one seen on
    # two days or more is expected - AN1468's "expected remote administrators vs. rare/first-time
    # access", AN1185's allowlists, read off the evidence (W-D16, Q120).
    ("WIN-LAT-2", f"""
        INSERT INTO findings
        WITH a0 AS (SELECT a.*, l.account, l.source FROM win_session_acts a
                    JOIN win_logons l ON l.row_id = a.logon_row
                    WHERE a.event_id IN (4697, 4698) AND l.ltype = '3'),
        pd AS (SELECT source, account, what, count(DISTINCT CAST(ts AS DATE)) AS days FROM a0 GROUP BY ALL),
        a AS (SELECT a0.* FROM a0 JOIN pd ON pd.source IS NOT DISTINCT FROM a0.source
                                         AND pd.account IS NOT DISTINCT FROM a0.account
                                         AND pd.what IS NOT DISTINCT FROM a0.what
              WHERE pd.days = 1),
        -- AN1468's "access to ADMIN$ / C$" in the same session (5140, logged once per session).
        sh AS (SELECT row_id, logon_row, what AS share, ts FROM win_session_acts
               WHERE event_id = 5140 AND {_admin_share("what")}),
        r AS (SELECT row_id, row_id AS act FROM a UNION ALL SELECT logon_row, row_id FROM a
              UNION ALL SELECT sh.row_id, a.row_id FROM sh JOIN a ON a.logon_row = sh.logon_row AND sh.ts <= a.ts)
        SELECT DISTINCT r.row_id, 'WIN-LAT-2', NULL,
               'Network logon to ' || a.host || ' as ' || a.account || ' from ' || coalesce(a.source, '?') ||
               coalesce(', opened ' || (SELECT string_agg(DISTINCT sh.share, ', ') FROM sh
                                        WHERE sh.logon_row = a.logon_row AND sh.ts <= a.ts), '') ||
               ', then ' || CASE a.event_id WHEN 4697 THEN 'service' ELSE 'scheduled task' END || ' "' ||
               a.what || '" created in that session',
               ['T1021.002'] || CASE WHEN a.event_id = 4697 THEN ['T1569.002'] ELSE []::VARCHAR[] END,
               coalesce(a.source, ''), a.account
        FROM a JOIN r ON r.act = a.row_id
    """),
    # A file written into ADMIN$ / C$ over the network, then run on that host - PsExec copies
    # PSEXESVC.exe to ADMIN$ and installs it (T1021.002 AN1468, W-D8, Q91). 5145 names the file
    # (RelativeTargetName under ShareLocalPath) and the access (AccessMask 0x2 WriteData); it
    # needs Detailed File Share auditing - a host without it shows nothing here. Joined by the
    # file's path on the same host, the run after the write: no window. Only a (source, account,
    # file) written on one day of the evidence, as WIN-LAT-2 (W-D16, Q120).
    ("WIN-LAT-4", f"""
        INSERT INTO findings
        WITH wr AS (
          SELECT e.row_id, e.ts, {HOST} AS host, {_account("w.data['SubjectUserName']")} AS account,
                 {_addr("w.data['IpAddress']")} AS source, trim(w.data['ShareName']) AS share,
                 lower(replace(replace(trim(w.data['ShareLocalPath']), '\\??\\', '') || '\\' ||
                               trim(w.data['RelativeTargetName']), '\\\\', '\\')) AS path
          FROM product_events e JOIN win_events w USING (row_id)
          WHERE w.provider = '{SECURITY}' AND w.event_id = 5145 AND e.ts IS NOT NULL
            AND {_admin_share("w.data['ShareName']")}
            AND (try_cast(trim(w.data['AccessMask']) AS BIGINT) & 2) <> 0
            AND coalesce(trim(w.data['RelativeTargetName']), '') NOT IN ('', '\\')),
        run AS (
          SELECT e.row_id, e.ts, {HOST} AS host, w.event_id,
                 -- lower first: Windows writes %SystemRoot% in mixed case.
                 replace(lower(CASE WHEN w.event_id = 4697 THEN w.data['ServiceFileName']
                                    WHEN w.event_id = 4688 THEN w.data['NewProcessName']
                                    ELSE w.data['Image'] END), '%systemroot%', 'c:\\windows') AS image,
                 coalesce(w.data['ServiceName'], e.program) AS what
          FROM product_events e JOIN win_events w USING (row_id)
          WHERE e.ts IS NOT NULL AND ((w.provider = '{SECURITY}' AND w.event_id IN (4697, 4688))
                                      OR (w.provider = '{SYSMON}' AND w.event_id = 1))),
        pairs0 AS (SELECT wr.row_id AS wrow, run.row_id AS rrow, wr.ts AS wts, wr.host, wr.account, wr.source,
                          wr.share, wr.path, run.event_id, run.what
                   FROM wr JOIN run ON run.host = wr.host AND run.ts >= wr.ts
                                   AND (run.image = wr.path OR (run.event_id = 4697 AND contains(run.image, wr.path)))),
        pd AS (SELECT source, account, path, count(DISTINCT CAST(wts AS DATE)) AS days FROM pairs0 GROUP BY ALL),
        pairs AS (SELECT p.* FROM pairs0 p JOIN pd ON pd.source IS NOT DISTINCT FROM p.source
                                                  AND pd.account IS NOT DISTINCT FROM p.account
                                                  AND pd.path = p.path
                  WHERE pd.days = 1),
        r AS (SELECT wrow AS row_id, wrow, rrow FROM pairs UNION ALL SELECT rrow, wrow, rrow FROM pairs)
        SELECT r.row_id, 'WIN-LAT-4', NULL,
               p.path || ' written to ' || p.share || ' on ' || p.host || ' as ' || p.account || ' from ' ||
               coalesce(p.source, '?') || ', then run there as ' ||
               CASE p.event_id WHEN 4697 THEN 'service "' || p.what || '"' ELSE 'process ' || p.what END,
               ['T1021.002'] || CASE WHEN p.event_id = 4697 THEN ['T1569.002'] ELSE []::VARCHAR[] END,
               coalesce(p.source, ''), p.account
        FROM pairs p JOIN r ON r.wrow = p.wrow AND r.rrow = p.rrow
        -- One finding per event: the service install named when there is one.
        QUALIFY row_number() OVER (PARTITION BY r.row_id ORDER BY p.event_id <> 4697, p.rrow) = 1
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
               ['T1550.002'], l.source, l.account
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
                 ['T1558.003'], '', w.account
          FROM weak w JOIN hit h ON h.account = w.account AND w.ts BETWEEN h.ts AND h.ts + INTERVAL 1 HOUR
          GROUP BY w.row_id, w.account)
    """),
    # LSASS dump: a process opens lsass.exe, then writes a file (T1003.001 DET0363
    # AN1030 - "then invokes memory dump, file creation"), joined by the process's
    # Sysmon GUID. Registry writes are left out: an antivirus reads lsass and writes
    # its own keys all day. Only an access that can read lsass's memory - PROCESS_VM_READ
    # (0x10), which MiniDumpWriteDump and ReadProcessMemory need (W-D17, Q123): svchost's
    # 0x3000 before writing a Prefetch file cannot dump anything.
    ("WIN-HOST-2", f"""
        INSERT INTO findings
        WITH acc AS (SELECT e.row_id, e.ts, {HOST} AS host, lower(w.data['SourceProcessGUID']) AS g,
                            w.data['SourceImage'] AS img, w.data['GrantedAccess'] AS access,
                            {_account("w.data['SourceUser']")} AS account
                     FROM product_events e JOIN win_events w USING (row_id)
                     WHERE w.provider = '{SYSMON}' AND w.event_id = 10
                       AND lower(w.data['TargetImage']) LIKE '%\\lsass.exe'
                       AND (try_cast(trim(w.data['GrantedAccess']) AS BIGINT) & 16) <> 0),
        wr AS (SELECT e.row_id, e.ts, {HOST} AS host, lower(w.data['ProcessGuid']) AS g,
                      w.data['TargetFilename'] AS f
               FROM product_events e JOIN win_events w USING (row_id)
               WHERE w.provider = '{SYSMON}' AND w.event_id = 11),
        pairs AS (SELECT a.row_id AS arow, wr.row_id AS wrow, a.host, a.img, a.access, a.account, wr.f
                  FROM acc a JOIN wr ON wr.host = a.host AND wr.g = a.g AND wr.ts >= a.ts),
        r AS (SELECT arow AS row_id, arow, wrow FROM pairs UNION ALL SELECT wrow, arow, wrow FROM pairs)
        SELECT DISTINCT r.row_id, 'WIN-HOST-2', NULL,
               'LSASS opened by ' || p.img || ' (access ' || p.access || ') on ' || p.host ||
               ', which then wrote ' || p.f,
               ['T1003.001'], '', coalesce(p.account, '')
        FROM pairs p JOIN r ON r.arow = p.arow AND r.wrow = p.wrow
    """),
]

# Story 5c: Sysmon's network connections (event 3) - which process on which host
# talked to which public address. Windows logs no refused connection, so a feed
# match on a blocked connection (R3005's) has no Windows twin.
_CONNECTIONS = f"""
    SELECT row_id, ts, upper(split_part(hostname, '.', 1)) AS host, program, dstip, srcip
    FROM product_events
    WHERE action = 'network_connection' AND ts IS NOT NULL AND dstip IS NOT NULL AND program IS NOT NULL
      AND regexp_matches(dstip, '{IPV4_RE}') AND NOT regexp_matches(dstip, '{NON_PUBLIC_IPV4_RE}')
"""
BEACON_MIN_GAPS, BEACON_MAX_CV = 30, 0.6        # R2007's measured method (rules.py)
BEACON_MIN_S, BEACON_MAX_S = 30, 3600
_BEACONS = f"""
    WITH c AS ({_CONNECTIONS}),
    g AS (SELECT *, date_diff('second', lag(ts) OVER (PARTITION BY host, program, dstip ORDER BY ts, row_id),
                              ts) AS gap FROM c)
    SELECT host, program, dstip, count(*) AS n, avg(gap) AS avg_gap,
           stddev_pop(gap) / nullif(avg(gap), 0) AS cv
    FROM g WHERE gap > 0 AND gap <= {BEACON_MAX_S}
    GROUP BY host, program, dstip
    HAVING count(*) >= {BEACON_MIN_GAPS} AND avg(gap) BETWEEN {BEACON_MIN_S} AND {BEACON_MAX_S}
       AND stddev_pop(gap) / nullif(avg(gap), 0) < {BEACON_MAX_CV}
"""


def prepare_mal_1(con):
    """W-D11 (Q99 a): the analytics ask for beacons to *rare* destinations (AN0076, AN0761 - "rare"
    undefined). A (process, destination) beaconing on more than half of the hosts with Sysmon
    network events is the fleet's - an agent's timer - and is left out, named on the line record.
    Under lines.MIN_LEGIT hosts there is no fleet to call a destination common in (Q105, as Q67):
    one host's evidence is "more than half" of itself, so every beacon is flagged instead.
    Writes TEMP TABLE win_fleet_beacons (program, dstip, hosts)."""
    total = con.execute("SELECT count(DISTINCT upper(split_part(hostname, '.', 1))) FROM product_events "
                        "WHERE action = 'network_connection' AND hostname IS NOT NULL").fetchone()[0]
    floor = "" if total >= lines.MIN_LEGIT else "AND false"
    con.execute(f"""
        CREATE OR REPLACE TEMP TABLE win_fleet_beacons AS
        SELECT program, dstip, count(DISTINCT host) AS hosts FROM ({_BEACONS})
        GROUP BY program, dstip HAVING count(DISTINCT host) > {total} / 2 {floor}""")
    left = con.execute("SELECT program, dstip, hosts FROM win_fleet_beacons ORDER BY hosts DESC, program, dstip"
                       ).fetchall()
    if total < lines.MIN_LEGIT:
        note = (f"{total} hosts with Sysmon network events - under {lines.MIN_LEGIT}, no beacon can be called "
                "the fleet's; every beacon is flagged")
    else:
        note = (f"{len(left)} fleet-wide timer(s) left out" +
                (": " + "; ".join(f"{p} -> {d} on {h} of {total} hosts" for p, d, h in left) if left else "") +
                f" - a (process, destination) beaconing on more than half of the {total} hosts with Sysmon "
                "network events is not a rare destination")
    return {}, {"method": "fleet-wide", "source": "ATT&CK T1071.001 DET0027 AN0076, T1573 DET0273 AN0761 "
                                                  "(beacons to rare destinations; rare undefined - more than "
                                                  "half the hosts, an internal method)",
                "hosts_with_network_events": total,
                "left_out": [{"process": p, "destination": d, "hosts": h} for p, d, h in left],
                "population": "(process, destination) pairs that beacon, by the hosts they beacon on",
                "note": note}

RULES += [
    # M1 beaconing, per process (T1071 DET0444): R2007's measured method - regular
    # intervals, jitter (CV) < 0.6, at least 30 intervals of 30 s - 1 h, public
    # destinations only - keyed on (host, process, destination). One change,
    # stated: a silence longer than the method's longest period (1 h) is not an
    # interval but the host switched off or the channel asleep, and is left out of
    # the statistics. Over a quarter of working days, a five-minute beacon's
    # nights and weekends made R2007's jitter far above 0.6 (W4 was missed).
    # A beacon the fleet shares (win_fleet_beacons, prepare_mal_1) is left out (W-D11).
    ("WIN-MAL-1", f"""
        INSERT INTO findings
        WITH c AS ({_CONNECTIONS}),
        b AS (SELECT * FROM ({_BEACONS}) x
              WHERE NOT EXISTS (SELECT 1 FROM win_fleet_beacons fb
                                WHERE fb.program = x.program AND fb.dstip = x.dstip))
        SELECT c.row_id, 'WIN-MAL-1', NULL,
               'Beaconing from ' || c.program || ' on ' || c.host || ' to ' || c.dstip || ' (' || b.n ||
               ' intervals at ~' || cast(round(b.avg_gap) AS INT) || 's, jitter ' ||
               cast(round(b.cv * 100) AS INT) || '%; silences over an hour left out)',
               ['T1071']
        FROM c JOIN b USING (host, program, dstip)
    """),
    # T1 a connection to a listed address (R3003's feed match, on Sysmon 3).
    ("WIN-INTEL-1", """
        INSERT INTO findings
        SELECT e.row_id, 'WIN-INTEL-1', NULL,
               'Connection from ' || coalesce(e.program, '?') || ' on ' ||
               upper(split_part(coalesce(e.hostname, '?'), '.', 1)) || ' to known-bad indicator ' || e.dstip ||
               ' [' || i.source || CASE WHEN i.note <> '' THEN ': ' || i.note ELSE '' END || ']',
               ['T1071']
        FROM product_events e JOIN ioc i ON e.dstip = i.value AND i.type = 'ip'
        WHERE e.action = 'network_connection'
    """),
    # T2 a sign-in attempt from a listed address (R3004's feed match, on the
    # attempts of the BRUTE rules' preparation - every event of the attempt).
    ("WIN-INTEL-2", """
        INSERT INTO findings
        SELECT r.row_id, 'WIN-INTEL-2', NULL,
               'Sign-in ' || CASE a.outcome WHEN 'success' THEN 'succeeded' ELSE 'failed' END || ' for ' ||
               a.account || ' from known-bad indicator ' || a.source ||
               ' [' || i.source || CASE WHEN i.note <> '' THEN ': ' || i.note ELSE '' END || ']',
               CASE WHEN a.outcome = 'success' THEN ['T1078'] ELSE ['T1110'] END, a.source, ''
        FROM win_attempts a JOIN ioc i ON a.source = i.value AND i.type = 'ip'
        JOIN win_attempt_rows r USING (attempt_id)
        WHERE a.source_kind = 'address'
    """),
]

# Story 5f (specs/windows_defender_rules.md, Q114-Q119): Microsoft Defender Antivirus's own
# verdicts, read like a firewall's (W-D12) - single events, so no line. Event ids, names and
# fields from Microsoft's "Review event logs and error codes ... Microsoft Defender Antivirus"
# (SOURCES.md, read 2026-10-28); item names as Defender writes them in its EventData.
DEFENDER = "Microsoft-Windows-Windows Defender"
DEFENDER_DETECTION = (1006, 1015, 1116,           # detected
                      1007, 1117,                 # action taken
                      1008, 1118, 1119)           # action failed / critically failed
DEFENDER_ACTION_TAKEN = (1007, 1117)
DEFENDER_ACTION_FAILED = (1008, 1118, 1119)
# 1117: "The Allow, No action, and None actions don't remediate detected threats" - these do.
DEFENDER_REMEDIATED = ("quarantine", "remove", "clean", "block")
# Turned off -> the event that says it was turned back on (5001 -> 5000, 5010 -> 5009, 5012 -> 5011).
DEFENDER_OFF = {5001: (5000, "real-time protection disabled"),
                5010: (5009, "malware scanning disabled"),
                5012: (5011, "virus scanning disabled")}
DEFENDER_TAMPER_BLOCKED = 5013
DEFENDER_CONFIG_CHANGED = 5007
DEFENDER_UPDATES = (2000, 2001, 2002)   # definitions updated / update failed / engine updated

# Item names differ by event (the provider's own templates, Get-WinEvent -ListProvider): 1006 /
# 1015 write `Path Found` and `Domain` + `User`; 1007 / 1008 `Cleaning Action`; 1116-1119 `Path`,
# `Action Name` and `Detection User`.
_DEFENDER = f"""
  SELECT e.row_id, e.ts, w.event_id, {HOST} AS host, w.data AS d,
         coalesce(w.data['Path'], w.data['Path Found']) AS path,
         trim(coalesce(w.data['Action Name'], w.data['Cleaning Action'])) AS action,
         coalesce(w.data['Detection User'],
                  nullif(trim(coalesce(w.data['Domain'] || '\\', '') || coalesce(w.data['User'], '')), '')) AS usr
  FROM product_events e JOIN win_events w USING (row_id)
  WHERE w.provider = '{DEFENDER}'
"""


def _ts(expr: str) -> str:
    return f"strftime({expr}, '%Y-%m-%d %H:%M:%S')"


RULES += [
    # Defender's detection (W-D13, Q115): the detected event and its outcome events are one
    # detection - same host and Detection ID (observed in the events; Microsoft's field lists do
    # not name it), else same host, threat ID and path. Medium when an action taken remediated it
    # and none failed - Defender stopped it, as a refused row is capped at medium; else high. No
    # technique: a detection says what Defender found, not what the attacker did (as CP-MAL-2's
    # Anti-Virus verdicts). Q116: a 1011 (deleted from quarantine) whose threat has no detection
    # event on that host in the evidence is its own medium suggestion - it had been quarantined.
    ("WIN-MAL-2", f"""
        INSERT INTO findings
        WITH ev AS ({_DEFENDER} AND w.event_id IN {DEFENDER_DETECTION}),
        k AS (SELECT *, host || '|' || coalesce(nullif(trim(d['Detection ID']), ''),
                                                coalesce(d['Threat ID'], '') || '|' || coalesce(path, '')) AS det
              FROM ev),
        g AS (SELECT det, any_value(host) AS host,
                     any_value(d['Threat Name']) FILTER (WHERE d['Threat Name'] IS NOT NULL) AS threat,
                     any_value(d['Category Name']) FILTER (WHERE d['Category Name'] IS NOT NULL) AS cat,
                     any_value(d['Severity Name']) FILTER (WHERE d['Severity Name'] IS NOT NULL) AS sev,
                     any_value(d['Process Name']) FILTER (WHERE nullif(d['Process Name'], 'Unknown') IS NOT NULL) AS proc,
                     any_value(usr) FILTER (WHERE usr IS NOT NULL) AS usr,
                     any_value(d['Source Name']) FILTER (WHERE d['Source Name'] IS NOT NULL) AS via,
                     string_agg(DISTINCT action, ', ') FILTER (WHERE event_id IN {DEFENDER_ACTION_TAKEN}) AS actions,
                     bool_or(event_id IN {DEFENDER_ACTION_FAILED}) AS failed,
                     bool_or(event_id IN {DEFENDER_ACTION_TAKEN}
                             AND lower(action) IN {DEFENDER_REMEDIATED}) AS remediated
              FROM k GROUP BY det),
        q AS ({_DEFENDER} AND w.event_id = 1011),
        lone AS (SELECT q.* FROM q WHERE NOT EXISTS (
                     SELECT 1 FROM ev WHERE ev.host = q.host AND ev.d['Threat ID'] = q.d['Threat ID']))
        SELECT k.row_id, 'WIN-MAL-2',
               CASE WHEN g.remediated AND NOT g.failed THEN {WEIGHT['medium']} END,
               'Defender: ' || coalesce(g.threat, 'threat') ||
               coalesce(' (' || g.cat || coalesce(', ' || g.sev, '') || ')', '') || ' on ' || g.host ||
               coalesce(' - ' || g.proc, '') || coalesce(', ' || g.usr, '') || coalesce(', via ' || g.via, '') ||
               ' - ' || CASE WHEN g.failed THEN 'the action failed' || coalesce(' (' || g.actions || ')', '')
                             WHEN g.remediated THEN g.actions
                             WHEN g.actions IS NOT NULL THEN g.actions || ' - not remediated'
                             ELSE 'no action recorded in the evidence' END,
               []::VARCHAR[], g.host, coalesce({_account('g.usr')}, '')
        FROM k JOIN g USING (det)
        UNION ALL
        SELECT row_id, 'WIN-MAL-2', {WEIGHT['medium']},
               'Defender deleted ' || coalesce(d['Threat Name'], 'a threat') ||
               coalesce(' (' || d['Category Name'] || coalesce(', ' || d['Severity Name'], '') || ')', '') ||
               ' from quarantine on ' || host || coalesce(' - ' || path, '') ||
               '; the detection itself is not in the evidence',
               []::VARCHAR[], host, ''
        FROM lone
    """),
    # Defender turned off or tampered with (W-D14, T1685 DET0497 AN1369; SigmaHQ b28e58e4 for
    # 5001). High; a change tamper protection blocked (5013) is medium - the attempt was refused.
    # Q117: a 5007 only when its new value is under Windows Defender\Exclusions\ (the key path is
    # observed; AN1369 and T1685's procedures name exclusion lists). Q118: when it was turned back
    # on and the nearest Defender update on either side are shown, with no window.
    ("WIN-HOST-3", f"""
        INSERT INTO findings
        WITH ev AS ({_DEFENDER} AND w.event_id IN ({", ".join(str(i) for i in (
                        *DEFENDER_OFF, *(on for on, _ in DEFENDER_OFF.values()),
                        DEFENDER_TAMPER_BLOCKED, DEFENDER_CONFIG_CHANGED, *DEFENDER_UPDATES))})),
        off AS (SELECT *, CASE event_id {" ".join(f"WHEN {off} THEN {on}" for off, (on, _) in DEFENDER_OFF.items())}
                          END AS on_id
                FROM ev
                WHERE event_id IN ({", ".join(str(i) for i in DEFENDER_OFF)}, {DEFENDER_TAMPER_BLOCKED})
                   OR (event_id = {DEFENDER_CONFIG_CHANGED}
                       AND contains(lower(coalesce(d['New Value'], '')), '\\windows defender\\exclusions\\'))),
        facts AS (
          SELECT o.row_id,
                 (SELECT min(x.ts) FROM ev x WHERE x.host = o.host AND x.event_id = o.on_id AND x.ts >= o.ts) AS back_on,
                 (SELECT arg_max(x.event_id || ' at ' || {_ts('x.ts')}, x.ts) FROM ev x
                  WHERE x.host = o.host AND x.event_id IN {DEFENDER_UPDATES} AND x.ts < o.ts) AS upd_before,
                 (SELECT arg_min(x.event_id || ' at ' || {_ts('x.ts')}, x.ts) FROM ev x
                  WHERE x.host = o.host AND x.event_id IN {DEFENDER_UPDATES} AND x.ts > o.ts) AS upd_after
          FROM off o)
        SELECT o.row_id, 'WIN-HOST-3',
               CASE WHEN o.event_id = {DEFENDER_TAMPER_BLOCKED} THEN {WEIGHT['medium']} END,
               CASE o.event_id
                 {" ".join(f"WHEN {off} THEN 'Defender {what} on '" for off, (_, what) in DEFENDER_OFF.items())}
                 WHEN {DEFENDER_TAMPER_BLOCKED} THEN 'Tamper protection blocked a change to Defender on '
                 ELSE 'Defender exclusion changed on ' END || o.host ||
               CASE WHEN o.event_id = {DEFENDER_CONFIG_CHANGED} THEN ': ' || o.d['New Value']
                    WHEN o.on_id IS NULL THEN ''
                    WHEN f.back_on IS NULL THEN ' - not turned back on in the evidence'
                    ELSE ' - turned back on at ' || {_ts('f.back_on')} || ' (' ||
                         date_diff('minute', o.ts, f.back_on) || ' min later)' END ||
               CASE WHEN f.upd_before IS NULL AND f.upd_after IS NULL THEN ''
                    ELSE '; nearest Defender update event: ' ||
                         concat_ws(', ', f.upd_before || ' before', f.upd_after || ' after') END,
               ['T1685'], o.host, ''
        FROM off o JOIN facts f USING (row_id)
    """),
]

# The rules that name their finding's entity - what each decided on (specs/finding_entities.md
# E-D1): a source, an account, or both; WIN-MAL-1 / WIN-INTEL-1 are one process on one host and
# keep the row's own. Defender's rules name the host it ran on (and the detection's account).
ENTITY = ("WIN-BRUTE-1", "WIN-BRUTE-2", "WIN-BRUTE-3", "WIN-BRUTE-4", "WIN-AUTH-1", "WIN-LAT-1",
          "WIN-LAT-2", "WIN-LAT-3", "WIN-LAT-4", "WIN-HOST-1", "WIN-HOST-2", "WIN-INTEL-2",
          "WIN-MAL-2", "WIN-HOST-3")
# WIN-AUTH-1 reads the attempts the BRUTE rules' preparation built, and their findings.
# WIN-LAT-2 / -3 read the sessions WIN-LAT-1's preparation built; WIN-BRUTE-4 its own epochs.
PREPARE = {"WIN-BRUTE-1": prepare_brute_1, "WIN-BRUTE-2": prepare_brute_2,
           "WIN-BRUTE-3": prepare_brute_3, "WIN-BRUTE-4": prepare_brute_4, "WIN-LAT-1": prepare_sessions,
           "WIN-HOST-1": prepare_host_1, "WIN-MAL-1": prepare_mal_1}
LEVEL = {"WIN-BRUTE-1": "medium", "WIN-BRUTE-2": "medium", "WIN-BRUTE-3": "medium", "WIN-BRUTE-4": "medium",
         "WIN-AUTH-1": "high", "WIN-LAT-1": "medium", "WIN-LAT-2": "medium", "WIN-LAT-3": "high",
         "WIN-LAT-4": "medium",
         "WIN-HOST-1": "high", "WIN-HOST-2": "high", "WIN-MAL-1": "high", "WIN-INTEL-1": "high",
         "WIN-INTEL-2": "medium",
         # Story 5f: high; a finding the event itself lowers writes medium (rules.apply_rules).
         "WIN-MAL-2": "high", "WIN-HOST-3": "high"}
LABELS = {"WIN-BRUTE-1": "password guessing", "WIN-BRUTE-2": "password spray",
          "WIN-BRUTE-3": "distributed guessing", "WIN-BRUTE-4": "low-and-slow guessing",
          "WIN-AUTH-1": "login after failures",
          "WIN-LAT-1": "uncommon RDP, then commands", "WIN-LAT-2": "remote service or task",
          "WIN-LAT-3": "NTLM without Kerberos", "WIN-LAT-4": "file copied to admin share, then run",
          "WIN-HOST-1": "Kerberoasting", "WIN-HOST-2": "LSASS dump",
          "WIN-MAL-1": "beaconing", "WIN-INTEL-1": "known-bad destination", "WIN-INTEL-2": "known-bad sign-in source",
          "WIN-MAL-2": "Defender detection", "WIN-HOST-3": "Defender turned off"}
# The sign-in and beaconing rules count in their generic twins' family (R2), the feed matches in R3's;
# a host behaviour has none to share, nor has Defender's verdict - its own evidence (AV).
FAMILY = {r: ("AV" if r == "WIN-MAL-2" else
              "R2" if r.startswith(("WIN-BRUTE", "WIN-AUTH", "WIN-MAL")) else
              "R3" if r.startswith("WIN-INTEL") else r.split("-")[1]) for r in LEVEL}
EQUIVALENT = {"WIN-BRUTE-1": "R2000", "WIN-BRUTE-2": "R2009", "WIN-BRUTE-3": "R2005",
              "WIN-AUTH-1": "R2008", "WIN-MAL-1": "R2007", "WIN-INTEL-1": "R3003", "WIN-INTEL-2": "R3004"}
# WIN-MAL-2 has no generic twin: R3002 is malware *traffic a firewall let through* - VERIS would call
# a Defender detection a Downloader, and the compromised-host pattern would count one Defender stopped.
# The generic sign-in rules stop on Windows rows. R2006 (one account, many
# sources succeeding within an hour) goes with them: on Windows it flagged a
# domain controller's own machine account signing in from its addresses. So do
# beaconing and the feed matches (story 5c); R3005 (blocked) has nothing to
# match on Windows, R3001 / R3002 no bytes or category, and stay generic.
SUPERSEDES = ("R2000", "R2005", "R2006", "R2008", "R2009", "R2007", "R3003", "R3004", "R3005")
FROM_GENERIC: tuple = ()
