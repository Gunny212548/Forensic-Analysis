"""Palo Alto Networks rules (specs/per_product_rules.md story 2, D11-D16).

Written on the PAN-OS Traffic log as the customer's exports carry it (fields:
PAN-OS 11.0 Traffic Log Fields, read 2026-10-22). Each rule reads
`product_events` - Palo Alto rows only (rules.apply_rules) - and names the
behaviour it matches and the document behind it (docs/standards/
detection-behaviours.md). The Authentication and Brute force areas are not
applicable: a Traffic log records sessions, not sign-ins (Q61).

Rules that draw a line take it from lines.py: `$above` and `$minimum` are
bound when the rule runs, from PREPARE, and the line's record is kept on the
case. A refusal is `verdict IN DENY_VERDICTS` (PAN-OS Action deny / drop /
drop ICMP / reset both / client / server).
"""

from . import lines
from .rules import DENY_VERDICTS, IPV4_RE, NON_PUBLIC_IPV4_RE

PRODUCT = "paloalto"
_INTERNAL = f"regexp_matches(coalesce(e.srcip, ''), '{NON_PUBLIC_IPV4_RE}')"

# PAN-DB categories its documentation defines as malicious content or C2
# ("URL Categories", Advanced URL Filtering, updated 2026-09-02). Grayware is
# left out: "does not pose a direct security threat". Phishing carries no
# technique until T1566 is read.
MALICIOUS_CATEGORIES = ("malware", "command-and-control", "ransomware", "compromised-website",
                        "phishing")

_ONE_HOUR_PORTS = """
    SELECT srcip, dstip, ts, row_id,
           count(DISTINCT dstport) OVER (PARTITION BY srcip, dstip ORDER BY ts
               RANGE BETWEEN CURRENT ROW AND INTERVAL 1 HOUR FOLLOWING) AS ports
    FROM {table}
    WHERE verdict IN {deny} AND srcip IS NOT NULL AND dstip IS NOT NULL
      AND dstport IS NOT NULL AND ts IS NOT NULL {extra}
"""

_DENIALS_BEFORE = """
    SELECT srcip, dstip, ts, row_id, verdict IN {deny} AS denied,
           count(*) FILTER (WHERE verdict IN {deny}) OVER (PARTITION BY srcip, dstip ORDER BY ts
               RANGE BETWEEN INTERVAL 1 HOUR PRECEDING AND CURRENT ROW) AS denials_before
    FROM {table}
    WHERE srcip IS NOT NULL AND dstip IS NOT NULL AND ts IS NOT NULL AND verdict IS NOT NULL {extra}
"""


def _trw(con) -> dict:
    """TRW over the Palo Alto rows, once per run (lines.trw)."""
    return lines.trw(con, PRODUCT, DENY_VERDICTS)


def _benign_pairs_value(value_sql: str, value: str) -> str:
    """Every (source, host) pair of a TRW-benign source, with its value or 0."""
    return f"""
        SELECT coalesce(max(w.{value}), 0) AS v
        FROM (SELECT DISTINCT srcip, dstip FROM raw_events
              WHERE product = '{PRODUCT}' AND srcip IS NOT NULL AND dstip IS NOT NULL) p
        JOIN trw_{PRODUCT} t ON t.srcip = p.srcip AND t.decision = 'benign'
        LEFT JOIN ({value_sql}) w ON w.srcip = p.srcip AND w.dstip = p.dstip
        GROUP BY p.srcip, p.dstip
    """


def _prepare_scan_2(con):
    return {}, _trw(con)


def _prepare_scan_1(con):
    _trw(con)
    value_sql = _ONE_HOUR_PORTS.format(table="raw_events", deny=DENY_VERDICTS,
                                       extra=f"AND product = '{PRODUCT}'")
    rec = lines.evidence_line(con, _benign_pairs_value(value_sql, "ports"), 2,
                              "(source, host) pairs of the sources TRW decided benign; value = most "
                              "distinct refused ports in any hour")
    return _params(rec), rec


def _params(rec: dict) -> dict:
    """The SQL's parameters, and the line in a few words for each finding."""
    if rec["method"] == "no-line":
        note = f"no line: {rec['members']} legitimate pairs, minimum {rec['minimum']:g}"
    else:
        note = f"line above {rec['above']:g} and at least {rec['minimum']:g}, from {rec['members']} legitimate pairs"
    return {"above": rec["above"], "minimum": rec["minimum"], "note": note}


def _prepare_scan_3(con):
    _trw(con)
    only = f"AND product = '{PRODUCT}'"
    value_sql = (f"SELECT * FROM ({_DENIALS_BEFORE.format(table='raw_events', deny=DENY_VERDICTS, extra=only)}) "
                 "WHERE NOT denied")
    rec = lines.evidence_line(con, _benign_pairs_value(value_sql, "denials_before"), 1,
                              "(source, host) pairs of the sources TRW decided benign; value = most "
                              "refusals in the hour before an allowed connection")
    return _params(rec), rec


RULES: list[tuple[str, str]] = [
    # S2 horizontal scan / host sweep - TRW (Jung et al. 2004 §4). T1046 from an
    # internal source (discovery), T1595.001 from outside (reconnaissance:
    # "probing activity targeting multiple IP addresses", DET0817 AN1949).
    ("PAN-SCAN-2", f"""
        INSERT INTO findings
        SELECT e.row_id, 'PAN-SCAN-2', NULL,
               'Horizontal scan from ' || e.srcip || ': TRW decided scanner after ' ||
               t.n_decided || ' new hosts (' || t.hosts || ' hosts tried)',
               CASE WHEN {_INTERNAL} THEN ['T1046'] ELSE ['T1595.001'] END
        FROM product_events e
        JOIN trw_{PRODUCT} t ON t.srcip = e.srcip AND t.decision = 'scanner'
        WHERE e.verdict IN {DENY_VERDICTS}
    """),
    # S1 vertical scan - one source, many refused ports on one host in an hour
    # (T1046 DET0376 AN1057/AN1058; from outside T1595 DET0830). Line: lines.py.
    ("PAN-SCAN-1", f"""
        INSERT INTO findings
        SELECT * FROM (
          WITH w AS ({_ONE_HOUR_PORTS.format(table="product_events", deny=DENY_VERDICTS, extra="")}),
          a AS (SELECT * FROM w WHERE ports > $above AND ports >= $minimum)
          SELECT e.row_id, 'PAN-SCAN-1', NULL,
                 'Vertical scan ' || e.srcip || ' -> ' || e.dstip || ' (' || max(a.ports) ||
                 ' distinct ports refused within an hour; ' || $note || ')',
                 CASE WHEN {_INTERNAL} THEN ['T1046'] ELSE ['T1595'] END
          FROM w e
          JOIN a ON a.srcip = e.srcip AND a.dstip = e.dstip
                AND e.ts BETWEEN a.ts AND a.ts + INTERVAL 1 HOUR
          GROUP BY e.row_id, e.srcip, e.dstip)
    """),
    # S5 allowed after being refused - the same source refused, then let through
    # to the same host within an hour. No ATT&CK analytic names it: an internal
    # method (the SOC benchmark's implied-rule bypass), stated as one.
    ("PAN-SCAN-3", f"""
        INSERT INTO findings
        SELECT * FROM (
          WITH w AS ({_DENIALS_BEFORE.format(table="product_events", deny=DENY_VERDICTS, extra="")})
          SELECT row_id, 'PAN-SCAN-3', NULL,
                 'Allowed ' || srcip || ' -> ' || dstip || ' after ' || denials_before ||
                 ' refusals in the hour before (possible policy gap; ' || $note || ')',
                 []::VARCHAR[]
          FROM w
          WHERE NOT denied AND denials_before > $above AND denials_before >= $minimum)
    """),
    # M5 the firewall's own verdict on the destination: a PAN-DB category it
    # defines as malicious (T1071.001 for malware / C2; phishing untagged).
    ("PAN-MAL-2", f"""
        INSERT INTO findings
        SELECT row_id, 'PAN-MAL-2', NULL,
               'PAN-DB category ''' || lower(category) || ''' (' ||
               coalesce(srcip, '?') || ' -> ' || coalesce(dstip, '?') || ')',
               CASE WHEN lower(category) = 'phishing' THEN []::VARCHAR[] ELSE ['T1071.001'] END
        FROM product_events
        WHERE lower(category) IN {MALICIOUS_CATEGORIES}
    """),
]

PREPARE = {"PAN-SCAN-1": _prepare_scan_1, "PAN-SCAN-2": _prepare_scan_2,
           "PAN-SCAN-3": _prepare_scan_3}


def from_generic(generic: dict[str, str]) -> list[tuple[str, str]]:
    """Rules whose method is a generic rule's, run on Palo Alto rows only:
    M1 beaconing is R2007's measured method kept (D16 table); T1-T3 are
    R3003-R3005's feed matches. The SQL is the generic rule's own, so the two
    can never drift apart while both exist (story 4 retires the generic)."""
    out = []
    for rid, src in (("PAN-MAL-1", "R2007"), ("PAN-INTEL-1", "R3003"),
                     ("PAN-INTEL-2", "R3004"), ("PAN-INTEL-3", "R3005")):
        sql = generic[src]
        assert sql.count(f"'{src}'") == 1, src
        out.append((rid, sql.replace("raw_events", "product_events").replace(f"'{src}'", f"'{rid}'")))
    return out


LEVEL = {"PAN-SCAN-1": "low", "PAN-SCAN-2": "low", "PAN-SCAN-3": "high", "PAN-MAL-1": "high",
         "PAN-MAL-2": "high", "PAN-INTEL-1": "high", "PAN-INTEL-2": "medium",
         "PAN-INTEL-3": "medium"}
LABELS = {"PAN-SCAN-1": "vertical scan", "PAN-SCAN-2": "horizontal scan",
          "PAN-SCAN-3": "allowed after refusals", "PAN-MAL-1": "beaconing",
          "PAN-MAL-2": "malicious URL category", "PAN-INTEL-1": "known-bad destination (allowed)",
          "PAN-INTEL-2": "known-bad source (allowed)", "PAN-INTEL-3": "known-bad destination (blocked)"}
# The family each rule counts in for confidence (rules.RULE_FAMILY): that of
# the generic rule matching the same behaviour (R2002 / R2004 / R2007 are R2,
# R3002 / R3003-R3005 are R3).
FAMILY = {"PAN-SCAN-1": "R2", "PAN-SCAN-2": "R2", "PAN-SCAN-3": "R2", "PAN-MAL-1": "R2",
          "PAN-MAL-2": "R3", "PAN-INTEL-1": "R3", "PAN-INTEL-2": "R3", "PAN-INTEL-3": "R3"}
