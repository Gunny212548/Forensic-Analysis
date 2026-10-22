"""The firewall rules every firewall product shares (specs/per_product_rules.md, D11-D16).

A firewall log records connections and the decision on each, whatever the
product: the scanning, beaconing and feed-match behaviours of
docs/standards/detection-behaviours.md are read the same way from each. What
differs per product is the id prefix (`PAN`, `CP`, ...), how a destination
service is named (Palo Alto writes a port, a Check Point SmartConsole export a
service name - gotcha #8) and the product's own rules beside these
(rules_paloalto.py, rules_checkpoint.py).

Every rule reads `product_events` - its product's rows only (rules.apply_rules).
A refusal is `verdict IN DENY_VERDICTS`; an allowed connection is `verdict =
'allow'`. Anything else - Check Point's Detect, a sign-in, an update log - is
neither, so it is no evidence of a scan either way.

Rules that draw a line take it from lines.py: `$above`, `$minimum` and `$note`
are bound when the rule runs, from PREPARE, and the line's record is kept on
the case.
"""

from . import lines
from .rules import DENY_VERDICTS, NON_PUBLIC_IPV4_RE

_INTERNAL = f"regexp_matches(coalesce(e.srcip, ''), '{NON_PUBLIC_IPV4_RE}')"

_ONE_HOUR_SERVICES = """
    SELECT srcip, dstip, ts, row_id,
           count(DISTINCT {service}) OVER (PARTITION BY srcip, dstip ORDER BY ts
               RANGE BETWEEN CURRENT ROW AND INTERVAL 1 HOUR FOLLOWING) AS services
    FROM {table}
    WHERE verdict IN {deny} AND srcip IS NOT NULL AND dstip IS NOT NULL
      AND {service} IS NOT NULL AND ts IS NOT NULL {extra}
"""

_DENIALS_BEFORE = """
    SELECT srcip, dstip, ts, row_id, verdict IN {deny} AS denied,
           count(DISTINCT CASE WHEN verdict IN {deny} THEN {service} END) OVER (
               PARTITION BY srcip, dstip ORDER BY ts
               RANGE BETWEEN INTERVAL 1 HOUR PRECEDING AND CURRENT ROW) AS denials_before
    FROM {table}
    WHERE srcip IS NOT NULL AND dstip IS NOT NULL AND ts IS NOT NULL
      AND (verdict = 'allow' OR verdict IN {deny}) {extra}
"""


def _params(rec: dict) -> dict:
    """The SQL's parameters, and the line in a few words for each finding."""
    if rec["method"] == "no-line":
        note = f"no line: {rec['members']} legitimate pairs, minimum {rec['minimum']:g}"
    else:
        note = (f"line above {rec['above']:g} and at least {rec['minimum']:g}, "
                f"from {rec['members']} legitimate pairs")
    return {"above": rec["above"], "minimum": rec["minimum"], "note": note}


def build(product: str, prefix: str, service: str = "dstport", unit: str = "ports") -> dict:
    """The shared rules of one firewall product: RULES, PREPARE, LEVEL, LABELS,
    FAMILY. `service` is the SQL naming a connection's destination service,
    `unit` what the finding text calls it."""
    only = f"AND product = '{product}'"

    def trw(con) -> dict:
        return lines.trw(con, product, DENY_VERDICTS)

    def benign_pairs(value_sql: str, value: str) -> str:
        """Every (source, host) pair of a TRW-benign source, with its value or 0."""
        return f"""
            SELECT coalesce(max(w.{value}), 0) AS v
            FROM (SELECT DISTINCT srcip, dstip FROM raw_events
                  WHERE product = '{product}' AND srcip IS NOT NULL AND dstip IS NOT NULL) p
            JOIN trw_{product} t ON t.srcip = p.srcip AND t.decision = 'benign'
            LEFT JOIN ({value_sql}) w ON w.srcip = p.srcip AND w.dstip = p.dstip
            GROUP BY p.srcip, p.dstip
        """

    def prepare_scan_2(con):
        return {}, trw(con)

    def prepare_scan_1(con):
        trw(con)
        value_sql = _ONE_HOUR_SERVICES.format(table="raw_events", deny=DENY_VERDICTS,
                                              service=service, extra=only)
        rec = lines.evidence_line(con, benign_pairs(value_sql, "services"), 2,
                                  "(source, host) pairs of the sources TRW decided benign; value = "
                                  f"most distinct refused {unit} in any hour")
        return _params(rec), rec

    def prepare_scan_3(con):
        trw(con)
        before = _DENIALS_BEFORE.format(table="raw_events", deny=DENY_VERDICTS, service=service,
                                        extra=only)
        value_sql = f"SELECT * FROM ({before}) WHERE NOT denied"
        rec = lines.evidence_line(con, benign_pairs(value_sql, "denials_before"), 2,
                                  "(source, host) pairs of the sources TRW decided benign; value = "
                                  f"most distinct {unit} refused in the hour before an allowed "
                                  "connection")
        return _params(rec), rec

    s1, s2, s3 = f"{prefix}-SCAN-1", f"{prefix}-SCAN-2", f"{prefix}-SCAN-3"
    rules = [
        # S2 horizontal scan / host sweep - TRW (Jung et al. 2004 §4). T1046 from
        # an internal source (discovery), T1595.001 from outside
        # (reconnaissance: "probing activity targeting multiple IP addresses",
        # DET0817 AN1949).
        (s2, f"""
            INSERT INTO findings
            SELECT e.row_id, '{s2}', NULL,
                   'Horizontal scan from ' || e.srcip || ': TRW decided scanner after ' ||
                   t.n_decided || ' new hosts (' || t.hosts || ' hosts tried)',
                   CASE WHEN {_INTERNAL} THEN ['T1046'] ELSE ['T1595.001'] END
            FROM product_events e
            JOIN trw_{product} t ON t.srcip = e.srcip AND t.decision = 'scanner'
            WHERE e.verdict IN {DENY_VERDICTS}
        """),
        # S1 vertical scan - one source, many refused services of one host in an
        # hour (T1046 DET0376 AN1057/AN1058; from outside T1595 DET0830).
        (s1, f"""
            INSERT INTO findings
            SELECT * FROM (
              WITH w AS ({_ONE_HOUR_SERVICES.format(table="product_events", deny=DENY_VERDICTS, service=service, extra="")}),
              a AS (SELECT * FROM w WHERE services > $above AND services >= $minimum)
              SELECT e.row_id, '{s1}', NULL,
                     'Vertical scan ' || e.srcip || ' -> ' || e.dstip || ' (' || max(a.services) ||
                     ' distinct {unit} refused within an hour; ' || $note || ')',
                     CASE WHEN {_INTERNAL} THEN ['T1046'] ELSE ['T1595'] END
              FROM w e
              JOIN a ON a.srcip = e.srcip AND a.dstip = e.dstip
                    AND e.ts BETWEEN a.ts AND a.ts + INTERVAL 1 HOUR
              GROUP BY e.row_id, e.srcip, e.dstip)
        """),
        # S5 allowed after probing - the same source refused on several services
        # of a host, then let through to it within an hour. Several services,
        # not one refusal: on the customer's Check Point export one dropped
        # packet before an accepted HTTPS session was 9 ordinary internal
        # clients (Q71). No ATT&CK analytic names it: an internal method (the
        # SOC benchmark's implied-rule bypass - a scan, then accepts), stated.
        (s3, f"""
            INSERT INTO findings
            SELECT * FROM (
              WITH w AS ({_DENIALS_BEFORE.format(table="product_events", deny=DENY_VERDICTS, service=service, extra="")})
              SELECT row_id, '{s3}', NULL,
                     'Allowed ' || srcip || ' -> ' || dstip || ' after ' || denials_before ||
                     ' distinct {unit} were refused in the hour before (possible policy gap; ' ||
                     $note || ')',
                     []::VARCHAR[]
              FROM w
              WHERE NOT denied AND denials_before > $above AND denials_before >= $minimum)
        """),
    ]
    m1, i1, i2, i3 = f"{prefix}-MAL-1", f"{prefix}-INTEL-1", f"{prefix}-INTEL-2", f"{prefix}-INTEL-3"
    return {
        "RULES": rules,
        # Rules whose method is a generic rule's, on this product's rows only:
        # M1 beaconing is R2007's measured method (D16 table), T1-T3 are
        # R3003-R3005's feed matches. The SQL is the generic rule's own, so the
        # two cannot drift apart while both exist (story 4 retires the generic).
        "FROM_GENERIC": ((m1, "R2007"), (i1, "R3003"), (i2, "R3004"), (i3, "R3005")),
        "PREPARE": {s1: prepare_scan_1, s2: prepare_scan_2, s3: prepare_scan_3},
        "LEVEL": {s1: "low", s2: "low", s3: "high", m1: "high", i1: "high", i2: "medium",
                  i3: "medium"},
        "LABELS": {s1: "vertical scan", s2: "horizontal scan", s3: "allowed after refusals",
                   m1: "beaconing", i1: "known-bad destination (allowed)",
                   i2: "known-bad source (allowed)", i3: "known-bad destination (blocked)"},
        # The family each rule counts in for confidence (rules.RULE_FAMILY): that
        # of the generic rule matching the same behaviour (R2002 / R2004 / R2007
        # are R2, R3003-R3005 R3).
        "FAMILY": {s1: "R2", s2: "R2", s3: "R2", m1: "R2", i1: "R3", i2: "R3", i3: "R3"},
        # The generic rule each one matches the same behaviour as (escalation
        # patterns and VERIS count behaviours, not ids)...
        "EQUIVALENT": {s1: "R2002", s2: "R2002", s3: "R2004", m1: "R2007", i1: "R3003",
                       i2: "R3004", i3: "R3005"},
        # ...and the generic rules that stop running on this product's rows
        # (story 4, D13). R2003 is R2002's count over service names - both scans
        # are SCAN-1 / SCAN-2 now. R3001 stays: no data-transfer rule yet.
        "SUPERSEDES": ("R2002", "R2003", "R2004", "R2007", "R3003", "R3004", "R3005"),
    }


def from_generic(pairs, generic: dict[str, str]) -> list[tuple[str, str]]:
    """The generic rules' SQL, renamed and run on product_events."""
    out = []
    for rid, src in pairs:
        sql = generic[src]
        assert sql.count(f"'{src}'") == 1, src
        out.append((rid, sql.replace("raw_events", "product_events").replace(f"'{src}'", f"'{rid}'")))
    return out
