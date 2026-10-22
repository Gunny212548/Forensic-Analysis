"""Firewall rules: Palo Alto and Check Point (rules_firewall.py, rules_paloalto.py,
rules_checkpoint.py; specs/per_product_rules.md stories 2-3).

    python tests/check_firewall_rules.py [--repo DIR]

In-memory DuckDB with hand-built Palo Alto rows whose every expected finding is
known: a horizontal scanner TRW decides after 4 refused hosts, benign sources
it decides after 4 allowed ones, a vertical scan above the line measured on the
benign pairs, a source refused on one port many times (not a scan), an allow
after refusals within the hour (and one two hours later, not flagged), a
malicious PAN-DB category and grayware (not flagged), and Check Point rows
the Palo Alto rules must never touch. Also: the no-line case under 20
legitimate members, and each line's record. Needs duckdb only.
"""

import argparse
import sys
from datetime import datetime, timedelta
from pathlib import Path

FAILED: list[str] = []


def check(ok: bool, what: str) -> None:
    print(f"  {'ok  ' if ok else 'FAIL'} {what}")
    if not ok:
        FAILED.append(what)


def build(con, benign: int):
    from app.services import db, intel

    con.execute(db.SCHEMA)
    intel.create_table(con)
    con.execute("ALTER TABLE raw_events ADD COLUMN product VARCHAR")
    t0 = datetime(2026, 3, 1, 9, 0, 0)
    rows = []

    def ev(src, dst, port, verdict, sec, product="paloalto", category="any", app=None):
        rows.append((len(rows), t0 + timedelta(seconds=sec), src, dst,
                     None if port is None else str(port), verdict, category, product, app))

    # Benign internal sources: each reaches 5 hosts, all allowed (TRW: benign after 4).
    for i in range(benign):
        for h in range(5):
            ev(f"10.0.{i}.1", f"10.9.0.{h}", 443, "allow", i * 60 + h)
    # Horizontal scanner from outside: 6 hosts, all refused (TRW: scanner after 4).
    for h in range(6):
        ev("198.51.100.7", f"10.9.1.{h}", 22, "deny", 5000 + h)
    # Vertical scan: one source refused on 10 ports of one host within 10 minutes.
    for p in range(10):
        ev("203.0.113.5", "10.9.2.1", 1000 + p, "deny", 6000 + p * 60)
    # Not a scan: refused 30 times on one port.
    for k in range(30):
        ev("203.0.113.6", "10.9.2.2", 3389, "deny", 7000 + k * 30)
    # Allowed after probing 3 services within the hour; refusals on 2 services then
    # an allow 2 h later; one service refused 3 times then an allow (a retry, Q71).
    for k in range(3):
        ev("203.0.113.8", "10.9.2.3", 8080 + k, "deny", 9000 + k * 60)
    ev("203.0.113.8", "10.9.2.3", 443, "allow", 9000 + 1200)
    ev("203.0.113.9", "10.9.2.4", 8080, "deny", 9000)
    ev("203.0.113.9", "10.9.2.4", 8081, "deny", 9010)
    ev("203.0.113.9", "10.9.2.4", 443, "allow", 9000 + 7200)
    for k in range(3):
        ev("203.0.113.10", "10.9.2.5", 443, "deny", 9000 + k)
    ev("203.0.113.10", "10.9.2.5", 443, "allow", 9100)
    # PAN-DB categories: malware (flagged), grayware (not).
    ev("10.0.0.1", "192.0.2.10", 443, "allow", 11000, category="malware")
    ev("10.0.0.1", "192.0.2.11", 443, "allow", 11001, category="grayware")
    # Check Point rows shaped like a scan: never a Palo Alto finding, but a
    # Check Point one - by port (Log Exporter) and by service name with no port
    # (SmartConsole, gotcha #8). Detect is neither a refusal nor an accept.
    for p in range(10):
        ev("203.0.113.50", "10.9.3.1", 2000 + p, "deny", 12000 + p, product="checkpoint")
    for k, name in enumerate(("http", "ftp", "telnet")):
        ev("203.0.113.51", "10.9.3.2", None, "drop", 12100 + k, product="checkpoint", app=name)
    for h in range(6):
        ev("203.0.113.52", f"10.9.4.{h}", 443, "detect", 12200 + h, product="checkpoint")
    # FortiGate has no rule set yet: its scan is still the generic R2002's (story 4).
    for p in range(10):
        ev("203.0.113.60", "10.9.5.1", 3000 + p, "deny", 13000 + p, product="fortigate")
    con.executemany("INSERT INTO raw_events (row_id, ts, srcip, dstip, dstport, verdict, category, "
                    "product, app) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", rows)


def findings(con, rid):
    return {r[0] for r in con.execute(
        "SELECT DISTINCT r.srcip FROM findings f JOIN raw_events r USING (row_id) WHERE f.rid = ?",
        [rid]).fetchall()}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", default=str(Path(__file__).resolve().parent.parent))
    sys.path.insert(0, ap.parse_args().repo)
    import duckdb

    from app.services import lines, rules

    print("the line arithmetic")
    check(abs(lines.TRW_UPPER - 4.595) < 0.001 and abs(lines.LLR_FAILURE - 1.386) < 0.001,
          "TRW: ln(0.99/0.01) upper bound, ln(0.8/0.2) per failure - 4 failures decide")

    print("with 25 benign sources (a line is measured)")
    con = duckdb.connect()
    build(con, 25)
    rec: dict = {}
    matched = rules.apply_rules(con, lines=rec)
    check(findings(con, "PAN-SCAN-2") == {"198.51.100.7"}, f"horizontal scanner ({findings(con, 'PAN-SCAN-2')})")
    check(matched.get("PAN-SCAN-2") == 6, f"its 6 refused rows ({matched.get('PAN-SCAN-2')})")
    trw = rec["PAN-SCAN-2"]
    check(trw["sources"]["scanner"] == 1 and trw["sources"]["benign"] == 25,
          f"TRW decisions recorded ({trw['sources']})")
    check(trw["measured_success_benign"] == 1.0 and trw["assumption_holds"],
          "benign success ratio measured beside the paper's 0.8")
    vertical = {"203.0.113.5", "203.0.113.8", "203.0.113.9"}  # the probes refused on 2+ ports too
    check(findings(con, "PAN-SCAN-1") == vertical,
          f"vertical scans: 2+ distinct refused ports, never one port repeated ({findings(con, 'PAN-SCAN-1')})")
    check(matched.get("PAN-SCAN-1") == 15, f"their 10 + 3 + 2 refused rows ({matched.get('PAN-SCAN-1')})")
    s1 = rec["PAN-SCAN-1"]
    check(s1["method"] == "evidence-line" and s1["members"] == 127 and s1["above"] == 0 and s1["minimum"] == 2,
          f"line over 127 benign pairs (25 x 5 + 10.0.0.1's two category rows), p99 0 -> the 2-port minimum decides ({s1['members']}, {s1['above']})")
    check(findings(con, "PAN-SCAN-3") == {"203.0.113.8"},
          f"allowed after probing within the hour only - not 2 h later, not a retry ({findings(con, 'PAN-SCAN-3')})")
    check(findings(con, "PAN-MAL-2") == {"10.0.0.1"} and matched.get("PAN-MAL-2") == 1,
          "malware category flagged, grayware not")
    pan = con.execute("SELECT count(*) FROM findings f JOIN raw_events r USING (row_id) "
                      "WHERE f.rid LIKE 'PAN-%' AND r.product <> 'paloalto'").fetchone()[0]
    check(pan == 0, "no Palo Alto rule touched a Check Point row")
    check(findings(con, "CP-SCAN-1") == {"203.0.113.50", "203.0.113.51"},
          f"Check Point vertical scans, by port and by service name ({findings(con, 'CP-SCAN-1')})")
    check(not findings(con, "CP-SCAN-2") and rec["CP-SCAN-2"]["sources"]["scanner"] == 0,
          "six Detect verdicts are no scan: neither refusals nor accepts")
    check(findings(con, "R2002") == {"203.0.113.60"},
          f"the generic port scan runs only where no product rule replaces it ({findings(con, 'R2002')})")
    from app.services import products
    cells = {c["area"]: c for c in products.matrix(["paloalto", "fortigate"], rules.RULE_PRODUCT,
                                                   rules.RULE_SUPERSEDED)[0]["areas"]}
    check(cells["scanning-policy"]["rules"] == ["PAN-SCAN-1", "PAN-SCAN-2", "PAN-SCAN-3"]
          and not cells["scanning-policy"]["generic"],
          f"Palo Alto's scanning area lists its own rules only ({cells['scanning-policy']['rules']})")
    forti = {c["area"]: c for c in products.matrix(["fortigate"], rules.RULE_PRODUCT,
                                                   rules.RULE_SUPERSEDED)[0]["areas"]}
    check(forti["scanning-policy"]["rules"] == ["R2002", "R2003", "R2004"],
          "FortiGate's still lists the generic rules")
    check(con.execute(f"SELECT {rules.generic_sql(repr('PAN-MAL-1'))}").fetchone()[0] == "R2007",
          "PAN-MAL-1 counts as R2007's behaviour (escalation, VERIS)")
    tags = dict(con.execute("SELECT DISTINCT rid, mitre FROM findings WHERE rid IN ('PAN-SCAN-1', 'PAN-SCAN-2')").fetchall())
    check(tags == {"PAN-SCAN-1": ["T1595"], "PAN-SCAN-2": ["T1595.001"]},
          f"an outside source is reconnaissance, not discovery ({tags})")

    print("with 3 benign sources (no line: every pair showing the behaviour)")
    con = duckdb.connect()
    build(con, 3)
    rec = {}
    rules.apply_rules(con, lines=rec)
    check(rec["PAN-SCAN-1"]["method"] == "no-line" and rec["PAN-SCAN-1"]["members"] == 17,
          f"17 legitimate pairs - no line ({rec['PAN-SCAN-1']['members']})")
    check(findings(con, "PAN-SCAN-1") == {"203.0.113.5", "203.0.113.8", "203.0.113.9"},
          "every pair with 2 or more refused ports still goes to the analyst")
    check(findings(con, "PAN-SCAN-3") == {"203.0.113.8"}, "allowed after refusals, no line")

    print("\nFIREWALL RULES OK" if not FAILED else f"\n{len(FAILED)} FAILED")
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
