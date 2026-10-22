"""Products and periods (specs/per_product_rules.md story 1: D11, D12, D15).

    python tests/check_products.py <scratch> [--repo DIR]

Three parts. In-memory DuckDB with hand-built rows: the product written on each
item's rows, a product rule reading only its product's rows and skipped when
the case has none, an unknown product refused. The period of an item: span,
days with events, gaps, events per day, rows without a time. The detection
matrix: a not-applicable cell with its reason, generic rules counted for every
product, "no rule yet". Then end to end through the pipeline on gen_usecase's
two files zipped into one case: each member's product and period on the
manifest, and the findings unchanged by the product column. Needs duckdb only.
"""

import argparse
import os
import subprocess
import sys
import zipfile
from datetime import date, datetime, timedelta
from pathlib import Path

FAILED: list[str] = []


def check(ok: bool, what: str) -> None:
    print(f"  {'ok  ' if ok else 'FAIL'} {what}")
    if not ok:
        FAILED.append(what)


def unit() -> None:
    import duckdb

    from app.services import db, period, pipeline, products, rules

    con = duckdb.connect()
    con.execute(db.SCHEMA)
    t0 = datetime(2026, 1, 1, 9, 0, 0)
    # Item A (rows 0-5): firewall rows on 1, 2 and 6 January - a 3-day gap.
    # Item B (rows 6-8): sshd rows, one without a time.
    days = [0, 0, 1, 5, 5, 5]
    for i, d in enumerate(days):
        con.execute("INSERT INTO raw_events (row_id, ts, srcip, verdict) VALUES (?, ?, ?, 'deny')",
                    [i, t0 + timedelta(days=d), f"10.0.0.{i}"])
    con.execute("INSERT INTO raw_events (row_id, ts, srcip, action) VALUES "
                "(6, ?, '10.1.0.1', 'auth_failed'), (7, ?, '10.1.0.1', 'auth_failed'), "
                "(8, NULL, '10.1.0.1', 'auth_failed')", [t0, t0 + timedelta(minutes=1)])
    items = [("fw.csv", "row_id BETWEEN ? AND ?", [0, 5], {"logsource": {"profile": "paloalto-traffic"}}),
             ("auth.log", "row_id BETWEEN ? AND ?", [6, 8], {"logsource": {"profile": "openssh-sshd"}}),
             ("odd.txt", "row_id BETWEEN ? AND ?", [9, 9], {"logsource": {"profile": None}})]

    print("the product of every row")
    present = pipeline.mark_products(con, items)
    check(present == ["paloalto", "linux"], f"products present, in order ({present})")
    got = dict(con.execute("SELECT product, count(*) FROM raw_events GROUP BY product").fetchall())
    check(got == {"paloalto": 6, "linux": 3}, f"each item's rows carry its product ({got})")
    pipeline.mark_products(con, items)
    check(con.execute("SELECT count(*) FROM raw_events").fetchone()[0] == 9,
          "marking twice changes nothing")

    print("a product rule reads only its product's rows")
    test_rules = [
        ("T-PAN", "INSERT INTO findings SELECT row_id, 'T-PAN', NULL, 'pan', ['T0000'] FROM product_events"),
        ("T-CP", "INSERT INTO findings SELECT row_id, 'T-CP', NULL, 'cp', ['T0000'] FROM product_events"),
        ("T-ANY", "INSERT INTO findings SELECT row_id, 'T-ANY', NULL, 'any', ['T0000'] FROM raw_events "
                  "WHERE action = 'auth_failed'"),
    ]
    calls = []
    matched = rules.apply_rules(con, on_rule=lambda i, n: calls.append((i, n)), rules=test_rules,
                                rule_product={"T-PAN": "paloalto", "T-CP": "checkpoint"})
    check(matched == {"T-PAN": 6, "T-ANY": 3}, f"rows matched per rule ({matched})")
    pan_rows = {r[0] for r in con.execute("SELECT row_id FROM findings WHERE rid = 'T-PAN'").fetchall()}
    check(pan_rows == set(range(6)), "the Palo Alto rule matched Palo Alto rows only")
    check(calls == [(1, 3), (2, 3), (3, 3)], "progress is reported for a skipped rule too")
    try:
        rules.apply_rules(con, rules=test_rules[:1], rule_product={"T-PAN": "pan'; DROP TABLE x; --"})
        check(True, "an unknown product never reaches SQL (not present, skipped)")
    except ValueError:
        check(False, "an unknown product never reaches SQL")
    con.execute("UPDATE raw_events SET product = 'bogus' WHERE row_id = 0")
    try:
        rules.apply_rules(con, rules=test_rules[:1], rule_product={"T-PAN": "bogus"})
        check(False, "a product outside products.PRODUCTS is refused")
    except ValueError:
        check(True, "a product outside products.PRODUCTS is refused")
    con.execute("UPDATE raw_events SET product = 'paloalto' WHERE row_id = 0")
    old = duckdb.connect()
    old.execute(db.SCHEMA)
    check(rules._products_present(old) == set(), "a store without the product column has no products")

    print("the period each item covers")
    p = period.measure(con, "row_id BETWEEN ? AND ?", [0, 5])
    check((p["first"], p["last"]) == ("2026-01-01 09:00:00", "2026-01-06 09:00:00"),
          f"first and last event ({p['first']} - {p['last']})")
    check((p["span_days"], p["active_days"]) == (6, 3), f"6-day span, 3 days with events "
          f"({p['span_days']}, {p['active_days']})")
    check((p["gap_count"], p["gap_days"]) == (1, 3)
          and p["longest_gaps"] == [{"from": "2026-01-03", "to": "2026-01-05", "days": 3}],
          f"one gap of 3 days, 3-5 January ({p['longest_gaps']})")
    check(p["events_per_day"] == {"min": 1, "median": 2, "max": 3},
          f"events per day ({p['events_per_day']})")
    q = period.measure(con, "row_id BETWEEN ? AND ?", [6, 8])
    check(q["rows_without_time"] == 1 and q["gap_count"] == 0 and q["span_days"] == 1,
          f"a row without a time is counted, not dated ({q['rows_without_time']})")
    e = period.measure(con, "row_id = ?", [99])
    check(e["span_days"] == 0 and e["first"] is None and e["events_per_day"] is None,
          "an item without timed rows has no period")
    year = [(date(2025, 1, 1) + timedelta(days=d), 1) for d in range(0, 365, 2)]
    y = period.summarise(len(year), len(year), datetime(2025, 1, 1), datetime(2025, 12, 31), year)
    check(y["span_days"] == 365 and y["gap_count"] == 182 and len(y["longest_gaps"]) == period.LONGEST_GAPS,
          f"a year with every other day silent: 182 gaps, {period.LONGEST_GAPS} listed")

    print("what each product's areas run")
    m = {c["area"]: c for c in products.matrix(["paloalto"], rules.RULE_PRODUCT)[0]["areas"]}
    check(m["authentication"]["status"] == "n/a" and "sign-ins" in m["authentication"]["reason"],
          "Palo Alto Authentication is not applicable, with the reason")
    check(m["scanning-policy"]["status"] == "rules" and m["scanning-policy"]["generic"],
          f"generic rules run on Palo Alto until they are retired ({m['scanning-policy']['rules']})")
    every_cp = {rid: "checkpoint" for rid in rules.RULE_LEVEL}
    every_cp.update({rid: "checkpoint" for rid, _ in rules.RULES})
    n = {c["area"]: c for c in products.matrix(["linux"], every_cp)[0]["areas"]}
    check(n["scanning-policy"]["status"] == "none", "an area with no rule for the product reads 'no rule yet'")
    check({pid for pid, p in products.PRODUCTS.items() if p["type"] not in ("firewall", "os", None)} == set(),
          "every product is a firewall, an OS or not yet classified")
    profiles = [p for prod in products.PRODUCTS.values() for p in prod["profiles"]]
    check(len(profiles) == len(set(profiles)), "a profile belongs to one product")


def end_to_end(scratch: Path) -> None:
    import duckdb

    os.environ["DATA_DIR"] = str(scratch / "store")
    from app.services import db, intel, pipeline, rules, storage

    print("end to end: gen_usecase's two files in one zip")
    company = storage.create_company("Products Co")
    zpath = scratch / "nightfall.zip"
    cid = storage.create_case("nightfall.zip", "zip", zpath.stat().st_size,
                              company_id=company["company_id"])["case_id"]
    pipeline.process_case(cid, zpath, "zip")
    man = storage.load_manifest(cid)
    check(man.get("status") == "ready", f"processed ({man.get('status')}: {man.get('error')})")
    check(man.get("products") == ["linux", "paloalto"], f"products on the manifest ({man.get('products')})")
    per = {p["item"]: p for p in man.get("periods") or []}
    check(set(per) == {"nightfall-auth.log", "nightfall-firewall.csv"}, "a period per member")
    check(all(p["first"] and p["span_days"] >= 1 for p in per.values()), "each period is dated")
    check(per["nightfall-firewall.csv"]["product"] == "paloalto", "each period names its product")
    det = {d["product"]: d for d in man.get("detection") or []}
    check(det["paloalto"]["areas"][0]["status"] == "n/a", "the case says Palo Alto Authentication is n/a")
    check(det["linux"]["areas"][0]["status"] == "rules", "Linux Authentication runs rules")

    # The same rows without the product column, through the same rules.
    con = duckdb.connect()
    con.execute(f"ATTACH '{db.db_path(cid).as_posix()}' AS c (READ_ONLY)")
    con.execute("CREATE TABLE raw_events AS SELECT * EXCLUDE (product) FROM c.raw_events")
    con.execute(db.SCHEMA)
    intel.create_table(con)
    con.execute("INSERT INTO ioc SELECT * FROM c.ioc")
    before = rules.apply_rules(con)
    generic = {k: v for k, v in (man.get("rules_matched") or {}).items() if k not in rules.RULE_PRODUCT}
    check(before == generic, f"generic rules' findings unchanged by the product column ({before})")
    check(not any(k in rules.RULE_PRODUCT for k in before),
          "without the column no product rule runs")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("scratch")
    ap.add_argument("--repo", default=str(Path(__file__).resolve().parent.parent))
    args = ap.parse_args()
    sys.path.insert(0, args.repo)
    scratch = Path(args.scratch)
    scratch.mkdir(parents=True, exist_ok=True)
    unit()
    uc = scratch / "usecase"
    subprocess.run([sys.executable, str(Path(__file__).with_name("gen_usecase.py")), str(uc)],
                   check=True, capture_output=True)
    with zipfile.ZipFile(scratch / "nightfall.zip", "w") as z:
        z.write(uc / "nightfall-auth.log", "nightfall-auth.log")
        z.write(uc / "nightfall-firewall.csv", "nightfall-firewall.csv")
    end_to_end(scratch)
    print("\nPRODUCTS OK" if not FAILED else f"\n{len(FAILED)} FAILED")
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
