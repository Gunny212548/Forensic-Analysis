"""SigmaHQ's Windows rules in the app (specs/sigma_windows.md, story 6).

    python tests/check_sigma.py <scratch> --sigma <SigmaHQ checkout> [--repo DIR] [--dockerfile FILE]

Run in the dev container (the converted rules are at /opt/sigma, the image's build stage);
the checkout is the pinned commit's (its regression_data/ - outside the repo, copied in).
No network, no model (TRIAGE_ENABLED=0).

1. The bundle: present, its commit the Dockerfile's pin, every rule attributed (author, URL,
   DRL 1.1), the suggesting rules registered as product rules with a level, area and metadata.
2. SigmaHQ's own regression samples: each .evtx read by the app's own reader and processed by
   the pipeline, then the matches of its rule counted (findings or marks). The floor is the
   spike's measurement, 439 of 445 exact; the six that differ are named and must not change
   silently.
3. A case where one SigmaHQ rule fails still finishes, the failure listed (S-D9).
"""
import argparse
import os
import re
import sys
from pathlib import Path

FAILED: list[str] = []


def check(ok: bool, what: str) -> None:
    print(f"  {'ok  ' if ok else 'FAIL'} {what}")
    if not ok:
        FAILED.append(what)


# The samples whose count differs, measured 2026-10-29 (spike (b), then this check through the
# pipeline - the same six). A new one, or one swapped for another, fails the check.
KNOWN_DIFFER = {
    "06d71506-7beb-4f22-8888-e2e5e2ca7fd8",  # Mimikatz Use: keywords on the whole event, not convertible
    "1321dc4e-a1fe-481d-a016-52c45f0c8b4f",  # Defender exclusion added (5007): 0 of 1
    "801bd44f-ceed-4eb6-887c-11544633c0aa",  # Defender configuration changes (5007): 0 of 1
    "08249dc0-a28d-4555-8ba5-9255a198e08c",  # wscript / cscript local network connection: 0 of 1
    "7124aebe-4cd7-4ccb-8df0-6d6b93c96795",  # dtrace kernel dump: 2 of 1
    "5bac7a56-da88-4c27-922e-c81e113b20cb",  # GitHub self-hosted runner: 2 of 1
}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("scratch")
    ap.add_argument("--sigma", required=True, help="SigmaHQ checkout of the pinned commit")
    ap.add_argument("--repo", default=str(Path(__file__).resolve().parent.parent))
    ap.add_argument("--dockerfile", help="the Dockerfile holding the pin (default <repo>/Dockerfile; the "
                                         "container has none - copy it in)")
    args = ap.parse_args()
    scratch = Path(args.scratch)
    os.environ["DATA_DIR"] = str(scratch / "data")
    os.environ["AUTH_DIR"] = str(scratch / "auth")
    os.environ["TRIAGE_ENABLED"] = "0"
    sys.path.insert(0, args.repo)
    import duckdb
    import yaml
    from app.services import areas, db, pipeline, rule_meta, rules, sigma, storage

    print("the bundle")
    b = sigma.bundle()
    prov = b["provenance"] or {}
    dockerfile = Path(args.dockerfile or Path(args.repo) / "Dockerfile")
    pin = re.search(r"ARG SIGMA_COMMIT=([0-9a-f]{40})", dockerfile.read_text(encoding="utf-8"))
    check(bool(b["rules"]) and pin is not None and prov.get("commit") == pin.group(1),
          f"converted rules present, their commit the Dockerfile's pin ({prov.get('commit')})")
    check(prov.get("license") == "Detection Rule License (DRL) 1.1" and all(r["url"].startswith(
        f"https://github.com/SigmaHQ/sigma/blob/{prov.get('commit')}/") for r in b["rules"]),
        "every rule links its file at that commit, the licence named (DRL 1.1)")
    sugg = [r for r in b["rules"] if sigma.suggests(r)]
    check(sugg and all(r["level"] in ("high", "critical") and r["folder"] != "rules-threat-hunting" for r in sugg),
          f"only high / critical rules outside threat hunting suggest ({len(sugg)})")
    check(not set(sigma.TWINS) & {r["id"] for r in sugg}, "an in-house rule's twin only marks (S-D7)")
    ids = {rid for rid, _ in rules.RULES}
    check(all(r["rid"] in ids and rules.RULE_PRODUCT[r["rid"]] == "windows" and r["rid"] in rules.RULE_LEVEL
              and r["rid"] in areas.AREA_OF and r["rid"] in rule_meta.RULE_META for r in sugg),
          "each one a Windows product rule with a level, an area and metadata")
    d = rule_meta.describe(sugg[0]["rid"])
    check(d["origin"] == "SigmaHQ" and d["author"] == sugg[0]["author"] and d["url"] and d["license"],
          f"its rule card names the author, the link and the licence ({d['author']})")
    check(all(re.fullmatch(rules.RULE_ID_PATTERN, r["rid"]) for r in b["rules"]),
          "every SIGMA- id has the rule id shape")

    print("SigmaHQ's regression samples, through the pipeline")
    rid_of = {r["id"]: r["rid"] for r in b["rules"]}
    co = storage.create_company("Sigma regression")["company_id"]
    results = {"exact": 0, "differ": []}
    for info in sorted((Path(args.sigma) / "regression_data" / "rules" / "windows").rglob("info.yml")):
        doc = yaml.safe_load(info.read_text(encoding="utf-8"))
        uid = (doc.get("rule_metadata") or [{}])[0].get("id")
        for t in doc.get("regression_tests_info") or []:
            if t.get("type") != "evtx":
                continue
            ev = Path(args.sigma) / t["path"]
            want = t.get("match_count") or 1
            if uid not in rid_of or not ev.is_file():
                results["differ"].append((uid, want, None, "no rule / no sample"))
                continue
            cid = storage.create_case(ev.name, "log", ev.stat().st_size, company_id=co)["case_id"]
            pipeline.process_case(cid, ev, "log")
            con = db.connect(cid, read_only=True)
            rid = rid_of[uid]
            got = con.execute("SELECT count(DISTINCT row_id) FROM (SELECT row_id FROM findings WHERE rid = ? "
                              "UNION ALL SELECT row_id FROM sigma_marks WHERE rid = ?)", [rid, rid]).fetchone()[0]
            con.close()
            if got == want:
                results["exact"] += 1
            else:
                results["differ"].append((uid, want, got, t["path"].split("/")[-2]))
    total = results["exact"] + len(results["differ"])
    check(results["exact"] >= 439, f"{results['exact']} of {total} samples give exactly their count (floor 439)")
    for uid, want, got, where in results["differ"]:
        print(f"       differs: {where}  expected {want}, got {got}  ({uid})")
    check({uid for uid, *_ in results["differ"]} <= KNOWN_DIFFER,
          f"only the measured differences ({len(results['differ'])} of {len(KNOWN_DIFFER)} known)")

    print("a SigmaHQ rule that fails does not fail the case")
    con = duckdb.connect()
    con.execute("CREATE TABLE findings (row_id BIGINT, rid VARCHAR, lvl INTEGER, descr VARCHAR, mitre VARCHAR[], "
                "entity_src VARCHAR, entity_user VARCHAR)")
    con.execute("CREATE TABLE raw_events (row_id BIGINT, product VARCHAR, verdict VARCHAR)")
    con.execute("INSERT INTO raw_events VALUES (1, 'windows', NULL)")
    failures: dict = {}
    bad = sugg[0]["rid"]
    rules.apply_rules(con, rules=[(bad, "INSERT INTO findings SELECT * FROM no_such_table")],
                      rule_product={bad: "windows"}, failures=failures)
    check(bad in failures and "no_such_table" in failures[bad], f"listed, the others run ({failures})")
    try:
        rules.apply_rules(con, rules=[("R2000", "INSERT INTO findings SELECT * FROM no_such_table")], rule_product={})
        check(False, "one of ours failing still fails the case")
    except duckdb.Error:
        check(True, "one of ours failing still fails the case")

    print("\nSIGMA OK" if not FAILED else f"\n{len(FAILED)} FAILED")
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
