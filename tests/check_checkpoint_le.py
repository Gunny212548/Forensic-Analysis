"""Check Point Log Exporter records in an EventLog Analyzer export (IAI-85,
app/services/checkpoint_le.py, specs/IAI-85_checkpoint_log_exporter.md).

    python tests/check_checkpoint_le.py <scratch dir> [--repo DIR] [--real FILE]

Runs the committed synthetic sample (tests/samples/checkpoint-log-exporter,
expected counts in its README) through the real pipeline in a throwaway store,
plain, .gz and inside a .zip, and checks:

- the record grammar of the Log Exporter guide: separators, quoted values,
  the three escapes, a value holding `;` and `=` not split;
- identification: the export is this source; the same export holding other
  devices' messages is named and not read; a SmartConsole header is unchanged;
- the mapping (sk144192 names), epoch time (seconds and milliseconds) read as
  UTC and never flagged timezone-unconfirmed;
- update logs: one connection per loguid carries the verdict, the rest are
  `log_update`; a row that is not a record is loaded, counted, never dropped;
- the same counts plain, .gz and zipped (IAI-85 AC);
- with --real, the user's export: 20,000 rows, 9,591 connections.

duckdb + the app's own modules; no server, no network.
"""

import argparse
import gzip
import os
import shutil
import sys
import zipfile
from pathlib import Path
os.environ.setdefault("TRIAGE_ENABLED", "0")  # rules are measured here, not the AI review (triage.py)

REPO = Path(__file__).resolve().parent.parent
SAMPLE = REPO / "tests" / "samples" / "checkpoint-log-exporter" / "eventlog-analyzer-search-export.csv"
FAILED: list[str] = []


def check(ok: bool, what: str) -> None:
    print(f"  {'ok  ' if ok else 'FAIL'} {what}")
    if not ok:
        FAILED.append(what)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("scratch")
    ap.add_argument("--repo", default=str(REPO))
    ap.add_argument("--real", help="the user's EventLog Analyzer export (not committed)")
    args = ap.parse_args()
    scratch = Path(args.scratch)
    shutil.rmtree(scratch, ignore_errors=True)
    store = scratch / "store"
    store.mkdir(parents=True)
    os.environ["DATA_DIR"] = str(store)
    sys.path.insert(0, args.repo)
    from app.services import checkpoint_le, db, identify, pipeline, storage

    print("record grammar")
    f = checkpoint_le.parse_body('11241 - [a:"1"; tag:"x=1;y=2[z\\]"; q:"say \\"hi\\" \\\\ end"; b:""]')
    check(f == {"a": "1", "tag": "x=1;y=2[z]", "q": 'say "hi" \\ end', "b": ""},
          f"fields split, escapes undone, `;` inside a value kept ({f})")
    check(checkpoint_le.parse_body("no body here") == {}, "a text with no `[` has no fields")
    check(not checkpoint_le.is_record({"src": "1.2.3.4"}), "a record needs loguid and origin")

    print("identification")
    r = identify.identify(SAMPLE, "csv")
    check((r["status"], r["custom"], r["sigma"]) == ("supported", "checkpoint_log_exporter",
                                                       {"category": "firewall"}),
          f"the sample is a Log Exporter export ({r['status']}, {r['custom']})")
    other = scratch / "other.csv"
    lines = SAMPLE.read_text(encoding="utf-8").splitlines()
    other.write_text("\n".join(lines[:2] + ['1,"something else entirely",-,Windows,192.0.2.9,2026-10-21 10:00:00'] * 3)
                     + "\n", encoding="utf-8")
    r = identify.identify(other, "csv")
    check((r["status"], r["custom"]) == ("no_reader", "manageengine_eventlog_analyzer"),
          f"the same export of other messages is named and not read ({r['status']})")
    plain_csv = scratch / "plain.csv"
    plain_csv.write_text("\n".join(lines[1:]) + "\n", encoding="utf-8")
    check(identify.identify(plain_csv, "csv")["status"] == "unrecognised",
          "without its Search Results line the header is no documented source - nothing guessed")

    co = storage.create_company("Check Point LE")

    def run(src: Path, kind: str, ext: str) -> dict:
        m = storage.create_case(src.name, kind, src.stat().st_size, company_id=co["company_id"],
                                company_name=co["name"])
        raw = storage.raw_path(m["case_id"], ext)
        shutil.copyfile(src, raw)
        pipeline.process_case(m["case_id"], raw, kind)
        return storage.load_manifest(m["case_id"])

    def facts(m: dict) -> tuple:
        mp = (m.get("members") or [{}])[0].get("mapping") if m.get("members") else m.get("mapping")
        con = db.connect(m["case_id"], read_only=True)
        try:
            verdicts = dict(con.execute("SELECT coalesce(verdict, action, '-'), count(*) FROM raw_events "
                                        "GROUP BY 1").fetchall())
        finally:
            con.close()
        return (m["status"], m["total_rows"], (mp or {}).get("log_exporter"), verdicts, m.get("rules_matched"))

    print("plain")
    m = run(SAMPLE, "csv", "csv")
    status, rows, le, verdicts, matched = facts(m)
    check(status == "ready" and rows == 10, f"ready, 10 rows ({status}, {rows})")
    check(le == {"rows": 10, "records": 9, "not_records": 1, "connections": 7, "log_updates": 2},
          f"9 records, 1 row that is not one, 7 connections, 2 update logs ({le})")
    check(verdicts == {"allow": 2, "drop": 1, "reject": 1, "block": 1, "detect": 1, "log_update": 2, "-": 2},
          f"one verdict per connection; Key Install and the non-record carry none ({verdicts})")
    check(matched == {"R3001": 2}, f"R3001 on the two update rows that carry > 50 MB ({matched})")
    events = {e["row_id"]: e for e in db.list_raw(m["case_id"], 20, 0)}
    check(events[0]["ts"].startswith("2026-10-21 10:23:08") and events[0]["ts_raw"] == "1792552988",
          f"epoch seconds -> GMT+7 ({events[0]['ts']})")
    check(events[7]["ts"].startswith("2026-10-21 10:23:10"), f"epoch milliseconds ({events[7]['ts']})")
    check(events[0]["username"] == "Alice Example (alice)" and events[7]["username"] == "bob",
          "src_user_name, else user")
    check(events[1]["event"] == "Log update (same connection)", "an update row is typed as one")
    check(events[8]["ts"] is None and events[8]["raw"].startswith("12345 - not a Check Point"),
          "the row that is not a record is loaded with its text")
    flags = {fl for fd in db.collapsed_findings(m["case_id"]) for fl in fd["flags"]}
    check("timezone-unconfirmed" not in flags, f"an epoch states its zone - no timezone-unconfirmed ({flags})")
    base = facts(m)[1:]

    print("compressed")
    gz = scratch / "export.csv.gz"
    with open(SAMPLE, "rb") as src, gzip.open(gz, "wb") as dst:
        dst.write(src.read())
    check(facts(run(gz, "csv", "csv.gz"))[1:] == base, "a .csv.gz reads the same")
    zp = scratch / "export.zip"
    with zipfile.ZipFile(zp, "w") as z:
        z.write(SAMPLE, "export.csv")
    check(facts(run(zp, "zip", "zip"))[1:] == base, "the file inside a .zip reads the same")

    if args.real:
        print("the user's export")
        _, rows, le, verdicts, _ = facts(run(Path(args.real), "csv", "csv"))
        check(rows == 20000 and le["connections"] == 9591 and le["log_updates"] == 10409
              and le["not_records"] == 0, f"20,000 rows: 9,591 connections, 10,409 updates ({le})")

    print()
    print(f"{len(FAILED)} FAILED" if FAILED else "CHECKPOINT LE OK")
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
