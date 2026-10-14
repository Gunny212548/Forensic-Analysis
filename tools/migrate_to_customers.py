"""Move a store from the shared flat layout into one store per customer.

Before 2026-10-14 every case of every customer lived side by side in
DATA_DIR/{cases,db,raw,analysis,review,custody} and customers in
DATA_DIR/companies. Now each customer has DATA_DIR/customers/<company_id>/
(app/services/storage.py). This moves each case's files into the store of
the customer its manifest names - and nothing else:

    python tools/migrate_to_customers.py            # dry run: print the plan
    python tools/migrate_to_customers.py --apply    # do it

Evidence handling (ISO/IEC 27037, the same rules as custody.py):
- a file is moved with os.replace - a rename on the same filesystem, so its
  bytes are never rewritten;
- the raw file is hashed before the move and again after, and both must
  equal the acquisition digest on the manifest; a case that fails is left
  where it is and reported;
- each moved case gets a `relocated` custody entry (from, to, digest),
  appended to its hash chain - the chain moves with the file, so it stays
  intact;
- the manifest moves last, so an interrupted run leaves a case either fully
  in the old layout or visible in its new store with all its files.

Refuses to run while a case is queued or processing. A case without a
customer is not moved (FR-2.1 cases always have one); it is listed.
Idempotent: a second run finds nothing to move.
"""

import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import config  # noqa: E402
from app.services import custody, storage  # noqa: E402

LEGACY = ("cases", "db", "raw", "analysis", "review", "custody")


def case_files(data: Path, case_id: str) -> list[tuple[str, Path]]:
    """(subdir, file) for every file of one case in the old layout, the
    manifest last."""
    out = []
    for name in (f"{case_id}.duckdb", f"{case_id}.duckdb.wal"):
        out.append(("db", data / "db" / name))
    out += [("raw", p) for p in sorted((data / "raw").glob(f"{case_id}.*"))]
    for name in (f"{case_id}.json", f"{case_id}.job.json"):
        out.append(("analysis", data / "analysis" / name))
    out.append(("review", data / "review" / f"{case_id}.jsonl"))
    out.append(("custody", data / "custody" / f"{case_id}.jsonl"))
    out.append(("cases", data / "cases" / f"{case_id}.json"))
    return [(sub, p) for sub, p in out if p.is_file()]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true", help="move the files (default: dry run)")
    ap.add_argument("--actor", default="migrate_to_customers",
                    help="who to name on the custody entries")
    args = ap.parse_args()
    data = Path(config.DATA_DIR)

    manifests = []
    for p in sorted((data / "cases").glob("*.json")) if (data / "cases").is_dir() else []:
        try:
            manifests.append(json.loads(p.read_text(encoding="utf-8")))
        except (json.JSONDecodeError, OSError) as exc:
            print(f"SKIP {p.name}: unreadable manifest ({exc})")
    companies = sorted((data / "companies").glob("*.json")) if (data / "companies").is_dir() else []

    busy = [m["case_id"] for m in manifests if m.get("status") in ("queued", "processing")]
    if busy:
        print(f"refusing: {len(busy)} case(s) are queued or processing - wait for them: {', '.join(busy)}")
        return 1

    print(f"{'APPLY' if args.apply else 'DRY RUN'} - {len(companies)} customer(s), "
          f"{len(manifests)} case(s) in the old layout under {data}")

    # Customers first: a case can only move into a store that exists.
    for p in companies:
        company = json.loads(p.read_text(encoding="utf-8"))
        cid = company.get("company_id")
        if not storage.valid_company_id(cid or ""):
            print(f"SKIP customer file {p.name}: not a customer id")
            continue
        target = storage.customer_dir(cid) / "customer.json"
        print(f"customer {cid} ({company.get('name')}) -> {target.relative_to(data)}")
        if args.apply:
            storage.ensure_customer_store(cid)
            if target.exists():
                p.unlink()  # already migrated; the store's copy is the record
            else:
                os.replace(p, target)

    moved, problems = 0, []
    for m in manifests:
        case_id, cid = m["case_id"], m.get("company_id")
        if not cid or not storage.valid_company_id(cid):
            problems.append(f"{case_id}: no customer on the manifest - not moved")
            continue
        if not (storage.customer_dir(cid) / "customer.json").exists() and not (data / "companies" / f"{cid}.json").exists():
            problems.append(f"{case_id}: its customer {cid} does not exist - not moved")
            continue
        files = case_files(data, case_id)
        raws = [p for sub, p in files if sub == "raw"]
        recorded = (m.get("evidence") or {}).get("sha256")
        before = custody.sha256_file(raws[0]) if raws else None
        if recorded and before != recorded:
            problems.append(f"{case_id}: raw file digest {before} != acquisition digest {recorded} - not moved")
            continue
        print(f"case {case_id} -> customers/{cid}/  ({len(files)} files"
              + (f", raw sha256 {before[:16]}..." if before else ", no raw file") + ")")
        if not args.apply:
            continue
        root = storage.ensure_customer_store(cid)
        for sub, src in files:
            os.replace(src, root / sub / src.name)
        after = custody.sha256_file(root / "raw" / raws[0].name) if raws else None
        if after != before:
            # A rename cannot change bytes; if this ever fires, stop.
            print(f"STOP: {case_id} raw digest changed during the move ({before} -> {after})")
            return 2
        custody.record(case_id, "relocated", args.actor,
                       **{"from": "shared store (DATA_DIR/" + "|".join(LEGACY) + ")",
                          "to": f"customers/{cid}", "sha256": after,
                          "purpose": "each customer's evidence kept in its own store"})
        moved += 1

    if args.apply:
        for sub in LEGACY + ("companies",):
            d = data / sub
            if d.is_dir() and not any(d.iterdir()):
                d.rmdir()
    for p in problems:
        print("PROBLEM", p)
    print(f"{'moved' if args.apply else 'would move'} {moved if args.apply else len(manifests) - len(problems)} "
          f"case(s); {len(problems)} problem(s)")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
