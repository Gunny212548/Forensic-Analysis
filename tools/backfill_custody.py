"""Record a SHA-256 for cases uploaded before acquisition digests existed.

The upload handler has computed a digest since 2026-10-12 (custody.py). A
case uploaded earlier has none, so nothing can show its raw file is the one
that was handed over. This tool hashes those files *now* and says so: the
manifest's `evidence.retroactive` is true and the custody log's first entry
is `acquired_retroactively`. That digest proves the file has not changed
since this moment - it cannot speak for the time before, and the UI does not
pretend it does.

Cases that already carry a digest are left alone. Dry run by default.

    docker exec <container> python tools/backfill_custody.py           # report
    docker exec <container> python tools/backfill_custody.py --apply   # record
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.services import custody, storage  # noqa: E402

ACTOR = "system:tools/backfill_custody.py"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true", help="record the digests (default: report only)")
    args = ap.parse_args()

    todo, missing = [], []
    for m in storage.list_manifests():
        if (m.get("evidence") or {}).get("sha256"):
            continue
        raws = sorted(storage.case_dir(m["case_id"], "raw").glob(f"{m['case_id']}.*"))
        (todo if raws else missing).append((m, raws[0] if raws else None))

    for m, raw in todo:
        sha = custody.sha256_file(raw)
        size = raw.stat().st_size
        print(f"{'record' if args.apply else 'would record'} {m['case_id']} "
              f"{m.get('original_filename')!r}: {sha}")
        if args.apply:
            custody.record(
                m["case_id"], "acquired_retroactively", ACTOR, sha256=sha, bytes=size,
                original_filename=m.get("original_filename"), stored_as=raw.name,
                note="uploaded before acquisition digests were recorded; this digest "
                     "attests the file only from now on",
            )
            storage.update_case(m["case_id"], evidence=custody.evidence(sha, size, ACTOR, retroactive=True))
    for m, _ in missing:
        print(f"SKIP {m['case_id']} {m.get('original_filename')!r}: raw file missing")
    print(f"{len(todo)} case(s) {'recorded' if args.apply else 'to record'}, "
          f"{len(missing)} without a raw file")
    return 0


if __name__ == "__main__":
    sys.exit(main())
