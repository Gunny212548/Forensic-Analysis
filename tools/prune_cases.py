"""Remove duplicate cases from DATA_DIR, keeping one per distinct source file.

Why this exists: nothing in the app deletes a case. `tests/check_parity.py`
uploads the whole corpus on every run, and re-processing does not replace the
old case either, so a few validation runs took one store from ~99 cases to
619 - 548 of them byte-identical re-uploads of 71 files, 4.8 GB on disk and a
dashboard nobody can read.

Duplicates are identified by the **md5 of the preserved raw file**, not by
filename: the corpus contains two different exports both called
`log_30_.csv`, and collapsing those would destroy a real case (see the
matching rule in tests/check_parity.py).

Of each duplicate group one case is kept, and *which* one is the whole
decision. The order is: a case carrying **analyst decisions** first, then one
carrying a **cached analysis**, then the newest.

That order was learned by getting it wrong. The first version kept only the
newest, which on a store full of validation re-uploads meant keeping a
freshly uploaded duplicate and deleting the older case that held the AI
analysis - 10 cached analyses went with it, each one a Groq call under a
budget of roughly one a minute. Freshness is the weakest signal here: a
duplicate has identical *content* by definition, so the copy worth keeping is
the one with work attached to it.

A case whose raw file is missing is never touched - without it the case
cannot be rebuilt, so it is the opposite of disposable.

Dry run by default. Nothing is deleted without --apply.

    docker exec <container> python tools/prune_cases.py            # report
    docker exec <container> python tools/prune_cases.py --apply    # delete
    docker exec <container> python tools/prune_cases.py --apply --keep-reviewed
"""

import argparse
import hashlib
import json
import os
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import config  # noqa: E402


def md5(path: Path) -> str:
    h = hashlib.md5()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def case_files(data: Path, case_id: str) -> list[Path]:
    """Every file belonging to one case, across all of DATA_DIR."""
    found = [
        data / "cases" / f"{case_id}.json",
        data / "db" / f"{case_id}.duckdb",
        data / "analysis" / f"{case_id}.json",
        data / "review" / f"{case_id}.jsonl",
    ]
    found += list((data / "raw").glob(f"{case_id}.*"))
    return [p for p in found if p.exists()]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true", help="actually delete (default: report only)")
    ap.add_argument(
        "--keep-reviewed",
        action="store_true",
        help="never delete a case that has analyst decisions attached",
    )
    args = ap.parse_args()

    data = Path(config.DATA_DIR)
    groups: dict[tuple[str, str], list[dict]] = defaultdict(list)
    orphans = 0

    for manifest_path in sorted((data / "cases").glob("*.json")):
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        case_id = manifest["case_id"]
        raws = list((data / "raw").glob(f"{case_id}.*"))
        if not raws:
            orphans += 1
            continue
        groups[(manifest.get("original_filename") or "?", md5(raws[0]))].append(
            {
                "case_id": case_id,
                "uploaded_at": manifest.get("uploaded_at") or "",
                "reviewed": (data / "review" / f"{case_id}.jsonl").exists(),
                "analysed": (data / "analysis" / f"{case_id}.json").exists(),
            }
        )

    doomed: list[dict] = []
    for (name, digest), members in sorted(groups.items()):
        if len(members) < 2:
            continue
        # Reviews first, then a cached analysis, then recency - see the
        # module docstring for why recency alone was the wrong rule.
        members.sort(
            key=lambda m: (m["reviewed"], m["analysed"], m["uploaded_at"]),
            reverse=True,
        )
        keep, rest = members[0], members[1:]
        for m in rest:
            if args.keep_reviewed and m["reviewed"]:
                continue
            m["name"] = name
            m["kept_instead"] = keep["case_id"]
            doomed.append(m)

    freed = 0
    for m in doomed:
        freed += sum(os.path.getsize(p) for p in case_files(data, m["case_id"]))

    print(f"cases:            {sum(len(v) for v in groups.values())}")
    print(f"distinct sources: {len(groups)}  (by filename + md5)")
    print(f"duplicates:       {len(doomed)}")
    print(f"would free:       {freed / 1e9:.2f} GB")
    if orphans:
        print(f"no raw file:      {orphans}  (left alone - cannot be rebuilt)")
    reviewed = sum(1 for m in doomed if m["reviewed"])
    if reviewed:
        print(
            f"NOTE: {reviewed} of them carry analyst decisions. "
            "Re-run with --keep-reviewed to spare those."
        )

    if not args.apply:
        print("\ndry run - nothing deleted. Pass --apply to delete.")
        for m in doomed[:10]:
            print(f"  would delete {m['case_id']}  {m['name']}  (keeping {m['kept_instead']})")
        if len(doomed) > 10:
            print(f"  ... and {len(doomed) - 10} more")
        return 0

    removed = 0
    for m in doomed:
        for p in case_files(data, m["case_id"]):
            p.unlink()
        removed += 1
    print(f"\ndeleted {removed} cases, freed {freed / 1e9:.2f} GB")
    return 0


if __name__ == "__main__":
    sys.exit(main())
