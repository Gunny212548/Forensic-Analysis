"""Assert that a set of log files still produces the findings it used to.

Replaces "upload some files, curl /api/cases, read the table with your eyes",
which is how every ingest change up to now was validated. Exits non-zero on
any drift, so it can gate a change.

    python tests/gen_usecase.py /tmp/usecase
    python tests/check_parity.py /tmp/usecase          # ground truth
    python tests/check_parity.py "D:/forensic system/Logtest"   # full corpus
    python tests/check_parity.py <dir> --update        # rewrite the baseline

Needs FA_EMAIL / FA_PASSWORD for an account made with tools/create_user.py.

The baseline (tests/baseline.json) is keyed by the *sanitised* filename the
upload API reports back, with rows / flagged / per-rule counts. A filename
that exists in more than one version in the corpus - log_30_.csv is both a
comma and a tab separated export - stores a list of variants and is matched
by md5, so two different files sharing a name do not read as a regression.
"""

import argparse
import hashlib
import http.cookiejar
import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

BASELINE = Path(__file__).with_name("baseline.json")
LOG_SUFFIXES = {".csv", ".log", ".json", ".txt"}
DEFAULT_URL = "http://localhost:8091"
PARITY_CUSTOMER = "Parity check"


def _post_file(url: str, path: Path) -> dict:
    """Multipart upload with stdlib only - this script must not need httpx."""
    boundary = "----parity" + hashlib.md5(str(path).encode()).hexdigest()[:16]
    body = b"".join([
        # Every case needs a customer (FR-2.1). One fixed name, created on
        # first use, keeps parity runs grouped and out of real customers.
        f"--{boundary}\r\n".encode(),
        b'Content-Disposition: form-data; name="company_name"\r\n\r\n',
        f"{PARITY_CUSTOMER}\r\n".encode(),
        f"--{boundary}\r\n".encode(),
        f'Content-Disposition: form-data; name="file"; filename="{path.name}"\r\n'.encode(),
        b"Content-Type: application/octet-stream\r\n\r\n",
        path.read_bytes(),
        f"\r\n--{boundary}--\r\n".encode(),
    ])
    req = urllib.request.Request(
        f"{url}/api/upload", data=body,
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
    )
    with urllib.request.urlopen(req, timeout=300) as resp:
        return json.load(resp)


def _get(url: str) -> dict:
    with urllib.request.urlopen(url, timeout=60) as resp:
        return json.load(resp)


def login(url: str) -> None:
    """Every /api call needs a session since FR-1. Credentials come from the
    environment so they never land in shell history or the baseline:
    FA_EMAIL / FA_PASSWORD, an account made with tools/create_user.py. The
    cookie is kept by an installed opener, so _get/_post_file need no change."""
    email, password = os.environ.get("FA_EMAIL"), os.environ.get("FA_PASSWORD")
    if not (email and password):
        raise SystemExit("set FA_EMAIL and FA_PASSWORD (see tools/create_user.py)")
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    urllib.request.install_opener(opener)
    req = urllib.request.Request(
        f"{url}/api/auth/login",
        data=json.dumps({"email": email, "password": password}).encode(),
        headers={"Content-Type": "application/json"},
    )
    try:
        urllib.request.urlopen(req, timeout=30).close()
    except urllib.error.HTTPError as exc:
        raise SystemExit(f"login failed: {exc.code} {exc.reason}")


def collect(url: str, files: list[Path]) -> tuple[dict, list[str]]:
    """Upload everything, wait for every case, return {filename: [result, ...]}
    - a list per name, because a name can cover more than one file."""
    pending: list[tuple[Path, str]] = []
    notes: list[str] = []
    for path in files:
        try:
            m = _post_file(url, path)
        except urllib.error.HTTPError as exc:
            # A 0-byte file is rejected by design; that is not a failure.
            notes.append(f"{path.name}: upload rejected ({exc.code} {exc.reason})")
            continue
        pending.append((path, m["case_id"]))

    results: dict[str, dict] = {}
    deadline = time.time() + 1800
    while pending and time.time() < deadline:
        still: list[tuple[Path, str]] = []
        for path, case_id in pending:
            m = _get(f"{url}/api/cases/{case_id}")
            if m["status"] in ("queued", "processing"):
                still.append((path, case_id))
                continue
            if m["status"] == "failed":
                notes.append(f"{path.name}: case failed - {m.get('error')}")
                continue
            # Keyed by name -> list, never name -> one result: the corpus
            # holds two different files both called log_30_.csv, and a plain
            # assignment silently dropped one of them from the check.
            results.setdefault(m["original_filename"], []).append({
                "rows": m["total_rows"],
                "flagged": m["flagged_count"],
                "rules": dict(sorted((m.get("rules_matched") or {}).items())),
                "md5": hashlib.md5(path.read_bytes()).hexdigest(),
            })
        pending = still
        if pending:
            time.sleep(2)
    for path, _ in pending:
        notes.append(f"{path.name}: still processing at timeout")
    return results, notes


def _match(expected, actual: dict) -> dict | None:
    """Pick the baseline variant matching this file, by md5 when there are
    several versions of the same filename."""
    if isinstance(expected, list):
        for variant in expected:
            if variant.get("md5") == actual.get("md5"):
                return variant
        return None
    return expected


def _variants(entry) -> list[dict]:
    if entry is None:
        return []
    return entry if isinstance(entry, list) else [entry]


def compare(baseline: dict, actual: dict, scanned_md5: set[str]) -> list[str]:
    """`scanned_md5` is what was actually on disk this run, so checking a
    subdirectory reports only real drift - a baseline entry whose file was
    never offered is not missing, it just wasn't part of this run."""
    problems = []
    for name, variants in sorted(actual.items()):
        for got in variants:
            tag = f"{name} [{got['md5'][:8]}]" if len(variants) > 1 else name
            want = _match(baseline.get(name), got)
            if baseline.get(name) is None:
                problems.append(f"NEW      {tag}: not in baseline "
                                f"({got['rows']} rows, {got['flagged']} flagged)")
                continue
            if want is None:
                problems.append(f"VARIANT  {tag}: md5 {got['md5'][:8]} is a version "
                                f"the baseline does not have - different file, same name?")
                continue
            for field in ("rows", "flagged"):
                if want[field] != got[field]:
                    problems.append(
                        f"DRIFT    {tag}: {field} {want[field]:,} -> {got[field]:,}")
            if want["rules"] != got["rules"]:
                for rid in sorted(set(want["rules"]) | set(got["rules"])):
                    before, after = want["rules"].get(rid, 0), got["rules"].get(rid, 0)
                    if before != after:
                        problems.append(f"DRIFT    {tag}: {rid} {before:,} -> {after:,}")
    got_md5 = {v["md5"] for variants in actual.values() for v in variants}
    for name in sorted(set(baseline) - set(actual)):
        for variant in _variants(baseline[name]):
            md5 = variant.get("md5")
            if md5 and md5 in scanned_md5 and md5 not in got_md5:
                problems.append(f"MISSING  {name}: the file is on disk but "
                                f"produced no ready case this run")
    return problems


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("directory", help="directory to scan recursively for log files")
    ap.add_argument("--url", default=DEFAULT_URL)
    ap.add_argument("--update", action="store_true",
                    help="overwrite the baseline with this run instead of checking it")
    args = ap.parse_args()

    root = Path(args.directory)
    if not root.is_dir():
        print(f"not a directory: {root}")
        return 2
    files = sorted(p for p in root.rglob("*")
                   if p.is_file() and p.suffix.lower() in LOG_SUFFIXES)
    if not files:
        print(f"no log-shaped files under {root}")
        return 2
    print(f"{len(files)} files under {root}")

    login(args.url)
    actual, notes = collect(args.url, files)
    for note in notes:
        print(f"note: {note}")
    flat = [v for variants in actual.values() for v in variants]
    print(f"{len(flat)} cases processed under {len(actual)} distinct names, "
          f"{sum(v['rows'] for v in flat):,} rows, "
          f"{sum(v['flagged'] for v in flat):,} findings")

    if args.update:
        # MERGE, never replace. The first version of this rewrote the file
        # from whatever the run covered, so a --update pointed at one
        # subdirectory silently deleted every other entry - it took the
        # baseline from 70 entries to 67 and dropped the ground-truth pair
        # and the Check Point benchmark. A tool whose job is catching silent
        # drift must not cause it.
        merged: dict = {}
        if BASELINE.exists():
            merged = json.loads(BASELINE.read_text(encoding="utf-8"))
        kept = set(merged)
        added, updated = [], []
        for name, variants in actual.items():
            uniq: list[dict] = []
            for got in variants:
                if all(v["md5"] != got["md5"] for v in uniq):
                    uniq.append(got)
            # Keep variants of this name that this run did not see.
            seen_md5 = {v["md5"] for v in uniq}
            for old in _variants(merged.get(name)):
                if old.get("md5") and old["md5"] not in seen_md5:
                    uniq.append(old)
            new_entry = uniq[0] if len(uniq) == 1 else uniq
            if name not in merged:
                added.append(name)
            elif merged[name] != new_entry:
                updated.append(name)
            merged[name] = new_entry
        BASELINE.write_text(json.dumps(merged, indent=1, sort_keys=True), encoding="utf-8")
        untouched = len(kept - set(actual))
        print(f"baseline merged: {BASELINE} ({len(merged)} entries)")
        print(f"  {len(added)} added, {len(updated)} updated, "
              f"{untouched} left untouched (not part of this run)")
        for name in added:
            print(f"  + {name}")
        for name in updated:
            print(f"  ~ {name}")
        print("Say in CLAUDE.md what changed and why - a baseline nobody can "
              "explain is not evidence.")
        return 0

    baseline = json.loads(BASELINE.read_text(encoding="utf-8"))
    scanned_md5 = {hashlib.md5(p.read_bytes()).hexdigest() for p in files}
    problems = compare(baseline, actual, scanned_md5)
    if not problems:
        print(f"PARITY OK - {len(actual)} files match the baseline exactly")
        return 0
    print(f"\n{len(problems)} difference(s):")
    for p in problems:
        print(f"  {p}")
    print("\nIf these are intended, re-run with --update and say in CLAUDE.md "
          "what changed and why.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
