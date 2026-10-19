"""A case manifest is rewritten from several threads (pipeline progress, the
CSV estimator, status changes, a reader polling it). Nothing may be lost or
torn.

    python tests/check_manifest_atomic.py <scratch dir>

Five checks against storage.update_case / load_manifest:
- N threads each set their own key 200 times: every key survives (no lost
  update from the load-modify-save window);
- a late progress write cannot undo a status change made by another thread;
- a reader polling during the writes never sees a missing or half-written
  manifest;
- updating a case that does not exist is still a no-op;
- a corrupt manifest raises at once instead of retrying for seconds.

stdlib + the app's own modules; no network.
"""

import os
import sys
import tempfile
import threading
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
FAILED: list[str] = []


def check(ok: bool, what: str) -> None:
    print(f"  {'ok  ' if ok else 'FAIL'} {what}")
    if not ok:
        FAILED.append(what)


def main() -> int:
    scratch = Path(sys.argv[1] if len(sys.argv) > 1 else tempfile.mkdtemp())
    scratch.mkdir(parents=True, exist_ok=True)
    os.environ["DATA_DIR"] = str(scratch / "data")
    sys.path.insert(0, str(REPO))
    from app.services import storage

    storage.ensure_root()
    company = storage.create_company("Atomic check")
    case = storage.create_case("a.csv", "csv", 1, company_id=company["company_id"],
                               company_name=company["name"])
    cid = case["case_id"]

    # 1. no lost update
    keys = [f"k{i}" for i in range(8)]

    def writer(k):
        for n in range(int(os.environ.get("N", 200))):
            storage.update_case(cid, **{k: n})

    ths = [threading.Thread(target=writer, args=(k,)) for k in keys]
    for t in ths:
        t.start()
    for t in ths:
        t.join()
    m = storage.load_manifest(cid)
    check(all(m.get(k) == int(os.environ.get("N", 200)) - 1 for k in keys), "8 threads x 200 writes: every key kept its last value")

    # 2. a progress writer racing a status change
    storage.update_case(cid, status="processing")
    stop = threading.Event()
    seen = {"missing": 0, "torn": 0, "reads": 0}

    def progress():
        n = 0
        while not stop.is_set():
            n += 1
            storage.update_case(cid, progress={"stage": "ingest", "pct": n % 90})

    def reader():
        while not stop.is_set():
            seen["reads"] += 1
            try:
                if storage.load_manifest(cid) is None:
                    seen["missing"] += 1
            except Exception:  # noqa: BLE001 - JSONDecodeError, PermissionError
                seen["torn"] += 1

    bg = [threading.Thread(target=progress), threading.Thread(target=reader)]
    for t in bg:
        t.start()
    final_ok = True
    for i in range(int(os.environ.get("R", 300))):
        storage.update_case(cid, status="ready", total_rows=i)
        if storage.load_manifest(cid)["status"] != "ready":
            final_ok = False
    stop.set()
    for t in bg:
        t.join()
    check(final_ok, "a progress write never reverted status 'ready' (300 rounds)")
    check(seen["missing"] == 0 and seen["torn"] == 0,
          f"reader saw no missing/torn manifest in {seen['reads']} reads "
          f"(missing {seen['missing']}, torn {seen['torn']})")

    # 3. unknown case
    try:
        storage.update_case("c-doesnotexist", status="x")
        check(True, "updating an unknown case is a no-op")
    except Exception as exc:  # noqa: BLE001
        check(False, f"updating an unknown case is a no-op ({exc!r})")

    # 4. a corrupt manifest raises at once (no retry loop holding up every reader)
    import json
    bad = storage.manifest_path(cid)
    good = bad.read_text(encoding="utf-8")
    bad.write_text("{ not json", encoding="utf-8")
    t0 = time.monotonic()
    try:
        storage.load_manifest(cid)
        raised = False
    except json.JSONDecodeError:
        raised = True
    took = time.monotonic() - t0
    bad.write_text(good, encoding="utf-8")
    check(raised and took < 0.5, f"a corrupt manifest raises at once ({took:.2f}s)")

    print("FAILED: " + "; ".join(FAILED) if FAILED else "ALL OK")
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
