"""Download public threat-intel feeds into DATA_DIR/intel/.

This is the ONLY part of the system that touches the network, and it is
deliberately a separate script: analysis itself must stay offline and
reproducible, so feeds are refreshed on purpose rather than on every case.

    docker exec forensic-analyzer-forensic-analyzer-1 python tools/refresh_intel.py

A feed that fails is skipped with a warning - several of these are rate
limited or blocked from some networks, and a stale file is far better than
no file. Customer-supplied IOC lists can simply be copied into the same
directory; anything with an IP per line, or a CSV with an IP column, is
picked up by intel.load_indicators().
"""

import sys
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.services import intel  # noqa: E402

FEEDS = {
    # abuse.ch Feodo Tracker - botnet C2 servers, with malware family.
    "feodo_c2.csv": "https://feodotracker.abuse.ch/downloads/ipblocklist.csv",
    # abuse.ch ThreatFox - recent ip:port IOCs, malware family + confidence.
    "threatfox.csv": "https://threatfox.abuse.ch/export/csv/ip-port/recent/",
    # blocklist.de - hosts seen attacking (SSH brute force, mail, web).
    "blocklist_de.txt": "https://lists.blocklist.de/lists/all.txt",
    # CINS Army - poor-reputation addresses.
    "cins_badguys.txt": "https://cinsscore.com/list/ci-badguys.txt",
    # Tor exit nodes - not malicious, but material context for an analyst.
    "tor_exit.txt": "https://check.torproject.org/torbulkexitlist",
}

TIMEOUT = 45


def main() -> int:
    target = intel.intel_dir()
    target.mkdir(parents=True, exist_ok=True)

    ok = failed = 0
    for name, url in FEEDS.items():
        path = target / name
        try:
            request = urllib.request.Request(
                url, headers={"User-Agent": "forensic-analyzer/1.0"}
            )
            with urllib.request.urlopen(request, timeout=TIMEOUT) as resp:
                body = resp.read()
        except (urllib.error.URLError, OSError, TimeoutError) as exc:
            kept = " (keeping existing file)" if path.exists() else ""
            print(f"  SKIP {name}: {exc}{kept}")
            failed += 1
            continue
        path.write_bytes(body)
        print(f"  ok   {name}: {len(body):,} bytes")
        ok += 1

    indicators = intel.load_indicators()
    print(f"\n{ok} feed(s) refreshed, {failed} skipped -> "
          f"{len(indicators):,} usable IP indicators")

    by_source: dict[str, int] = {}
    for _, _, source, _ in indicators:
        by_source[source] = by_source.get(source, 0) + 1
    for source, n in sorted(by_source.items(), key=lambda kv: -kv[1]):
        print(f"  {source:<20} {n:>7,}")

    # Force the normalised staging file to be rebuilt on the next case.
    intel.staging_path().unlink(missing_ok=True)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
