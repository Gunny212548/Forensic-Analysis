# Gotcha #17

**17. Threat intel is offline on purpose, and it is just a JOIN.**
`intel.py` parses whatever is in `DATA_DIR/intel/` into one canonical `ioc`
table per case; `R3003` (known-bad destination, high) and `R3004`
(known-bad source, medium) join it. Nothing about analysis touches the
network - `tools/refresh_intel.py` downloads the feeds as a separate step, so
a case can be worked air-gapped and re-running it over the same feed files
gives the same findings, which matters when the output is evidence.

- The parser is format-agnostic, not one-per-feed: comment-prefixed CSV
  (abuse.ch Feodo, ThreatFox) or a bare list of addresses (blocklist.de,
  CINS, Tor exit nodes), plus anything a customer hands over in either shape.
  Only IP indicators are kept - the canonical schema has no URL, hash or
  domain column to match one against. Private/loopback/multicast addresses
  are dropped: a feed listing RFC1918 space would flag every internal flow.
- `R3004` is deliberately *lower* severity than `R3003`. Feeds like
  blocklist.de list any host that has ever probed anyone, so being scanned by
  one is background noise; talking **to** C2 infrastructure is not. On the
  corpus this is exactly what showed up - 2,480 hits, all inbound scanners
  against the customer's public addresses (and allowed).
- Indicators are loaded **after** ingest, filtered to addresses that appear
  in the case's own traffic (`intel.fill`). An indicator nobody talked to
  cannot produce a finding, and storing all ~43k in all 93 case files
  inflated every DuckDB for nothing.
- Feed snapshot at time of writing: 42,952 usable IPs from 5 feeds
  (blocklist_de 24,577 / cins 14,724 / threatfox 2,365 / tor 1,286).
  **Replaced 2026-10-14** when the whole store was reset: the old feed files
  went with it (no backup), so the old R3004 counts cannot be reproduced.
  Re-fetched: 44,514 (blocklist_de 25,729 / cins 14,759 / threatfox 2,846 /
  tor 1,180). The baseline was re-taken on it - only `R3004` moved, in 6
  files (`log_22_` 324 -> 318, `log_23_`/`log_24_` -> 319, `log_25_`/`log_26_`
  100 -> 92, `log_27_` 68 -> 73), every other rule and every row count
  identical. **A feed refresh moves R3003-R3006 by design**; re-take the
  baseline after one and say so, as here.
