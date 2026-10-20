# Gotcha #35

**35. Threat-intel feeds can be STIX 2.1 bundles (2026-10-12).** A `.json`
file in `DATA_DIR/intel/` is read by `intel._parse_stix()` - the form a
TAXII collection, OpenCTI or MISP exports. Only `indicator` objects whose
pattern is *nothing but* `ipv4-addr`/`ipv6-addr` `value =` comparisons joined
by OR are taken; anything that adds a condition (AND a port, WITHIN,
ISSUBSET, other object paths, non-STIX pattern types) is skipped and
counted, because keeping just the IP would widen "this address on port 443
for 5 minutes" into "this address, always". Revoked indicators are skipped;
`valid_until` is quoted in the note but **not** compared to the clock - that
would make re-runs over the same feed differ (gotcha #17). The source shown
on findings is the bundle's `created_by_ref` identity name. There is no
TAXII client: fetching stays out-of-band, like `refresh_intel.py`.

Found by testing the whole pipeline, not the parser: `build_staging()` had
its own copy of the feed-suffix list without `.json`, so STIX feeds parsed
fine and were never loaded. Both now read `intel.FEED_SUFFIXES`. Verified
with a stix2-library-built feed covering every accept/skip case (exact
match) and on `src10-8-3-215.csv`: R3003 fired on the three beacon
destinations, quoting the feed and indicator name.
