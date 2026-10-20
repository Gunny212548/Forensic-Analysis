# Gotcha #39

**39. JSON is streamed, flattened and mapped like a CSV header - and a
guess at a real Entra JSON export found nothing (2026-10-14, IAI-35).**
`parsers.iter_json` used to `read()` the whole file, JSON-lines included,
and handed nested values to the decoder as stringified dicts. Now:

- **Layouts**, stdlib only: JSON-lines a line at a time; a top-level array
  element by element (`raw_decode` over a buffer trimmed as it goes - a
  21 MB array read at a 6 MB peak); an object wrapping its records
  (`Records`, `value`, ... - `WRAPPER_KEYS`); back-to-back pretty-printed
  documents. **One pretty-printed object is still read whole** - the format
  cannot stream. A broken first line is a JSON-lines file with a bad line,
  not a pretty-printed document (only a first line ending `{` / `[` is), or
  a 10 GB file would be read into memory to find that out.
- **Records are flattened** to dotted keys (`properties.status.errorCode`);
  a list of objects stays one JSON value (Entra's applied CA policies).
- **Mapped once, like a CSV header**: the keys of the first 200 records go
  through `logsources.resolve_keys` -> documented profile or guess, on the
  manifest as `mapping` like any CSV. The guess sees camelCase keys as words
  (`sourceIPAddress` -> "source ip address"); values are read by the
  original key.
- **Unreadable entries are rows, counted**: kept as `_raw` (decoded as a text
  line), and `mapping.json` carries `layout`, `records`, `unparseable`, the
  first 3 positions and `broken_at_byte` when an array breaks off. The
  case page states it.

**Guessing is not enough for a real export, and fails silently.** Splunk
attack_data's two Entra password-spray captures (`tests/samples/`, Azure
Monitor diagnostic JSON: an envelope around the Graph signIn object) gave
31 rows and **0 findings** by guess - `properties.userDisplayName` won the
loose "user" match (gotcha #27's trap again) and the numeric `errorCode` is
no auth vocabulary, so no row had an outcome. The `entra-signin-azure-monitor`
profile reads `properties.userPrincipalName`, `properties.ipAddress`,
`properties.createdDateTime` (Graph: when the sign-in was initiated; the
envelope `time` differs by 28 minutes in the capture) and maps errorCode
`0` -> success and only the codes Microsoft's AADSTS reference names as
credential failures (50126, 50034, 50053, 50056, 50064) -> failed.
Microsoft publishes no "interrupted" list for errorCode, but its own code
names say `KmsiInterrupt` (50140) / `...Interrupt` (50074, 50125); counting
every non-zero code would turn a keep-me-signed-in prompt into a failed
login. Unknown codes count as nothing, like `Interrupted` in the CSV.

There is **no profile for the Graph / portal "Download JSON" shape** (the
same signIn object without the envelope): no real file of it has been
tested, and it would guess `userDisplayName` the same way.

Measured: the two captures -> R1000 x31 + R2000 x31 (one source, 31
accounts) and R1000 x31 alone (30 sources, 31 accounts, 26 s). **That
second file is a distributed spray no rule sees** - R2000 needs 3 failures
per source, R2005 5 sources per account, and each here has 1. And R2000
names a one-source-many-accounts spray "brute-force" - the label the
narrative will repeat. Both are rule work, not parser work.
gen_usecase now also writes the firewall as a JSON array (documented
PAN-OS profile) and as nested gzipped JSON-lines with two bad lines
(guessed): same findings as the CSV and all 26 decoded rows identical.
Corpus parity unchanged (67 files); baseline +4 (the twins, the captures).

Validated in a container built from the branch on a scratch store, not on
the host: the host has DuckDB 1.5.5 (the image pins 1.1.3), and under 1.5.5
`intel.fill()`'s `read_csv` no longer sniffs the quotes in the IOC staging
file (a ThreatFox note with commas, line 39,302) and every case fails.
**Fixed the same day by the upgrade to DuckDB 1.5.6** (image and
`requirements.txt`): `intel.fill()` now states the dialect it wrote
(`auto_detect=false`, `delim`, `quote`, `escape`), as the stage read in
`pipeline` already did. Verified on 1.5.6 in a container: corpus parity
(67 files), gen_usecase, `tests/samples` and `check_mcp` (44) all OK; a case
DuckDB written by 1.1.3 opens in 1.5.6 and one written by 1.5.6 opens in
1.1.3, so a rollback reads the files written meanwhile. 1.5.6 has
`connection.query_progress()`, so the CSV fast path's elapsed-time estimate
(FR-2.5) could become a measurement - not done yet.
