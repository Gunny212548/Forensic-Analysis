# Gotcha #43

**43. Check Point's SmartConsole export is read by its documentation, and
every case now says how much of its file was read (2026-10-14, IAI-31).**
Profile `checkpoint-smartconsole`: the columns are sk144192's *display
names* (Time, Action, Source, Destination, Service, Source User Name...),
which is what a SmartConsole / SmartView log export writes. The guess had
already mapped the same columns (gotcha #7 fixed the hard part), so the
benchmark is unchanged - 45,209 / 45,201, R2001 42,223, R2003 42,223, R2004
2,978, identical plain / `.gz` / `.zip` - but the case now cites the
source, and two values are read on purpose:
- `Key Install` (5 rows) is a VPN key exchange, not a traffic decision -
  verdict NULL (the human SOC report on this file reads it the same way).
  An empty vocabulary entry means "not a verdict"; the SQL path wraps the
  CASE in `NULLIF(..., '')` so it agrees with `decode_row`.
- `Detect` (IPS saw, did not block) stays `detect` - neither allow nor deny.
- `Time` has no zone; SmartConsole writes the exporting computer's zone and
  the file does not say which. Read as GMT+7, flagged timezone-unconfirmed,
  and the profile note says so.

**Coverage on every case** (`pipeline._coverage`, the AC "unparseable rows
counted and reported" for CSV/JSON/logs): `mapping.coverage` = rows in the
case, `not_loaded` (decoded but refused by the staging bulk load - it
reads with `ignore_errors=true`, which skipped a bad row **silently** while
the manifest still counted it; `_ingest_file` now returns rows actually
loaded), `time_unparsed`, and per mapped field the rows carrying a value -
the gotcha #7 query on every case. On the Check Point file: time / source /
destination 45,209, verdict 45,204, service 45,198, account 0 ("empty in
every row"). Corpus parity unchanged, so no file had been losing rows.

Not done (no real file - IAI-85): `fwm logexport` (semicolon, field names)
and Log Exporter (syslog `key="value"`). Sources found while researching:
sk144192 (field <-> display name), R81 CLI Reference `fwm logexport`,
R81.20 Log Exporter guide; Elastic's integration has Log Exporter test
fixtures (license unchecked).
