# Gotcha #59

**59. Check Point Log Exporter records arrive wrapped in a SIEM's export, and every
connection is several rows (IAI-85, 2026-10-21).** Design: `specs/IAI-85_checkpoint_log_exporter.md`;
reader `app/services/checkpoint_le.py`.

- The first real file was not from Check Point directly: a **ManageEngine EventLog Analyzer
  search export** - a `Search Results` line, EventLog Analyzer's header, and the Check Point
  record in `Message` after `11241 - `. The record is Log Exporter's default syslog format
  (documented: `[`, `; `, `name:"value"`, escapes `\\` `\"` `\]`); the wrapper is **observed**
  (ManageEngine documents report exports, not this layout). Identification needs both: the
  preamble + header, *and* most of the first 200 `Message` values parsing as records with
  `loguid` and `origin`. The same export of anything else is `no_reader`, named - never guessed.
- **Read `Message` with `regexp_extract_all`, not one `regexp_extract` per field**: the
  all-matches scan goes left to right without overlap, so text inside a value
  (`__policy_id_tag` holds `;`, `=` and `[...\]`) is never taken for a field. Python's
  `parse_body` uses the same pattern (`FIELD_PATTERN`).
- **20,000 rows were 9,591 connections.** In raw read-mode a connection's updates arrive as
  separate logs sharing a `loguid` (Log Exporter guide, Appendix B) - 2 to 5 rows each here, the
  later ones adding bytes and rule names. Every row stays an event (Q37); only the first per
  `loguid` (time, `sequencenum`, file order) carries the verdict, the rest are
  `action = 'log_update'` with no verdict. Counting verdicts counts connections; R3001 still
  sees the bytes on the update rows. Same move as ESXi's second PAM report (#57).
- `time` is a Unix epoch (seconds, or milliseconds with `time-in-milli`) - UTC by definition, so
  `db.TZ_MARKER_PATTERN` now counts an all-digit 10/13-digit `ts_raw` as **stating its zone**: no
  `timezone-unconfirmed`, and a declared zone (#58) does not move it. EventLog Analyzer's `Time`
  column was the collector's local clock (epoch + 7 h in all 20,000 rows) and is not read; nor is
  its `Username` (a display name) - the record's `src_user_name` / `user` are.
- The export holds **4 min 24 s** of traffic in exactly 20,000 rows - an export cap by its shape;
  the user can get no more. Record it in the case's provenance; correlation rules see a sliver.
- `service` is numeric here (unlike the SmartConsole export, #8), so port rules can run.
- Baseline: the real file (`D:/logtest/`, beside the SmartConsole benchmark) 20,000 rows, 11
  flagged (R3001 x2, R3004 x9 with the intel feeds); the synthetic sample
  (`tests/samples/checkpoint-log-exporter/`) 10 rows, R3001 x2. `tests/check_checkpoint_le.py`
  checks grammar, identification, mapping, update logs, plain / .gz / .zip, and `--real`.
- Still open on IAI-85: Log Exporter syslog lines straight from a collector and `fwm logexport` -
  no real file of either yet.
