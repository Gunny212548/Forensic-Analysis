# Check Point Log Exporter records in an EventLog Analyzer search export (synthetic)

`eventlog-analyzer-search-export.csv` - **made up**, not a capture: RFC 5737 / RFC 1918
addresses and invented account names, written to the layout of a real ManageEngine EventLog
Analyzer search export of Check Point Log Exporter records (IAI-85; the real file is customer
data and lives outside the repo, `D:/logtest/`). Read by `app/services/checkpoint_le.py`;
checked by `tests/check_checkpoint_le.py` and `tests/check_identify.py`.

Layout (observed, EventLog Analyzer documents none): a `Search Results` line, the header
`#, Message, DisplayName, LogType, Device, Time, ...`, one row per log; the record is in
`Message` after `11241 - `, in Log Exporter's default syslog format (Log Exporter
Administration Guide, *Format Configuration*).

| # | What the row exercises |
|---|---|
| 1 | Accept, loguid A, `src_user_name` - the connection |
| 2 | update of A (`sequencenum` 2), `client_outbound_bytes` 60,000,000 - R3001 |
| 3-6 | Drop, Reject, Block (Application Control, `appi_name`, `app_risk` 4), Detect |
| 7 | Key Install - not a traffic decision, no verdict |
| 8 | escapes `\"` `\]` `\\` in a value, `user` without `src_user_name`, `time` in milliseconds |
| 9 | a `Message` that is not a Log Exporter record - loaded, counted, not read |
| 10 | update of A (`sequencenum` 3), 61,000,000 bytes - R3001 |

Expected: 10 rows; 9 records, 1 not a record; 7 connections, 2 update logs; verdicts allow 2,
drop 1, reject 1, block 1, detect 1; R3001 x2; times 2026-10-21 10:23:08 / 10:23:10.123 GMT+7,
none flagged `timezone-unconfirmed`.
