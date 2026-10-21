# IAI-85 - Check Point Log Exporter records, read from an EventLog Analyzer search export

Status: **approved 2026-10-21** - Q37 every row an event (updates typed `log_update`), Q38 the real
file in `D:/logtest/`, Q39 Jira left untouched until the story closes. Jira IAI-85 ("Parser: Check
Point fwm logexport (semicolon) and Log Exporter (syslog key="value")"), labelled
`blocked-no-sample`; the user brought the first real file the same day:
`Search_Report-2026_10_21-10_23_21_869.csv` (25 MB), exported from **ManageEngine EventLog
Analyzer** (the user, 2026-10-21) - "only this file can be had" (no fuller export).

## The file, measured

- Line 1 `Search Results`, line 2 the header `#, Message, DisplayName, LogType, Device, Time,
  Severity, Facility, Source, Type, Destination IP, Username, Source IP, Description, Event Name,
  Event ID, FORMATID, Details, Host Type`, then 20,000 rows. Today `identify.py` says
  **unrecognised** - correct: no documented header matches, so the file is kept and not read.
- EventLog Analyzer's own columns carry almost nothing: `LogType` / `Host Type` = `CheckPoint
  Device`, `Device` one address, `Severity` `information`, the rest `-` in every row except
  `Time` (local wall clock) and `Username` (a display name, 23.9 % of rows).
- **`Message` is the record**: `11241 - [action:"Accept"; flags:"..."; ...; src:"..."; ...]` -
  a Check Point Log Exporter record in its default *syslog* format, after an EventLog Analyzer
  prefix (`11241 - `, the same in every row, meaning undocumented).
- 150 field names, all Check Point's own (`action`, `src`, `dst`, `s_port`, `service`, `proto`,
  `origin`, `product`, `time`, `loguid`, `xlatesrc`, `src_user_name`, `client_outbound_bytes`...).
- Actions: Accept 18,874 · Drop 961 · Detect 61 · Key Install 52 · Reject 37 · Block 7 ·
  Log Out 1 · none 6. Blades: Firewall, Application Control, URL Filtering, VPN, Web UI.
- Time: `time` is a Unix epoch; it equals the `Time` column minus 7 h in all 20,000 rows.
  20,000 rows cover **10:18:44-10:23:08 (4 min 24 s)** - an export cap, by the shape of it; the
  user cannot get more, so it is recorded as a limitation of this evidence (provenance).
- **Update logs: 20,000 rows are 9,591 connections.** Rows sharing a `loguid` (2 to 5 of them)
  are updates of one connection (later ones add byte counts, rule names); 4 of 7,095 such groups
  change their action. Read one row per event, every connection would count about twice.

## Documents read (to be added to `docs/standards/SOURCES.md`)

| Document | What it gives |
|---|---|
| Check Point **Log Exporter Administration Guide** (sc1.checkpoint.com/documents/Log_Exporter), *Format Configuration* | The syslog body: starts `[`, ends `]`, fields separated by `; `, name and value by `:`, values in `"`; escapes `\` -> `\\`, `"` -> `\"`, `]` -> `\]`, newline -> space |
| same guide, *Appendix B* | Time is epoch (`TIME_FORMAT = %s` for Splunk; "Epoch time format" for LEEF); **update logs**: in raw read-mode updates "arrive as distinct logs", use "the loguid field to correlate update logs" |
| **sk144192** Description of Fields in Check Point Logs (879 field rows parsed from the page) | Every mapped field below: `time`, `action` (Drop / Reject / Accept / ... / Block / Detect), `src`, `dst`, `s_port`, `service` ("Connection (service) destination port"), `src_user_name`, `user`, `client_outbound_bytes` ("Number of bytes sent from the client"), `service_id`, `appi_name`, `app_risk`, `origin`, `product`, `loguid`, `sequencenum`. Not in the table: `ifdir` (listed as internal), `xlatesport`, `xlatedport`, `destination_domain_name`, `lastupdatetime` |
| sk122323, R81 CLI `cp_log_export` | Formats Syslog / Splunk / CEF / LEEF / Generic / JSON / LogRhythm / RSA; syslog is the default |
| ManageEngine EventLog Analyzer user guide, *report export* | Reports export to PDF / CSV / XLSX / HTML; **the search-result CSV layout is not documented** |

So the record is **documented** (Check Point) and the wrapper is **observed** (EventLog Analyzer
publishes no layout for it) - the same two-level honesty as ESXi's observed lines (gotcha #42).

## Design

1. **Identification** (`identify.py`, `logsources.py`). A CSV whose first line is exactly `Search
   Results` and whose second line is EventLog Analyzer's header is read with that line skipped
   (a declared preamble of the profile, not a general "skip junk lines" rule). It is identified
   as *Check Point Log Exporter records (syslog format) in a ManageEngine EventLog Analyzer search
   export* only when the `Message` of the first rows parses as a Log Exporter body carrying
   `loguid` and `origin`; Sigma `category: firewall`, custom product `checkpoint_log_exporter`.
   Any other EventLog Analyzer export stays unrecognised (`no_reader`, named) - nothing guessed.
2. **Reading** - SQL, like every CSV (gotcha #1): `read_csv(..., skip=1)`, each field taken from
   `Message` with one `regexp_extract` per mapped field over the documented grammar (value =
   `"((?:[^"\\]|\\.)*)"`, then the three escapes undone). No row crosses into Python.
3. **Mapping** (sk144192 names):

   | canonical | from | note |
   |---|---|---|
   | `ts` | `time` (epoch) | converted to GMT+7; `ts_raw` keeps the epoch text, and an all-digit epoch counts as **stating its zone** (UTC by definition) in `db.TZ_MARKER_PATTERN` - so no `timezone-unconfirmed` |
   | `srcip` / `dstip` | `src` / `dst` | |
   | `dstport` | `service` | numeric in this file; port-based rules (R2002) can run, unlike the SmartConsole export (gotcha #8) |
   | `username` | `src_user_name`, else `user` | Check Point's own; EventLog Analyzer's `Username` column is a display name - not used |
   | `verdict` | `action` | Accept -> allow, Drop -> drop, Reject -> reject, Block -> block, Detect -> detect (all in sk144192's action list), Prevent -> prevent (a CLI guide example, not in sk144192's list); Key Install, Log Out -> none (not traffic decisions, gotcha #43) |
   | `app` | `appi_name`, else `service_id` | |
   | `risk` | `app_risk` | 0-5 as sk144192 defines |
   | `bytes_sent` | `client_outbound_bytes` | |
   | `raw` | the `Message` text | |

   Not mapped (no canonical column; kept in `raw`): NAT `xlatesrc` / `xlatedst`, `origin`,
   `product`, `src_machine_name`, `rule_name`. They become fields with revision 3 / OCSF.
4. **Update logs** (Q37). Proposed: **every row stays an event** (every line reachable on the
   timeline), and within each `loguid` only the first row - by `time`, `sequencenum`, file order -
   carries the verdict; the later rows get `action = 'log_update'` (event type "Log update (same
   connection)") and no verdict, but keep their byte counts. Firewall rules and behaviour
   profiles count verdicts, so they count connections, not updates; R3001 still sees the bytes.
   The same move as ESXi's second PAM report (gotcha #57). Coverage says "20,000 rows, 9,591
   connections, 10,409 update logs".
5. **Unreadable rows** (AC): a row whose `Message` is not a Log Exporter body is loaded with its
   raw text and no fields, and counted in coverage as "not a Log Exporter record" - never dropped.
6. **Compressed**: `.gz` / `.zip` go through the same CSV path as today (checked, not assumed).
7. **Out of scope, kept on IAI-85**: Log Exporter syslog *lines* straight from a collector (RFC
   5424 / 3164 envelope + the same body) and `fwm logexport` (semicolon) - both still have no real
   file (gotcha #27). The body parser is written once so the line reader can reuse it.

## Tests

- `check_identify.py`: the real file (`--corpus`) identified as this source; the same header with
  a non-Check-Point `Message` is not; a SmartConsole export still is SmartConsole.
- A small **synthetic** fixture in `tests/samples/` (made-up addresses, no real names) covering
  every mapped field, every action, escapes, update logs, a non-Log-Exporter row - its expected
  counts written in `tests/samples/README.md`.
- The real file in the parity baseline under the corpus folder of Q38 (customer data never in git).
- `check_parity.py` corpus + Check Point benchmark unchanged; `gen_usecase` unchanged.

## Questions

- **Q37 - update logs.** As proposed (every row an event, updates typed `log_update` and not
  counted as connections), or fold each `loguid` into one event (the timeline then shows 9,591
  rows, the 10,409 update lines only in `raw/`)?
- **Q38 - where the real file lives for parity.** Proposed: `D:/logtest/` beside the Check Point
  SmartConsole benchmark, never in the repo (it has staff names).
- **Q39 - Jira.** Move IAI-85 to In Progress and drop `blocked-no-sample`, with a comment naming
  the sample (no customer data in the comment)?
