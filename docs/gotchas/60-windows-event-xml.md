# Gotcha #60

**60. Windows events: one core for every container, the event kept as Windows wrote it
(W1, 2026-10-21).** Design and the W2-W5 plan: `specs/windows_event_logs.md`; core
`app/services/winevent.py`; check `tests/check_windows.py`.

- **Two tables, two jobs.** `win_events` holds the event as written - System values plus every
  EventData / UserData item in `data MAP(VARCHAR, VARCHAR)` under its own name (`CommandLine`,
  `TargetUserName`, `LogonType`...). Those are SigmaHQ's field names: the SigmaHQ story queries
  `data['CommandLine']` there (ADR-006 decision 2), not `raw_events`. `raw_events` gets the
  timeline row (UTC `TimeCreated` -> GMT+7, `Computer`, account, address, process, event type).
- **An event can span lines** (4672's `PrivilegeList`): the attack_data spray capture is 232
  events on 259 lines. Never read event XML line by line. `iter_event_texts` cuts at
  `</Event>`; an event cut short ends where the next `<Event` begins, so damage costs one event,
  counted as `unreadable` and kept as a text row. It scans by position - the first version sliced
  the buffer per event, quadratic in events per chunk. Measured: split 426 MB/s, split + parse
  ~39,000 events/s on 117 MB.
- **The staging CSV takes no line breaks** with `auto_detect=false` ("unterminated quote"): the
  `raw` text collapses whitespace; the full value stays in `win_events` (JSON-escaped in staging,
  cast to MAP on load).
- **Event types come from each event's Microsoft page** (Security) and the Sysmon page's event
  headings. An event with none is shown "Windows event <id> (<provider>)" - never guessed. 4625
  / 4624 are `auth_failed` / `auth_success`, so the existing sign-in rules run on Windows: the
  PurpleSharp NTLM spray gives R2000 x50, R2009 x50. 4771 / 4776 are typed but **not** counted
  as sign-in failures (Q41) - a DC can log them beside 4625 for the same attempt (#57's lesson).
- Which **Sysmon** items fill the timeline columns is observed from the events' own `Data Name`s;
  the Sysmon page lists events, not fields. Unnamed `<Data>` items get Winlogbeat's documented
  `param<n>`.
- Identification: event XML by the `Event` element in Microsoft's namespace (`.xml`, `.log`,
  `.txt`, in a zip too - `.xml` / `.evtx` are now zip member extensions); the Sigma service from
  the channel when the head has one channel, else `product: windows`. Splunk's classic text stays
  `no_reader` until W3.
- Baseline: `windows-sysmon.log` 0 -> 40 rows (it was kept unread before W1);
  `windows-security-xml-spray.log` (attack_data, Apache-2.0) 232 rows, 50 flagged.

## W2 - .evtx (2026-10-21)

Read with the `evtx` library (pyevtx-rs 0.13.1, MIT, Q42), which renders each record as event
XML into the same `parse_event()`. Identified by `ElfFile\0`, the channel from the records of the
first four chunks (`read_as: evtx`, profile `windows-evtx`). `.evtx.gz` is decompressed into
staging first - records are found by chunk offset. Lab: `D:/logtest/windows` (outside the repo,
Q43); `tests/check_windows.py --evtx` documents how its references were made.

- **The library drops damage silently.** Overwriting 400 bytes of one chunk lost 138 of its 158
  records, cutting the file lost the last chunk's 165 - no error object, no exception. So every
  record is counted against the chunk headers (libyal: first / last record identifier at 24 /
  32): what a header names and the reader did not return becomes one row per chunk
  (`[unreadable EVTX records] chunk N at byte X: k of records a-b not readable`) and
  `windows.unreadable`; a non-empty 64 KB slot with no `ElfChnk\0`, or whose header names more
  records than a chunk can hold, is `unreadable_chunks`. On 278 EVTX-ATTACK-SAMPLES files and two
  exports from this PC the count is exact (0 missing).
- **...and gives up at a slot with no chunk signature** ("Failed to parse chunk header"): a
  garbage first chunk lost all 43k events of the file. A file with such a slot is read from a
  staging copy of the file header and the slots that start with `ElfChnk\0` (never written beside
  the evidence); identification reads its head the same way and calls any `ElfFile\0` file
  supported, saying when its first chunks could not be read.
- **The library does not render values the way Windows does** - measured item by item against
  `Get-WinEvent .ToXml()` of the same files: a GUID bare and upper case (Windows `{lower}`, 38k
  Sysmon `ProcessGuid`s), FILETIME / SYSTEMTIME to 6 fraction digits (Windows 7), a null or empty
  value as the indent of its closing tag, a null *unnamed* item as an extra `<Data>` (Windows
  leaves it out), XML-illegal control characters kept (Windows writes `_`). A GUID cannot be told
  from a string that holds one by its text - Hyper-V's `PortName` is a bare upper-case GUID
  *string* - so the value types are read from the record's own Binary XML (`evtx_typed_values`:
  template instance, descriptors, nested 0x21 fragments) and only GUID / FILETIME / SYSTEMTIME
  values are rewritten. Result: 37,364 + 43,413 events identical to Windows' rendering in every
  System value and every item.
- **Do not use `wevtutil qe /f:xml >` as the reference**: it writes through the console code
  page (`®` -> `?`, U+200E -> `?`) and looks like a reader bug. `Get-WinEvent ... .ToXml()`
  written as UTF-8 is the reference.
- Speed: the library itself ~700k records/s (multi-threaded); the whole pipeline ~17k events/s
  on the 43k-event System export (2.5 s with rules and profiles). Not measured on a GB file.
- Not seen in any sample, so not handled: arrays of GUID / FILETIME (0x8f / 0x91); ANSI strings
  are decoded with the library's default windows-1252 (a Thai-locale ANSI string would need
  windows-874).

## W3 - Splunk's classic WinEventLog text (2026-10-21)

A time line (`MM/DD/YYYY hh:mm:ss AM`), `LogName=` ... header lines, then `Message=` and the
**rendered** message - the layout is observed (Splunk's docs refuse automated access). Identified
by a time line followed by `LogName=` in the first 50 lines (`read_as: winsplunk`).

- **The message names no item.** `Account For Which Logon Failed: / Account Name: X` is
  `TargetUserName`. Windows' own message templates say so: `ProviderMetadata.Events` gives per
  event ID and version the message with `%n` and the template's item names in order.
  `tools/export_win_templates.ps1` exports Security-Auditing (502) and Eventlog (44, for
  1100 / 1102) into `app/data/windows/` - committed (Q45), the Linux container cannot read them.
- **Matched line by line, not one regex**: a lazy-group regex over a 28-insertion message
  backtracks badly when a version does not fit. A literal line must read the same, a `%n` line
  gives its values, other lines continue the previous value (4672 PrivilegeList, 4662 Properties,
  blank lines inside 5145's Accesses). Newest version first.
- **The same version differs between Windows builds**: 5156 version 1 on Windows 11 has
  `InterfaceIndex` / `FilterOrigin` that an older build's version 1 lacks. A leftover
  `Label:<tab>` line therefore rejects a template instead of being swallowed as a continuation,
  and a message no template fits is kept whole as `Message` and counted
  (`windows.unmatched_messages`) - never mislabelled. Of 1,553 lab events with EventData, only
  5156 v1 had other names or order than this PC's template.
- **Values are as rendered (Q46)**: a SID as its account (`ATTACKRANGE\Administrator`), a `%%`
  parameter as its text. Hex is the exception that can be undone losslessly: the message writes
  `0xC000006D`, the event stores `0xc000006d`, and the template's `outType` says which items are
  hex - those are lower-cased. Control characters become `_`, as in Windows' XML.
- **Time has no zone (Q44)**: taken as written, GMT+7 by #21, flagged unconfirmed.
- Measured: attack_data account_lockout (9,245 events, 46 IDs) and both committed captures -
  every message named; Windows-rendered messages of the lab's 1,577 Security events read back:
  18,002 items equal to the XML, 1,597 SIDs / `%%` as rendered, 0 other. ~32k records/s.
- Seen in passing, not changed here: on the lockout capture R2006 flags the DC's own machine
  account `WIN-DC-259$` (177 rows, 4 sources) - Windows 4624s include computer accounts, which
  the multi-source rule was not written for.

## W4 - JSON: Winlogbeat / Elastic and NXLog (2026-10-21)

Q48: Winlogbeat and NXLog; PowerShell's `ConvertTo-Json` is W4b (its `Properties` carry no
names). `parsers.iter_json(..., flat=False)` gives each record as decoded - the dotted
flattening drops empty values, which are items here. Identified by the first records' shape
(`winevent.json_shape`), before any other JSON profile.

- **Winlogbeat** (`winlog.event_id`, `winlog.channel`): items are `winlog.event_data.*` and
  `winlog.user_data.*` (less Winlogbeat's `xml_name`); an Elasticsearch export's `_source` is
  unwrapped; time is `@timestamp` (TimeCreated, UTC). **Winlogbeat does not write what the
  event holds**, measured on Elastic's 97 test `.evtx` files and the JSON Winlogbeat wrote from
  each (lab, Elastic License): it leaves out empty items (258), renders `%%` parameters as text
  (71), writes GUIDs upper case (213) and trims values (12); 2,632 items equal; nothing else.
  The reader keeps Winlogbeat's values as written (Q46's rule).
- **NXLog** (`SourceModuleType: im_msvistalog`): its own fields and the event's items share the
  top level. Set aside: NXLog's documented fields (reference v5.11 and current), its core fields,
  `ExecutionThreadID` / `EventData` (its own sample), `Task` (observed in OTRF), Logstash's
  `@timestamp` `@version` `tags` `host` `port`. **But an item Windows' template names stays an
  item** - 4778's `AccountName` is also an NXLog field name and was lost before that rule. Keys
  no template names are kept and counted (`keys_outside_template`: OTRF's pipeline adds
  `ProcessId`). NXLog leaves out empty items too. The `EventData` XML is used when a record has it.
- **Channel names are case-insensitive**: OTRF's NXLog records hold both `security` and
  `Security` (`winevent.channel_name`).
- **A time with no zone is now kept as written everywhere** (`_when`): it used to be taken as
  UTC, harmless while only SystemTime (`...Z`) reached it; NXLog's `2020-09-22 04:37:54` is the
  agent's local time (Q49 / #21).
- OTRF's later datasets (from 2020-10) are flat JSON with no shipper field (`TimeCreated`, no
  `SourceModuleType`): recognised and kept as no_reader, not guessed at.
- Speed: ~16k events/s through the whole pipeline (OTRF purplesharp, 25,993 events, 1.6 s).
