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
  the channel when the head has one channel, else `product: windows`. `.evtx` is recognised by
  `ElfFile\0` and stays `no_reader` until W2; Splunk's classic text stays `no_reader` until W3.
- Baseline: `windows-sysmon.log` 0 -> 40 rows (it was kept unread before W1);
  `windows-security-xml-spray.log` (attack_data, Apache-2.0) 232 rows, 50 flagged.
