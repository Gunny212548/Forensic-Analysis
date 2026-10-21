# Windows event logs - Security, Sysmon and every format they arrive in

Status: **W1, W2 (.evtx) and W3 (Splunk text) built 2026-10-21** (gotcha #60; W4-W5 to come). **Approved 2026-10-21** - Q40 `win_events` + MAP, Q41 4771 / 4776 typed but not counted,
Q42 `evtx` (pyevtx-rs) for W2, Q43 GPL samples and exports from this machine kept outside the repo. The user: "ทำ Windows Security
กับ Sysmon reader ต่อ"; formats: "ต้องรับทุกรูปแบบที่เป็น Windows Log"; tested on **lab samples**
until a customer file exists. No Jira story yet (IAI-92 only *identifies* these files).

Why it matters: every log the tool reads today is network or sign-in. Nothing says what ran
on a host - and "which command, from which host, to which host" is the purpose (gotcha #54).
Windows is also where SigmaHQ has most of its rules (ADR-006 counted 44 for our current
sources; Windows has thousands), so this reader is what makes the SigmaHQ story worth doing.

## One event model, many containers

Every Windows format carries the same event: **System** (Provider, EventID, TimeCreated,
EventRecordID, Channel, Computer, Security UserID ...) and **EventData** - named `<Data
Name='...'>` items - or **UserData** (1102 uses `UserData/LogFileCleared`). So the work is one
core that turns *(System, data items)* into rows, and one small adapter per container:

| # | Container | How it arrives | Documented by | Sample (lab) | Story |
|---|---|---|---|---|---|
| 1 | **Event XML** | `wevtutil qe /f:xml`, `Get-WinEvent` `.ToXml()`, Splunk `XmlWinEventLog` (one event per line) | Microsoft Event schema (`SystemPropertiesType`, `EventDataType`) | attack_data `windows-sysmon.log` (have); attack_data Security XML (to fetch, Apache-2.0) | **W1 - this story** |
| 2 | **.evtx** | Event Viewer "Save All Events As", `wevtutil epl`, copied from `C:\Windows\System32\winevt\Logs` | libyal EVTX format doc (`ElfFile`, `ElfChnk`, records of Binary XML) - Microsoft publishes none | EVTX-ATTACK-SAMPLES (GPL-3.0, kept **outside** the repo); an export from a Windows machine | W2 |
| 3 | Splunk classic text | `WinEventLog` sourcetype: `LogName=`, `EventCode=`, `Message=` + rendered message | Splunk's docs refused automated access (403) - **observed** | attack_data `windows-security.log` (have) | W3 |
| 4 | JSON | Winlogbeat / Elastic (`winlog.event_id`, `winlog.event_data`...), `Get-WinEvent` piped to `ConvertTo-Json` | Elastic Winlogbeat exported fields (read); PowerShell's object - to read | none yet | W4 |
| 5 | Event Viewer CSV / TXT, `Export-Csv` | "Save As" CSV: Level, Date and Time, Source, Event ID, Task Category + the rendered message only | none found | none yet | W5 - message text only, so the weakest; fields come from the message templates on Microsoft's event pages |

W1 builds the core; W2-W5 each add an adapter, a sample and its checks. Every container is
identified first (gotcha #53); a Windows file in a container with no adapter yet stays
`no_reader`, named - as today.

## W1 design - the core and Event XML

### Identification
`identify.py` already recognises event XML by its Channel (Security, Sysmon/Operational).
It becomes **supported** for any `<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>`
records, with the Sigma logsource from the Channel - `windows / security`, `windows / sysmon` and the
other services the Sigma taxonomy v2.1.0 (read) defines for a channel; any other channel is
`product: windows` with the channel named.

### Reading
Python, streamed with `xml.etree.ElementTree.iterparse` (stdlib, no dependency), one event at a
time - never the whole file in memory - through the existing staging-CSV path (gotcha #1). A
record that is not well-formed is counted and kept as a text row, never dropped (as for JSON).

### Two places, two jobs (ADR-006 decision 2)
1. **`win_events`** - a new table in the case DuckDB, the event *as Windows wrote it*: `row_id`,
   `channel`, `provider`, `event_id`, `record_id`, `computer`, `user_sid`, `time_created` (text),
   and `data MAP(VARCHAR, VARCHAR)` - every EventData / UserData item under its own name
   (`CommandLine`, `ParentImage`, `TargetUserName`, `LogonType`, `IpAddress` ...). These are
   the names SigmaHQ rules match on, so the SigmaHQ story reads this table directly.
2. **`raw_events`** (unchanged schema) - the timeline row every other step already reads:

   | canonical | from | why |
   |---|---|---|
   | `ts` | `System/TimeCreated/@SystemTime` | UTC (`...Z`) -> GMT+7; states its zone |
   | `hostname` | `System/Computer` | the host the event happened on |
   | `username` | `TargetUserName`, else `SubjectUserName` (Security); `User` (Sysmon) | the account the event is about |
   | `srcip` | `IpAddress` (4624/4625/4648/4768/4769/4771), Sysmon 3 `SourceIp` | `-` and empty are NULL |
   | `dstip` / `dstport` | Sysmon 3 `DestinationIp` / `DestinationPort` | |
   | `program` | process image file name (`NewProcessName`, `Image`, `ProcessName`) | |
   | `action` | layer A event type (below) | |
   | `app` | `LogonType` name for logons (e.g. `RemoteInteractive (10)`), else the provider | |
   | `raw` | `"<EventID> · Field=Value · ..."` of the event's data, command line first | what the events table shows |

### Layer A - what each event is (from each event's Microsoft page)
Security: 4624 `auth_success` · 4625 `auth_failed` · 4648 `explicit_credentials` · 4672
`special_privileges` · 4688 `process_created` · 4697 `service_installed` · 4698
`scheduled_task_created` · 4720 `account_created` · 4740 `account_locked_out` · 4768
`kerberos_tgt` · 4769 `kerberos_service_ticket` · 4771 `kerberos_preauth_failed` · 4776
`ntlm_validation` · 1102 `audit_log_cleared`. Sysmon: one type per event ID 1-29 by its
heading on the Sysmon page (1 `process_created`, 3 `network_connection`, 10 `process_access`,
11 `file_created`, 13 `registry_value_set`, 22 `dns_query` ...). Any other event: no type,
shown as "Windows event <id> (<provider>)" - never guessed.

**4625 and 4624 feed the existing sign-in rules** (R2000 brute force, R2005 / R2009 spray,
R2006 multi-source, R2008 login after brute force) through `auth_failed` / `auth_success` +
`IpAddress`, exactly as sshd and Entra do. 4771 / 4776 failures are typed but not counted as
sign-ins in W1 (a Kerberos pre-auth failure and an NTLM validation are not the same act as a
logon failure - Q41).

### Tests
`tests/check_windows.py`: identification per channel; System and EventData read to the
letter on the Sysmon sample and a Security XML sample; UTC -> GMT+7; `win_events.data` keeps
every item; layer A types; a 4625 burst in a synthetic file fires R2000; a broken record counted
not dropped; `.gz` / `.zip`. Parity unchanged on the corpus. `check_identify` moves the two
samples from `no_reader` to `supported`.

## W2 - .evtx (built)

The `evtx` library (Q42) renders each record; `parse_event()` and the two tables are W1's. Two
things the library does not do, both measured and handled (gotcha #60): it drops damaged records
without an error - every record is counted against its chunk header and the shortfall kept as a
row - and it renders GUID / FILETIME / SYSTEMTIME values, null items and control characters
differently from Windows - the value types are read from the record's Binary XML (libyal) and
put in Windows' form. Checked: 278 EVTX-ATTACK-SAMPLES files and this PC's System export, every
event identical to `Get-WinEvent .ToXml()` of the same file; a cut file and an overwritten
chunk; `.gz` and `.zip`. The UI now states events per channel and anything unreadable
(`Mapping.jsx`, for event XML too).

## W3 - Splunk classic text (`WinEventLog`) - approved 2026-10-21 (Q44-Q47 as proposed), built

What it is (observed - Splunk's docs refuse automated access): a record starts with a time line
`MM/DD/YYYY hh:mm:ss AM|PM`, then `LogName=`, `SourceName=`, `EventCode=`, `EventType=`, `Type=`,
`ComputerName=`, `TaskCategory=`, `OpCode=`, `RecordNumber=`, `Keywords=` lines, then `Message=`
and the **rendered** message, which runs to the next record. The items are not named in it: the
message says `Account For Which Logon Failed: / Account Name: KERRI_RIVERS`, not `TargetUserName`.

**Item names from Windows' own message templates.** Every provider publishes, per event ID and
version, its message with `%n` insertions and the template naming each data item in order
(`ProviderMetadata.Events`; read on this PC: Microsoft-Windows-Security-Auditing, 502 events).
4625's message has `Account Name:\t\t%6` under `Account For Which Logon Failed:`, and its
template's 6th item is `TargetUserName` - so a rendered message is matched against the event's
templates (every version - 4624 has 4) and each value gets its Data name. Nothing guessed: an
event whose message matches no template keeps its whole message as one item `Message` and is
said so.

- Identification: the time line + `LogName=` record header (any channel; today only
  `LogName=Security` is recognised, as no_reader).
- System values: `EventCode` -> event_id, `ComputerName` -> computer, `RecordNumber` ->
  record_id, `LogName` -> channel; `SourceName` is the provider's display name ("Microsoft
  Windows security auditing.") and is turned into its name by the same provider metadata.
- **Time (Q44):** the time line has no zone. Proposed: as gotcha #21 - taken as GMT+7 and
  flagged `timezone-unconfirmed`; the analyst declares the source's zone at Ingest (story 3)
  and re-processes.
- **Templates in the repo (Q45):** exported once from this PC (Windows 11) by a small tool into
  `app/data/windows/` as JSON - Microsoft's message text and item names. Proposed: commit it
  (the same text is on Microsoft's event pages); the container (Linux) cannot read it from
  Windows at run time.
- **Values as rendered (Q46, to know rather than decide):** Splunk's text carries what the
  message shows - a SID as an account name (`ATTACKRANGE\Administrator`), `%%1842` as `Yes`.
  `win_events` gets the right names with those values, and the case page says so; a SigmaHQ
  rule matching a raw SID would not match this container.
- Not in W3: Sysmon (its provider metadata is not on this PC) and other providers - message
  kept whole as above.
- **Samples (Q47):** commit attack_data `T1110.003/purplesharp_remote_spray/windows-security.log`
  (Apache-2.0, 211 KB: 4625 x20, 4624, 4776, 4672, 4688...); keep
  `T1078.002/account_lockout` (10 MB, 46 event IDs incl. 4740 / 4768 / 4769) in
  `D:/logtest/windows/splunk-text/`. Fidelity check: the Security events of the lab .evtx files
  rendered by Windows (`Get-WinEvent .Message`) written in this layout, read back, and their items
  compared with the same events' XML.

As built (gotcha #60): Eventlog's templates too (1100 / 1102 are its events, in the Security
log); hex items lower-cased as the event stores them (the template's `outType` says which);
a leftover `Label:` line rejects a template - the same version differs between builds (5156
v1); matched line by line, not by one regex. All 9,245 lockout events and both committed
captures named; Windows-rendered lab messages read back equal to their XML but for SIDs / `%%`.

## Questions

- **Q40 - native fields.** As proposed: a `win_events` table with a `MAP` of the event's own
  items, beside `raw_events` (ADR-006 decision 2) - or wide columns per known field?
- **Q41 - Kerberos / NTLM failures.** 4771 and 4776 failures typed but not counted as sign-in
  failures in W1 (as proposed), or counted with 4625 now?
- **Q42 - EVTX library (W2).** `evtx` (pyevtx-rs 0.13.1, MIT, compiled wheel for Linux x86_64 /
  Python 3.12, released 2026-09-22) or `python-evtx` (0.8.1, Apache-2.0, pure Python, last
  release 2025-05-02)? Proposed: `evtx`, after a speed measurement on a large file in W2.
- **Q43 - samples outside the repo.** EVTX-ATTACK-SAMPLES is GPL-3.0: kept in `D:/logtest/windows/`
  like customer files, not committed; Apache-2.0 attack_data files are committed as today.
  And may W2 export a sample `.evtx` / XML / CSV from this Windows machine (System and
  Application channels; Security needs an administrator), kept outside the repo?
