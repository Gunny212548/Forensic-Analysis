# Splunk attack_data captures: formats identified, and the Windows event XML ones read

The test files for IAI-92 (`app/services/identify.py`): each must be identified
as its log source in the Sigma logsource taxonomy and, where it has no reader yet,
kept as evidence and not analysed. Checked by `tests/check_identify.py`.

All seven come from Splunk's **attack_data** repository, downloaded 2026-10-20 (the
Security XML and text spray ones 2026-10-21) from `media.githubusercontent.com/media/splunk/attack_data/master/...`.
Five are unmodified; the two large ones are their **first lines only** (a change, stated
here as the license asks):

| file here | original | sourcetype | original SHA-256 | kept |
|---|---|---|---|---|
| `cisco_asa_generic_logs.log` | `datasets/cisco_asa/generic/cisco_asa_generic_logs.log` | `cisco:asa` | `b42d51b1f09c7d447ebf3ca1c1a594a886bbf529b06a4300c9a5a58d191a2385` | whole file |
| `ftd_connection_events.log` | `datasets/cisco_secure_firewall_threat_defense/connection_event/connection_events.log` | `cisco:sfw:estreamer` | `37e737d87c4e8396396f3a69621c127bd943eb733036deb7abaa5a5a7276371d` | first 60 lines |
| `windows-security.log` | `datasets/attack_techniques/T1003.001/atomic_red_team/windows-security.log` | WinEventLog (Splunk's text rendering) | `962debff1935335a6c6396a19d778127af1316b964226ba4427fae4fb9c9361b` | whole file |
| `windows-sysmon.log` | `datasets/attack_techniques/T1003.001/atomic_red_team/windows-sysmon.log` | `XmlWinEventLog` (Sysmon/Operational) | `a1905850598f1e943708c3329190e29c6cb046389c1575cb2afd6369b5f269f1` | first 40 lines |
| `windows-security-xml-spray.log` | `datasets/attack_techniques/T1110.003/purplesharp_remote_spray_xml/windows-security.log` (downloaded 2026-10-21) | `XmlWinEventLog` (Security) | `92ab741ca691f9b7308cc684864bee0b0bff1bb1e01440c4ab874a3afa3f4307` | whole file |
| `windows-security-text-spray.log` | `datasets/attack_techniques/T1110.003/purplesharp_remote_spray/windows-security.log` (downloaded 2026-10-21) | `WinEventLog` (Splunk's classic text, Security) | `183b41e3edf93ccc716b67f5ecf665da2d4ff87e97e03e087a3e090ce25fc9bc` | whole file |
| `crowdstrike_falcon.log` | `datasets/attack_techniques/T1003.001/atomic_red_team/crowdstrike_falcon.log` | `crowdstrike:events:sensor` | `9eb639b8642f067f76ddb8b4ab66494deb9893eed528bcb02063802c2dbff140` | whole file |

- License: Apache License 2.0 (the repository's license), Copyright Splunk Inc.
- Splunk recorded the Windows and CrowdStrike files in its attack_range lab
  running Atomic Red Team T1003.001 (2022-01-12); the dataset metadata calls the
  Cisco ASA (2025-10-30) and FTD (2025-04-03) files "generated" in the same lab.

## Windows event XML (read since W1, specs/windows_event_logs.md)

`windows-sysmon.log` and `windows-security-xml-spray.log` are read by `app/services/winevent.py`
(`tests/check_windows.py`). The spray capture is PurpleSharp's "Remote password spraying attack
against one host using NTLM" (Splunk attack_range, 2022-09-08; dataset author Mauricio Velazco):
232 events - 4625 x50, 4776 x50, 4648 x50, 4688 x36, 4624 x21, 4634 x21, 4672 x3, 4719 x1 - two
computers; the 4625s come from 10.0.1.15 against 50 accounts. Expected: R2000 x50, R2009 x50.

## Splunk classic text (read since W3)

`windows-security.log` (T1003.001, 4688 x4) and `windows-security-text-spray.log` are Splunk's
`WinEventLog` text: a time line, `LogName=` ... header lines and the rendered `Message=`. Read by
`winevent.parse_splunk`, each value named by Windows' own message template (`app/data/windows`).
The text spray is PurpleSharp's remote NTLM spray in another run than the XML one (Splunk
attack_range, 2021-04-20): 162 events - 4688 x37, 4689 x37, 4625 x20, 4776 x20, 4624 x16,
4634 x16, 4672 x11, 5140 x3, 5145 x2; the 4625s come from 10.0.1.15. Expected: R2000 x20,
R2009 x20.

## What they show, and what they do not

- **Real formats, lab events.** They are what these products write, so they
  test *identification*. They are not customer traffic.
- **Not every format a customer hands over.** `windows-security.log` is Splunk's
  text rendering of the Security log, not a Windows export (`.evtx`, or the
  event XML of `wevtutil qe /f:xml`); `windows-sysmon.log` is the event XML.
  `ftd_connection_events.log` is FTD's eStreamer JSON, not its syslog.
- **CrowdStrike's event dictionary needs a Falcon login.** The marker used to
  recognise it (`event_simpleName`, `aid`, `cid`) is observed in this file, not
  quoted from CrowdStrike.
