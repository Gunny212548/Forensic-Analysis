# Log formats this tool identifies but does not read yet

The test files for IAI-92 (`app/services/identify.py`): each must be identified
as its log source in the Sigma logsource taxonomy, and - having no reader yet -
kept as evidence and not analysed. Checked by `tests/check_identify.py`.

All five come from Splunk's **attack_data** repository, downloaded 2026-10-20 from
`media.githubusercontent.com/media/splunk/attack_data/master/...`. Three are
unmodified; the two large ones are their **first lines only** (a change, stated
here as the license asks):

| file here | original | sourcetype | original SHA-256 | kept |
|---|---|---|---|---|
| `cisco_asa_generic_logs.log` | `datasets/cisco_asa/generic/cisco_asa_generic_logs.log` | `cisco:asa` | `b42d51b1f09c7d447ebf3ca1c1a594a886bbf529b06a4300c9a5a58d191a2385` | whole file |
| `ftd_connection_events.log` | `datasets/cisco_secure_firewall_threat_defense/connection_event/connection_events.log` | `cisco:sfw:estreamer` | `37e737d87c4e8396396f3a69621c127bd943eb733036deb7abaa5a5a7276371d` | first 60 lines |
| `windows-security.log` | `datasets/attack_techniques/T1003.001/atomic_red_team/windows-security.log` | WinEventLog (Splunk's text rendering) | `962debff1935335a6c6396a19d778127af1316b964226ba4427fae4fb9c9361b` | whole file |
| `windows-sysmon.log` | `datasets/attack_techniques/T1003.001/atomic_red_team/windows-sysmon.log` | `XmlWinEventLog` (Sysmon/Operational) | `a1905850598f1e943708c3329190e29c6cb046389c1575cb2afd6369b5f269f1` | first 40 lines |
| `crowdstrike_falcon.log` | `datasets/attack_techniques/T1003.001/atomic_red_team/crowdstrike_falcon.log` | `crowdstrike:events:sensor` | `9eb639b8642f067f76ddb8b4ab66494deb9893eed528bcb02063802c2dbff140` | whole file |

- License: Apache License 2.0 (the repository's license), Copyright Splunk Inc.
- Splunk recorded the Windows and CrowdStrike files in its attack_range lab
  running Atomic Red Team T1003.001 (2022-01-12); the dataset metadata calls the
  Cisco ASA (2025-10-30) and FTD (2025-04-03) files "generated" in the same lab.

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
