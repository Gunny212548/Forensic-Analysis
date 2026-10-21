# OTRF Security-Datasets: NXLog JSON (read since W4)

`rdp_interactive_taskmanager_lsass_dump.json` - Windows events as the OTRF lab shipped them:
NXLog's `im_msvistalog` records (`to_json`) forwarded through Logstash, one JSON object per line.
Read by `app/services/winevent.py` (`parse_json_event`), checked by `tests/check_windows.py`.

| | |
|---|---|
| Source | https://github.com/OTRF/Security-Datasets, `datasets/atomic/windows/credential_access/host/rdp_interactive_taskmanager_lsass_dump.zip` (downloaded 2026-10-21) |
| Original | `rdp_interactive_taskmanager_lsass_dump_2020-09-22043748.json`, SHA-256 `cdca69c166f71a7bd9daf4b2d5d420690f6489a25abf5ee9688b01344f40f69b`, 5,489 records |
| License | MIT, Copyright (c) Open Threat Research (OTRF) |
| **Changed** | **283 of the 5,489 records kept, in their order, unmodified**: every record of the smaller channels, Sysmon 1 / 3 / 8 / 11 / 17 / 18 / 22, and at most 3 (Sysmon) or 4 (Security) of each of the noisy IDs (Sysmon 7 / 9 / 10 / 12 / 13; Security 4656 / 4658 / 4663 / 4673 / 4689 / 4690 / 5156 / 5158) |

What it shows: an RDP session to a workstation and an LSASS dump from Task Manager (OTRF's
description), Sysmon + Security + Terminal Services channels. The Security channel is written both
`Security` and `security`. `EventTime` has no zone (the agent's local time, Q49). Some records
carry `ProcessId`, which no Windows template names for their event - added on the way, counted
on the case page, kept.
