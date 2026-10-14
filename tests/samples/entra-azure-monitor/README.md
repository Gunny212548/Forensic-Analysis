# Entra ID sign-in logs, Azure Monitor JSON export (real captures)

The real-file test for IAI-35 (JSON parser) and the `entra-signin-azure-monitor`
log source profile (`app/services/logsources.py`, CLAUDE.md gotcha #39).

Both files are unmodified copies from Splunk's **attack_data** repository,
renamed from `.log` to `.jsonl` only, because this app reads a `.log` upload as
a text log:

| file here | original | recorded | SHA-256 |
|---|---|---|---|
| `azuread_signin.jsonl` | `datasets/attack_techniques/T1110.003/password_spraying_azuread/azuread_signin.log` | 2023-06-16 | `14b4ded54e61209e62cd8d883032a8bb3f33753cec0423510a725142ae36c0f6` |
| `azure_ad_distributed_spray.jsonl` | `datasets/attack_techniques/T1110.003/azure_ad_distributed_spray/azure_ad_distributed_spray.log` | 2023-11-06 (dataset page dated 2025-08-12) | `e449c7a937e83f9795065e6ac215ad71ec80ae2fa66fdba0621326aa23bd7f85` |

- Source: https://github.com/splunk/attack_data (downloaded 2026-10-14 from
  `media.githubusercontent.com/media/splunk/attack_data/master/...`)
- Dataset pages: https://research.splunk.com/attack_data/e73d690b-57d8-430f-be60-b64a0f1405cd
  and https://research.splunk.com/attack_data/a5169e72-9b94-4ac9-91f6-e48f9ef786f2/
- License: Apache License 2.0 (the repository's license), Copyright Splunk Inc.
  Redistributed here unmodified apart from the file names.
- Splunk recorded them in its attack_range lab with Invoke-MSOLSpray; per the
  dataset page, tenant ids, user names and IPs were replaced.

## What they contain and what the app must find

| file | records | shape | expected | measured 2026-10-14 |
|---|---|---|---|---|
| `azuread_signin.jsonl` | 31 | one source (82.1.1.35), 31 accounts, all `errorCode` 50126 | every row a failed sign-in, and the burst from one source correlated | R1000 x31, R2000 x31 - case `medium` |
| `azure_ad_distributed_spray.jsonl` | 31 | 30 sources, 31 accounts, one 50126 each, within 26 s | every row a failed sign-in | R1000 x31 only - **no correlation rule sees a distributed spray** (each source fails once, each account from one source) |

Read with the documented profile, no field guessed; the account is
`properties.userPrincipalName`. Without the profile (guessing only) both files
gave 31 rows and **0 findings**: the guess took `userDisplayName` as the account
and the numeric `errorCode` as an unknown sign-in result. Counts are in
`tests/baseline.json`; check with

```bash
python tests/check_parity.py tests/samples
```
