# ADR-006: How Sigma rules are evaluated, and on which field names

Status: **Proposed** (2026-10-20) - spike (a) of `specs/case_flow_design.md` revision 4.
**Scope changed by revision 5 (the user, same day):** the in-house rules stay as the
primary detection and SigmaHQ rules run *beside* them. Decisions 1-4 below apply to the
SigmaHQ rules only; the correlation part of decision 1 is not needed (R2000 / R2005 /
R2006 remain) and Q11 is closed.
Not built. Spike scripts: `specs/spike-sigma/` (run with a venv holding `pySigma==2.0.1`,
`pySigma-backend-sqlite==2.1.1`, `duckdb==1.5.6`; the app pins the same DuckDB).
Measured on SigmaHQ commit `f083329` (2026-10-19, 3,776 rules) and the Sigma
specification commit `ba9251a` (correlation rules v2.1.0).

## Context

Revision 4 retires the 20 in-house rules for SigmaHQ rules, the correlation examples of
the Sigma correlation specification, and threat-intel matching. Two questions had to be
answered before any story could be designed:

1. **Engine.** pySigma (LGPL-2.1) has no DuckDB backend. Its SQLite backend
   (`pySigma-backend-sqlite`, LGPL-3.0) is the closest. Run its SQL on DuckDB, evaluate in
   SQLite, or write our own?
2. **Field names.** Sigma rules match on the logsource's own field names. Which names do
   the rules for our logsources use, and do our files have them?

## What was measured

### Rules that apply to what identify.py can read

44 SigmaHQ rules: `azure/signinlogs` 19, `linux` (no service) 16, `linux/sshd` 3,
`linux/syslog` 2, `category: firewall` 2, `m365/exchange` 1, `linux/auth` 1. Status: 41
`test`, 2 `stable`, 1 `experimental`. Level: 22 high, 17 medium, 5 low. **All 22 Linux
rules are keyword searches on the raw line** - no field mapping needed. No SigmaHQ rule
targets PAN-OS, Check Point or FortiGate traffic; the two firewall rules are a cleartext
port list and two Equation Group C2 addresses.

### Engine

| Option | Result |
|---|---|
| A. SQLite backend's SQL run on DuckDB (backticks swapped) | **Rejected.** Of 8 basic detection forms, 4 return different rows *with no error*: `=`, `contains`, `startswith` and wildcards are case-sensitive on DuckDB (LIKE), case-insensitive in Sigma. A `contains 'device code'` matched 1 of 4 rows. Correlation SQL uses `typeof`, `json_patch`, `json_each`, `json_group_array` - SQLite only. |
| B. Evaluate in SQLite | Works as the backend intends **only** if every column is `TEXT COLLATE NOCASE`; on a plain table `=` is case-sensitive too. Even then `field\|gt: 1000` on a TEXT column matches every non-numeric string (SQLite orders any text above any number): 14 false rows of 18 in the test. NOCASE folds ASCII only. Needs a second copy of every case's events in another engine. |
| C. **DuckDB dialect of the SQLite backend** (`duck_dialect.py`, ~40 lines) | pySigma still parses the rule, applies the modifiers and builds the condition; the subclass changes only tokens: `"` identifiers, `ILIKE`, `regexp_matches`, `COLLATE NOCASE` on equality, `TRY_CAST(... AS DOUBLE)` for numbers. Differential test against B on 20 forms (wildcards, `?`, literal `%_`, backslash paths, `contains\|all`, regex, `\|i`, `\|cased`, null, lists, quotes, CIDR, numbers): **18 identical; the 2 that differ are cases where B is wrong** (`gt` on text; non-ASCII case folding). All 44 rules convert and run on DuckDB. |

Correlations: a `value_count` in the shape of the spec's example, on the Entra spray
sample, gave the same 27 windows / 1 source from the SQLite backend on SQLite and from
hand-written DuckDB SQL. So the SQLite backend can be the **test oracle** for our
correlation SQL.

### Field names, on our real Entra files

The signinlogs rules use Log Analytics `SigninLogs` column names (`ResultType`,
`AuthenticationRequirement`, `DeviceDetail.isCompliant` ...) - and are not consistent
among themselves: some test `Status = 'Success'`, others `properties.message`,
`ActivityDetails`. Run with a prototype mapping (not yet checked against Microsoft's
table reference):

| File | Rules applicable / 19 | Matches | What went wrong |
|---|---|---|---|
| Azure Monitor JSON, Splunk spray capture (62 rows) | 11 | 0 | Nothing - a spray is a correlation; no event rule should fire. Today R2005 finds it. |
| Entra portal CSV, KM23 (91 rows) | 15 | Account Lockout 1, Non-Compliant Devices **91** | **"Only Single Factor Authentication Required" 0, should be 64**: the CSV says `Single-factor authentication`, the rule `singleFactorAuthentication`. **"Login to Disabled Account" 0, should be 4**: the rule demands the exact text "User account is disabled. The account has been disabled by an administrator."; the file says "The user account is disabled." |

Also seen: `Account Lockout` (AADSTS 50053) matched a row whose reason is "blocked
because it came from an IP address with malicious activity" - Microsoft's code covers
both. `Sign-ins from Non-Compliant Devices` (level high) fires on every sign-in of a
tenant without Intune.

### Correlations

- SigmaHQ publishes **0 correlation rules**, and **no base rule** for a failed Entra
  sign-in (AADSTS 50126) or a failed sshd password.
- The specification's examples reference base rules it does not include
  (`5638f7c0-...`, `many_failed_logins`, `successful_login`) and Windows field names
  (`ComputerName`, `WorkstationName`, `User`).
- With the example's own threshold (>= 100 accounts per source per day) the spray
  sample gives 0; at 3 it gives one source.

## Decision (proposed)

1. **Engine: option C.** Detection SQL comes from pySigma through a DuckDB subclass of
   the SQLite backend, pinned exactly (`pySigma==2.0.1`, `pySigma-backend-sqlite==2.1.1`,
   both LGPL, used unmodified as libraries). The differential test becomes a check
   script and runs on every pin change. Correlations are DuckDB SQL of our own for the
   types used, each tested against the SQLite backend on SQLite as the oracle.
2. **Detection runs on the source's own fields, not on OCSF.** Each log source profile
   gains a field map *Sigma name -> the file's column*, every line citing the vendor
   document it comes from, kept as the original columns of the file (VARCHAR) beside
   `raw_events`. OCSF stays the schema of the timeline (revision 3), derived separately.
   Reason: `pySigma-pipeline-ocsf` (0.1.2, MIT) covers Windows / Sysmon, firewall,
   proxy, DNS and web server only - none of Entra, sshd or syslog - and pins
   `pySigma<2`; mapping our files to OCSF and then Sigma to OCSF would be two maps of our
   own to get wrong instead of one.
3. **A rule whose fields the file lacks is reported "not applicable", per rule, per
   file** - never run as 0 matches (gotcha #7 in Sigma form). The case shows which rules
   ran, which could not, and why.
4. **Every match names the rule's author, status and level** (DRL 1.1), and the SigmaHQ
   commit and its hash are recorded on the case.

## Consequences

- Positive: rules as published, semantics measured rather than assumed; one engine
  (DuckDB) as today; no second copy of the events.
- Negative: we maintain a ~40-line subclass of a third-party backend's internal hooks -
  a pySigma upgrade can break it, which is why the pin and the differential test go
  together.
- **Coverage on our data is thin.** On the real Entra CSV, 2 of 19 rules match anything,
  and one of those matches every row. The two misses above are silent unless the
  value vocabulary is mapped as well as the names (see Q12).

## Questions for the user (they change the stories)

- **Q11 - base rules for correlations.** SigmaHQ has none for our failed-login events.
  (a) Write the base rule ourselves, its condition taken only from the vendor's own
  documentation (Microsoft's AADSTS list, OpenSSH's log message), status `experimental`,
  marked as ours; the correlation logic and threshold come from the spec. (b) No
  correlation where no published base rule exists - brute-force and spray findings
  disappear for Entra and sshd. Recommended: (a).
- **Q12 - value vocabulary.** Map the portal CSV's display values to the Graph / Log
  Analytics values (`Single-factor authentication` -> `singleFactorAuthentication`) where
  Microsoft documents both, or leave such rules "not applicable" for the CSV.
  Recommended: map only what a Microsoft page shows side by side; otherwise not
  applicable. **Decided 2026-10-22 (the user): as recommended** - each mapped pair cites
  the Microsoft page that shows both forms (`docs/standards/SOURCES.md`); the
  `SigninLogs` reference is read before the map is written.
- **Q10 (open since revision 4) - thresholds.** The spec's example values give 0 on the
  spray sample. Spec values as defaults, adjustable per case and shown on the finding?
- **Q13 - noisy rules.** `Sign-ins from Non-Compliant Devices` flags 91 of 91 sign-ins.
  Show every published rule as is (the analyst decides), or let the analyst switch a rule
  off per case, recorded with a reason?

Not yet read, needed before the field maps are written: Microsoft's `SigninLogs` table
reference (Log Analytics) - the prototype map in `entra_run.py` is unverified.
