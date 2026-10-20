# Behaviour profiles - layer C facts about addresses, accounts and hosts

Status: **approved and built for source addresses and accounts** (2026-10-20; Q27-Q29 as
proposed - windows 1 / 10 / 60 minutes, rank from 20 entities, sources first; accounts built
on branch `esxi-auth-dedupe`; hosts follow). Branch
`behaviour-profiles` off `mcp-tools`. A window is `[t, t + W]`, both ends included, so two
events exactly W apart share it. Measured: 0.06-0.09 s per 65,534-row case; parity unchanged.
The user's request: build behaviour profiles (item 1 of: profiles in SQL -> AI reads them
over MCP -> analyst decides).

## Why

A rule compares a count with a fixed number, and a fixed number taken from one customer's
data misfires on a customer with more traffic (the user, 2026-10-20). A profile instead
**describes** each address, account and host - how often, how fast, how widely, when - and
places it **against the other entities of the same evidence**, so a busy log is compared with
itself. It is layer C (D12): facts, never verdicts, no threshold of ours. The AI reads the
profiles (small, already counted) rather than raw rows it cannot count; the analyst decides.
Counting stays in SQL: exact, fast, reproducible (ACPO principle 3).

Standards: SP 800-92 §5.2.1 (understand the baseline of typical entries) and §5.2.2 (the
factors for prioritising: newness, time of day, frequency, source); SP 800-86 §6.4.2
(examine the sources around an event of interest).

## What is profiled, and from which logs

Only what our profiles actually fill. "n/a" means the log has no field for it - the profile
says so instead of showing 0.

**Source address**

| Fact | Auth logs (sshd, ESXi, PAM) | Entra sign-in | Firewall (PAN-OS, FortiGate) | Check Point |
|---|---|---|---|---|
| events, first / last seen, days active | yes | yes | yes | yes |
| sign-ins failed / succeeded / unknown account | yes | yes | n/a | n/a |
| distinct accounts tried; accounts that succeeded | yes | yes | n/a | n/a |
| **most failures in any 1 / 10 / 60 minutes** | yes | yes | n/a | n/a |
| first success after failures, and the gap | yes | yes | n/a | n/a |
| refused / allowed connections | n/a | n/a | yes | yes |
| distinct destination hosts; distinct refused ports (services on Check Point) | n/a | n/a | yes | services |
| **most refused in any 1 / 10 / 60 minutes** | n/a | n/a | yes | yes |
| bytes sent: total, largest session, to public addresses | n/a | n/a | yes | n/a |
| hours of day it was active (GMT+7) | yes | yes | yes | yes |
| listed by a threat feed | yes | yes | yes | yes |

**Account**: sources it signed in from (distinct, and most in any hour), failures and
successes, first / last seen, hours active, hosts it was used on (auth logs with a host).

**Host** (the host name of auth logs; the destination address of firewall logs): sources that
reached it, accounts used on it, refused / allowed inbound, outbound destinations and bytes.

## Against the same evidence (option B)

Every count above that varies between entities also carries its **rank among the entities of
the same case** - "more failures in 10 minutes than 99% of the 412 sources in this file". This
is what adapts to traffic volume: a large organisation's addresses are ranked against each
other. A rank needs a crowd: with fewer than 20 entities of that kind the rank is not shown,
and the profile says why.

The windows are fixed at 1, 10 and 60 minutes and all three are shown - no single window is
chosen, so there is no threshold to tune.

Not computable now, and said so rather than faked:
- **Impossible travel**: no profile maps a location field (Entra's `location` is not read
  yet) - needs the OCSF event store (revision 3).
- **"First time ever seen"** across cases: a profile covers one evidence item; across the
  investigation once the flow runs on the project (D6, story 2).
- **Lateral movement across hosts**: needs host fields beyond auth logs (Windows logs - no
  reader yet).

## Where it is computed and shown

- **Computed at ingest**, after the rules, into three tables in the case DuckDB
  (`profile_source`, `profile_account`, `profile_host`) by SQL - window functions with
  `RANGE ... INTERVAL n MINUTE` for the sliding counts. Derived data: recomputed on every
  re-process, nothing hand-edited. Time measured on the corpus before it ships (gotcha #18).
- **Shown**: clicking an address or account anywhere in the case (events table, Timeline,
  Attack events) opens its profile beside the page; the events table's context column gains
  one line per event from its source's profile ("failed 47 times in 10 min - top 1% of
  sources here").
- **Served over MCP**: `get_profile(case_id, kind, value)` and
  `list_unusual(case_id, kind, by)` - the top entities by a chosen fact, with ranks. This is
  what the AI reads in item 2.
- **Not a finding.** No profile fact enters the findings, the severity or the report gate.

## Changes (outline)

| Where | What |
|---|---|
| `app/services/profiles.py` (new) | the SQL that builds the three tables; `get(case, kind, value)`; `top(case, kind, by, n)` |
| `app/services/pipeline.py` | build profiles after the rules; progress stage `profiles` |
| `app/services/db.py` | `_events` adds the source's profile line to `context` |
| routes | `GET /cases/{id}/profiles/{kind}/{value}`, `GET /cases/{id}/profiles/{kind}?by=` |
| `app/mcp_server.py` | `get_profile`, `list_unusual` |
| `frontend` | a profile panel opened from any address / account; context line |
| tests | `tests/check_profiles.py` on gen_usecase: the attacker's 1/10/60-minute counts equal what the planted file holds (8 failures within a minute), the benign host's are low, n/a where the log has no field, ranks hidden under 20 entities; parity unchanged (no rule touched) |

## Questions

- **Q27 - windows.** 1, 10 and 60 minutes, all shown. Proposed: yes.
- **Q28 - minimum crowd for a rank.** 20 entities of the kind in the evidence. Proposed: yes.
- **Q29 - first build.** All three entity kinds at once, or source addresses first (the
  brute-force question), then accounts and hosts. Proposed: source addresses first, MCP tool
  and panel with them, the other two in a follow-up.
