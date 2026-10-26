# Who a finding is about - entities, account history, IPv4-mapped addresses (design)

Status: **proposed 2026-10-26**, waiting for Q93-Q97. The user asked for it after the synthetic Windows
quarter was uploaded to 8091 (case-20261026-073956-7449e480, "เช็คผล Finding อันใหม่").

## What the uploaded quarter showed

The rules found W1-W11 and flagged no plain or look-alike event (gotcha #68). Three problems remain,
and all three come from what the analyst and the AI are handed, not from the detection:

1. **One behaviour, hundreds of suggestions.** A suggestion is a collapsed finding,
   `rid|srcip|username` (gotcha #19), and the source and account are read from **each flagged row**.
   For a rule that decides on a source or an account across many rows, every distinct row value
   makes another suggestion. The quarter's 517 suggestions:

   | Rule | Suggestions | Distinct sources | Distinct accounts | What it is |
   |---|---|---|---|---|
   | WIN-BRUTE-2 | 262 | 2 | 261 | 2 sprayers (W1 + W11 from one device, W2); one per guessed name |
   | WIN-BRUTE-4 | 152 | 142 | 4 | one epoch against 4 accounts; one per rotating address |
   | WIN-INTEL-2 | 40 | 37 | 4 | listed addresses |
   | WIN-BRUTE-3 | 33 | 33 | 1 | adm.it guessed from 30 addresses (W9) |
   | WIN-BRUTE-1 / LAT-1 / LAT-4 / AUTH-1 / LAT-2 / HOST-2 / ... | 30 | | | |

   Rows split a finding further: a 4776 has no address, a 4688 in an RDP session has none either,
   and Sysmon writes `MEKONG\adm.backup` where Security writes `adm.backup`. W7's one RDP session
   became 3 WIN-LAT-1 suggestions, 2 of them with no source at all.
2. **The AI reviewed 80 of 517** (`triage.MAX_SUGGESTIONS`, highest level first) and **advised
   reject on W7 and W6** (8 of the 76 attack suggestions it saw): procdump reading LSASS "matches
   the documented false positive" of a security product; RDP as adm.backup "a first-time connection
   for backup tasks"; adm.backup's 280 failures "a service with an old password". Its facts never
   said that adm.backup **had been guessed and then signed in** from WS023 (W6, WIN-AUTH-1) two weeks
   before - the facts list other findings of the *source* only, and the W7 rows it saw had no source.
   Gotcha #13 again: missing input, not reasoning.
3. **`::ffff:10.20.50.23` read as external.** The DC writes 4768 / 4769 / 4771 addresses in the
   IPv4-mapped form; the rules read it as IPv4 (`rules_windows._addr`), the timeline column does not
   - 17,322 rows of the quarter. The AI called W11's guest device "an external IP".

## Proposed decisions

### E-D1 - a rule may name the entity of its finding (Q93)

`findings` gains two nullable columns, `entity_src` and `entity_user`. A rule that decides on an
entity writes it; every other rule leaves them NULL and keeps today's row-based key, so no generic,
Palo Alto or Check Point finding changes its key (review decisions, FD ids and lifecycles of existing
cases stay attached - gotcha #19, #49). Every reader that builds or matches a key (`db.finding_key`
callers, `collapsed_findings`, `finding_rows`, `triage.facts`, `severity`, `related`, `grounding`,
MCP - ten SQL sites) reads `coalesce(entity, row value)` through one view. Accounts in an entity are
written as the rules already compare them: lower case, no `DOMAIN\`, no `@realm`.

The Windows rules' entities - the thing each one decided on:

| Rule | entity_src | entity_user | Quarter: suggestions now -> proposed |
|---|---|---|---|
| WIN-BRUTE-1 guessing | attempt source | account | 7 -> 3 |
| WIN-BRUTE-2 spray | attempt source | - | 262 -> 2 |
| WIN-BRUTE-3 one account, many sources | - | account | 33 -> 1 |
| WIN-BRUTE-4 low-and-slow | - | account | 152 -> 4 |
| WIN-AUTH-1 sign-in after failures | attempt source | account | 4 -> 3 |
| WIN-INTEL-2 listed sign-in source | attempt source | - | 40 -> 37 |
| WIN-LAT-1 / -2 / -3 / -4 | the session's source | the session's account | 15 -> 7 |
| WIN-HOST-1 Kerberoasting | - | requesting account | 1 -> 1 |
| WIN-HOST-2 LSASS dump | - | the process's account | 2 -> 1 |
| WIN-MAL-1, WIN-INTEL-1 | row-based, as today (one host, one process) | | 2 -> 2 |

About 517 -> 61, so the AI reviews every one of them (under 80). The last column is an **estimate**:
BRUTE-2 / -3 / -4 and INTEL-2 are the distinct sources or accounts counted in the uploaded case's
findings; the BRUTE-1, AUTH-1, LAT and HOST rows are counted by hand from the incidents. To be measured. One effect to know: W1 (Jul 14) and W11 (Sep
15) come from the same guest device, so they become **one** WIN-BRUTE-2 suggestion with two episodes
in its text - one device, one decision.

### E-D2 - the account's history is a fact (Q94)

`triage.facts` lists "other findings of this source" today. Add the same for the **account**, across
every source, in time order relative to this suggestion: e.g. *"Account adm.backup: WIN-BRUTE-1
(password guessing) from 10.20.10.33, 280 attempts 2026-08-17 21:00-21:48, then WIN-AUTH-1 (signed in
after flagged failures) 21:48 - 15 days before this suggestion"*, and whether the account signed in
from this source **before** its first failure (the owner test of Javed & Paxson §4.2, already in
WIN-AUTH-1's text). Computed in SQL from the case's findings, cited like every other fact, nothing
inferred. The prompt is not changed (gotcha #13: hardening was measured to do nothing).

### E-D3 - an IPv4-mapped address is written as the IPv4 address it maps (Q95)

RFC 4291 §2.5.5.2: the IPv4-mapped IPv6 address "is used to represent the addresses of IPv4 nodes as
IPv6 addresses" - 80 zero bits, 16 one bits, then the IPv4 address (§2.2: "::FFFF:129.144.52.38").
`winevent.timeline_row` writes `::ffff:a.b.c.d` (any case) as `a.b.c.d` in `srcip`; `win_events.data`
keeps what Windows wrote. Rows, flagged counts and per-rule counts do not move (the rules already read
it so); keys of findings on those rows do. Old cases show the old form until re-processed (gotcha #21's
rule, said on the case like every re-process).

## Tests

- `tests/check_windows_rules.py`: the quarter's suggestions per rule as in the table (each incident
  one or a few suggestions); W7's RDP session one WIN-LAT-1 suggestion with its source; no `::ffff:` in
  `raw_events.srcip`; generic, Palo Alto and Check Point keys unchanged (`check_workflow`,
  `check_firewall_rules`, parity).
- The AI review re-run on the quarter (Ollama, about 10 minutes): every suggestion reviewed; W6 / W7
  advice recorded before and after - **measured, not promised**: the facts can change the advice, they
  cannot guarantee it.
- `check_triage.py`: the account-history fact, with its ids; `check_mcp.py`, `check_customer_isolation`.

## Questions

- **Q93 - entities (E-D1).** Let a rule name its finding's entity, Windows rules as in the table,
  every other rule unchanged? Recommended: yes.
- **Q94 - account history (E-D2).** Add the account's other findings, before / after, as a fact for
  the AI and the finding page? Recommended: yes.
- **Q95 - IPv4-mapped (E-D3).** Write `::ffff:a.b.c.d` as `a.b.c.d` in the timeline column?
  Recommended: yes.
- **Q96 - W1 + W11.** One WIN-BRUTE-2 suggestion per sprayer even when its episodes are two months
  apart (the key has no time)? Recommended: yes - the analyst decides about the device; the text lists
  each episode.
- **Q97 - order.** E-D3 first (keys depend on it), then E-D1, then E-D2, as one story on one branch,
  then the AI re-run on the quarter? Recommended: yes.
