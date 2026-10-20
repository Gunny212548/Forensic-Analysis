# In-house rules - do they make sense?

Review of 2026-10-20, at the user's request ("develop our own rules so they make sense"),
against the three layers of `case_flow_design.md` D12 (A event type, B known pattern,
C context) and the code as it stands (`app/services/rules.py`, `severity.py`). Nothing is
changed yet; the proposals below need the user's decisions.

## What a rule that makes sense looks like

1. **It answers one question an analyst would ask**, in plain words: "did one source try many
   passwords in a short time?" - and its name and description say exactly that.
2. **A pattern happens in time.** Events far apart are not one behaviour: a correlation counts
   inside a time window, not over the whole file.
3. **Every threshold has a recorded reason** - a measurement on our data or a published value
   - and the finding shows the threshold next to the count ("14 failures in 10 minutes;
   rule: >= 10 in 10 minutes").
4. **The rows flagged are the evidence of the pattern**, not every row of the entity (gotcha
   #23, already held by every correlation rule).
5. **The ATT&CK tag names the behaviour the rows show**, checked against the technique page.
6. **It works across the investigation's files** (D6), when the pattern can cross files.
7. **It has a positive and a benign case in `tests/gen_usecase.py`.**

## Findings, rule by rule

| Rule | What it does today | Problem | Proposal |
|---|---|---|---|
| R1000 auth failed | every failed sign-in is a finding | An event type, not a pattern | **Layer A** (D13) |
| R1001 login success | every successful sign-in | Same | **Layer A** (D13) |
| R1002 invalid user | every attempt on a non-existent account | Same; one typo is normal | **Layer A** (D13); counted by a spray rule |
| R1003 SSH connection | every SSH connection | Same | **Layer A** (D13) |
| R1004 password changed | every password change | Same; on ESXi most are vCenter's monthly `vpxuser` rotation (gotcha #42) | **Layer A** (D13) |
| R2000 brute force | a source with **>= 3 failures in the whole file** | **No time window**: 3 failures over six months is not brute force. 3 is also the number of a mistyped password. | N failures from one source **within a window**, per target account; threshold measured |
| R2001 blocked repeatedly | a source with >= 5 denies, whole file | Not an attack pattern - the internet is refused all day; overlaps R2002/R2003; no window | **Layer C** fact ("this source was refused N times"), not a finding |
| R2002 port scan | >= 10 distinct refused ports per source, whole file | No window. Sees only a **vertical** scan (one host, many ports); a **horizontal** scan (one port, many hosts - e.g. SSH across a subnet) is missed | Window; add the horizontal form (distinct destination hosts) |
| R2003 service sweep | >= 20 distinct refused services per source, whole file | No window | Window |
| R2004 allowed despite blocks | >= 20 denies, >= 1 allow, denies >= 3x allows; flags the allowed rows | Order ignored (the allows may come first); whole file; tagged **T1133 External Remote Services**, which ATT&CK defines as "external-facing remote services ... such as VPNs, Citrix" - an allowed connection is not that unless the service is one | Window and order (allowed **after** being blocked); **drop T1133** unless the allowed service is a remote-access service |
| R2005 "password spray" | one **account**, failures from >= 5 sources, whole file | **Misnamed.** ATT&CK T1110.003: "a single or small list of commonly used passwords against many different accounts". One account from many sources is distributed guessing (T1110.001: "systematically guess the password"). No window. | Rename "distributed guessing on one account", tag T1110.001, window. **Add a real spray rule**: failures across many accounts (from one source, or in one window) |
| R2006 multi-source logins | one account, successes from >= 4 sources in one clock hour | Clock-hour buckets split a burst at :59/:00; an IPv4 and an IPv6 of one device count as two | Sliding window; review the IPv4/IPv6 pair before counting |
| R2007 beaconing | regular intervals to a public address; measured thresholds | Makes sense: measured (CV 0.6), egress only, reasons written | **Keep** |
| R3000 high-risk app allowed | vendor app risk >= 4 and allowed | The vendor's rating of the application, not an attack; 12,281 rows on one host (R2007 comment) | **Layer C** fact ("application the vendor rates high risk") |
| R3001 large transfer | one session > 50 MB, **any direction, any destination** | Internal backups and file shares match; one fixed number; a slow exfiltration split into small sessions is missed | Egress to public addresses only; **sum per source -> destination in a window** (the Sigma correlation spec's own example is `value_sum` of bytes per source, 1 h) |
| R3002 malware-flagged | the firewall's own category says malware / C2 | Makes sense - the vendor's verdict, cited | **Keep** |
| R3003-R3005 intel, by verdict | address in a feed, split allowed / blocked | Makes sense; the feed is quoted on the finding | **Keep** |
| R3006 intel inbound blocked | listed scanner refused at the perimeter | Informational by design - "the firewall doing its job" | **Layer C** fact, not a finding |

Escalation (`severity.py`):

| Pattern | Problem | Proposal |
|---|---|---|
| credential-compromise | The success only has to come **after** the first failure - months later still counts | The success must follow within the brute-force window |
| compromised-host | Makes sense: two different post-intrusion behaviours on one host | Keep |

## Missing patterns an attack path needs

These are what a forensic reconstruction asks first, and no rule answers them today:

- **Password spray** (many accounts) - see R2005.
- **Horizontal scan** (one port, many hosts) - see R2002.
- **Success after failures, then something new from that account** - the step after
  credential-compromise; needs layer C ("first time this account ...").

## What this would leave

| Layer | Rules |
|---|---|
| A - event type | R1000, R1001, R1002, R1003, R1004 |
| B - known pattern | R2000, R2002, R2003, R2004, R2005 (renamed), R2006, R2007, R3001, R3002, R3003, R3004, R3005 + new spray, horizontal scan |
| C - context fact | R2001, R3000, R3006 |

## Decided (the user, 2026-10-20)

- **Q18 -> measured.** Each correlation window and threshold is set by measurement on our own
  corpus, the way R2002 and R2007 were, and the measurement is written next to the rule.
- **Q20 -> yes.** R2005 is renamed (distributed guessing on one account), retagged T1110.001,
  and a password-spray rule matching ATT&CK T1110.003 (failures across many accounts) is added.

- **Q19 -> yes.** R2001, R3000, R3006 become layer C facts.
- **Q21 -> renames and layer moves first**; time windows are the next story.

## Story 1 plan - renames and layer moves (approved and built 2026-10-20, branch `rules-layers`)

Built as planned, verified in a container from the branch: every check script passes
(rule_meta, workflow, MCP, customer isolation, case flow, jobs, authz, identify); parity
over the use case, the samples, the Check Point benchmark and the corpus moved only the
moved rules and added only R2008/R2009, re-taken in `tests/baseline.json` (flagged rows
176,635 -> 47,959). Recorded as CLAUDE.md gotcha #56.

Found while planning: **R1001 cannot simply stop being a finding.** `severity.py`'s
credential-compromise pattern raises the *R1001 success rows* to high - that finding is
"the attacker got in", the most important one the rules produce. VERIS maps R1001 to "Use
of stolen creds", and the graph draws login edges from it. So the success-after-attack
evidence needs a layer B rule of its own before R1001 leaves.

| Change | Where |
|---|---|
| New **R2008 "login succeeded after brute force"**: a success from a source that brute-forced that account earlier (today's credential-compromise condition), flagging the success rows; level high; T1078. The escalation pattern keeps raising the attack's own rows | `rules.py`, `severity.py`, `rule_meta.py` |
| New **R2009 password spray** (ATT&CK T1110.003): one source failing against many accounts; threshold measured on the corpus and written next to the rule | `rules.py`, `rule_meta.py` |
| R2005 renamed "distributed guessing on one account", tag T1110.001 | `rules.py`, `rule_meta.py`, labels |
| R2004 loses T1133 | `rules.py`, `rule_meta.py` |
| R1000-R1004 stop writing findings; the event keeps its `action` (layer A) | `rules.py`; readers below |
| R2001, R3000, R3006 stop writing findings; a new `context` table (row_id, kind, detail) holds the fact, shown as a chip in the events table | `rules.py`, `db.py`, `EventsTable.jsx` |
| Readers of the moved ids follow: areas, VERIS (R1001 -> R2008), the auth set in `severity.py`, confidence families, related findings | `areas.py`, `veris.py`, `severity.py`, `db.py` |
| Tests: gen_usecase expectations, `check_workflow` (its auth-rule set), `check_mcp` (`get_rule R1000`), `check_rule_meta`; `tests/baseline.json` re-taken with every move explained | `tests/` |
| Docs: CLAUDE.md rule list, `docs/STANDARDS.md`, measurement PDF rebuilt | docs |

Not in this story: time windows (story 2), layer A vocabulary from OCSF (D14), layer C facts
beyond the three moved rules.

## Decisions needed

- **Q18** - correlation windows: one window per rule chosen by measurement on the corpus (as
  R2002 and R2007 were), the Sigma correlation spec's example values where one exists (1 h
  for failed logins), or set by the analyst per investigation with those as defaults?
- **Q19** - R2001, R3000, R3006 move to layer C (facts on the event, not findings to review)?
- **Q20** - R2005 renamed and retagged, and a real password-spray rule added?
- **Q21** - order of work: the windows first (they change most counts), or the renames and
  layer moves first (they change no detection)?

Every change re-takes `tests/baseline.json` with the moves explained (CLAUDE.md, parity).

## Sources read for this review

MITRE ATT&CK, read 2026-10-20: T1110.003 Password Spraying (v1.8, modified 2025-10-24),
T1110.001 Password Guessing (v1.7, modified 2026-05-12), T1133 External Remote Services
(v2.5, modified 2026-05-12). Sigma correlation rules specification 2.1.0 (`value_sum`
example: `bytes_sent` > 1,000,000 per source and user in 1 h; `event_count` example: >= 100
failed logins per host in 1 h).
