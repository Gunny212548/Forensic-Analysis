# Gotcha #50

**50. The Overview was redesigned three times in one day, and what the user
rejected is recorded so it is not proposed again (2026-10-19, the user's
request, no story).** The cards follow a reference screenshot the user
supplied (score top right, rows of coloured chips, a trend under them) in the
console's **light** palette - the user chose light over a dark console.
Order now: header (unchanged: title, status line, **the line naming the
customer** - the 2026-10-15 requirement stands - Refresh, Upload) -> a thin
**attention banner that exists only while something waits** -> one KPI strip
(Open findings, mean time to contain against `MTTC_TARGET_HOURS`, default 4,
Open cases, Customers) -> **Detection areas** (six cards) -> findings per day
+ severity + top affected -> most urgent findings + recent activity.
- **Areas** (`services/areas.py`): every one of the 20 rules belongs to exactly
  one of six areas (Authentication, Brute force & spraying, Scanning & policy,
  Malware & C2, Data & applications, Threat intelligence); `check_workflow.py`
  fails when a rule is not placed. The number on a card is workflow findings
  not yet Resolved, the chips are those open ones by level, the trend is
  findings first seen per day of *event* time on one 30-day axis. A card opens
  `#/findings/area=<id>&status=open` (gotcha #51). No 0-10 score: the user declined it, because every
  number must be explainable and no standard formula exists (gotcha #16).
- **Findings per day** uses the id registry's time (when a finding entered the
  workflow), not event time - uploaded events are months old.
- **MTTC** is `lifecycle.summary` per case, summed in `overview.build`; the
  per-case facts are cached on the DuckDB, review-log and custody mtimes.
- **Attention** counts: critical findings unassigned (link: Findings filtered
  `#/findings/severity=critical&unassigned=1`, plus `company_id` when scoped),
  **workflow** findings awaiting review (opens that case's Reports > Findings),
  failed cases (links the newest), and custody / review-log
  problems (a custody chain that no longer verifies, or whose last integrity
  check failed - a later passing check clears it).
- **Rejected by the user - do not re-propose:** a four-tile Attention panel with
  a hint line under every number; a one-line header without the customer line
  and Refresh (reverted at once); a page cut down to attention + KPIs + areas
  (reverted at once). Taken off the page: the case table, the techniques list.
  Cases are reached from Customers or Findings; the ATT&CK Map page is still a
  placeholder. **Jira IAI-20 and IAI-67..70 still describe those on the
  Overview and are stale.**
- `/api/overview` still returns the daily case chart, the case list, the
  techniques and `recent`; the page ignores the first three and tests use `recent`.
- `docs/STANDARDS.md` rows 17-19 state the internal methods (ids, related
  findings, areas).
- **2026-10-27, the SOCRadar layout (the user's request, mockup approved):** the
  same content rearranged, nothing rejected above brought back. The KPI strip is
  the summary card's right column (Open findings big, highest open severity,
  MTTC / open cases / customers under it); last upload, cases processed and
  areas with open findings are fact tiles beside the per-day chart; an area card
  is icon + open count + share of the open findings + the open ones by level,
  greyed when nothing is open (the level chips went into that line); severity is
  counts plus one split bar; most urgent and recent activity are folding
  sections. No caption under the KPI numbers (rejected above), the customer line,
  Refresh and Upload stay.
- **2026-10-27, later: the Overview counts as the case counts (the user: "the
  dashboard does not match the case - the case has lateral movement, the
  Overview shows no number").** Every Lateral movement suggestion was medium, so
  the card - which counted only high / critical findings open in the workflow -
  said 0 beside a case listing 8. Now: an area card's number is every suggestion
  in the area (the line under it: by level, how many not decided, how many open
  in the workflow), and it opens the case holding most of them on Attack events
  (`case_id`; the Findings page lists the workflow only, so it could not show
  them); the big total is suggestions not decided, with Analyst decided under it;
  the chart is suggestions by the day their first event happened over the whole
  span, as on the case page (cut to 30 days it said 110 where the case said 526);
  "areas with suggestions". The banner's "awaiting review" went - the big total
  says it. The workflow's own figures (open 7, critical unassigned, MTTC, open
  cases) stay on the urgent list, the Findings page and the menu badge.
  `check_workflow.py` asserts `undecided`, `case_id` and the whole-span trend.
- **2026-10-27: an account on Top affected names its computers** (the user: "NT AUTHORITY\SYSTEM,
  Administrator - say where they come from"). SYSTEM or a local Administrator is a different account
  on every computer; the row now says "on app01 (5,436) · jump01 (95) · dc1 (91) +3 more" - the
  computers whose logs hold its flagged events (`hostname`, the machine that wrote the event), most
  events first, every full name on hover; "computer not recorded" when the log has none (sshd /
  ESXi lines, gotcha #3). `db.account_hosts()` is its own query: `risk_scores()` feeds the
  narrative's prompt (analysis_jobs), which must not move.
