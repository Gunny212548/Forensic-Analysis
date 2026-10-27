# Gotcha #73

**73. The analyst's decision replaced the status workflow on screen - every status stayed Open**

2026-10-27. The user asked when the Findings page's statuses (Open / Investigating / Contained /
Resolved) change. They never did: the buttons that moved them (assign, investigate, contain, resolve,
reopen - `components/Lifecycle.jsx`) left with the Respond step (gotcha #54, case_flow_design.md
revision 3), so every high / critical finding sat Open and unassigned, the status filter only ever
matched Open, MTTC was "—" for good, and a case could never close on the Customers page or the
Overview. The user chose to follow the analyst's decision instead (review.py: Unreviewed / Accepted /
Modified / Rejected), which the case's Attack events does change.

What changed:
- **Findings page**: a Decision filter ("Not decided" = Unreviewed) and column in place of Status;
  the Assignee filter and column are gone; the first tile is "Not decided" and toggles that filter;
  the menu badge is `undecided_count` (high / critical not decided). `/api/findings` takes `decision`
  and returns `by_decision` / `undecided_count`; it still takes `status` and `unassigned` for API
  readers, and the table sorts by level, then decision (not decided first).
- **Overview**: no MTTC row; the urgent list is high / critical not decided (worst first, then the
  longest waiting), its head "Not decided" / "Critical not decided"; the banner's "critical
  unassigned" is "critical not decided" (`critical_undecided`; `critical_unassigned` left the API).
- **Open / closed case** (Overview's open cases, the Customers page): open while any suggestion in
  it is not decided, closed when every one is - the report gate (`ready_for_report`); the highest
  open severity is the worst suggestion not decided (`open_max_lvl`). It was "while a high or
  critical finding is not Resolved" (IAI-79, gotcha #49).

Kept on purpose: `lifecycle.py`, `POST /api/cases/{id}/lifecycle` and the lifecycle entries in the
hash-chained review log - an audit trail is never cut, and an API reader may still use them; the
Overview API still reports `open_findings` and the MTTC fields. Nothing on screen reads them.

`tests/check_workflow.py` asserts the new open / closed rule (decide every suggestion of a case: it
closes; undo one: it opens at that suggestion's level), the decision filter against the badge, and
critical-not-decided against its Findings filter.
