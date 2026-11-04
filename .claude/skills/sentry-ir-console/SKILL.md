---
name: sentry-ir-console
description: The SENTRY-IR console requirements: the Figma export and how to render its outlined SVGs, the functional spec PDF, Jira project IAI and the sprint rule, what Sprint 1 built, projects, the product decisions the user made that the Figma does not show (no incident, every datum from an upload, finding lifecycle) and what the data forced onto the Figma. Load before working a Jira story, comparing a page with the Figma, or revisiting a product decision.
---

# SENTRY-IR console (requirements Sept 2026)

Moved out of `CLAUDE.md` on 2026-11-04, word for word; `CLAUDE.md` keeps the one-line rules and the gotcha index. **Before changing code a gotcha names, read `docs/gotchas/NN-*.md`.** If this file and the code disagree, the code is the fact - fix this file (doc-keeper).

The target UI is `docs/figma-export/` (10 screens: login, Upload, Overview,
Incidents (= the Findings page, see *Decisions*), Timeline, Customers,
Attack-graph, Attck-map, Reports, Settings).
Its text is **outlined to paths**, so `grep` finds nothing; render each SVG
with headless Chrome (`--screenshot --window-size=1728,<height>`) and read the
image. Use the SVG's own height - `Overview.svg` is 2346px tall and a
1117px window silently cuts off its bottom half. On Windows pass the output
and `file:///` paths with forward slashes (`cygpath -m`); backslashes are
eaten on the way to Chrome and it renders "file couldn't be accessed". The
agreed functional spec is `docs/requirements/AI-Incident-Analysis-Reporting-FR.pdf`
(not in git; 59 items, FR-0..FR-12); its HTML source was generated, not
kept in the repo.

## Jira

**Work is tracked in Jira**, project `IAI` at
https://titlenattapat.atlassian.net (epics = spec areas, stories labelled
`IAT-FR-x.y`, six two-week sprints from 2026-09-29). Work the active sprint
in rank order. When a story needs something a later sprint builds, split the
dependent criterion into its own story in that sprint rather than leaving
the story open: IAI-12's open-findings badge became **IAI-78** (Sprint 3) that way.

Built in Sprint 1 (verified in Docker, 2026-09-29):
- **IAI-12 app shell / IAI-13 login** - grouped sidebar, user + role +
  logout, English per the Figma. Roles since IAI-14 (see the `case-api` skill, *Login*).
- **IAI-22/23/25/27 upload** - customer required, 10 GB after
  decompression, 2.5x disk check, `.gz` streamed, `.zip` → one case,
  separate upload / processing percentages.
- **IAI-20 case list** - was the table on the Overview; since 2026-10-19 the Overview has
  no case table (gotcha #50) and cases are reached from Customers or Findings. The Jira
  story still says Overview.
- **IAI-18/19 Customers** - a customer is added on the Upload page only
  (see *Decisions*); the Customers page's one action is deleting a customer
  (admin / manager, gotcha #74) and it shows, per
  customer, open cases of total / closed /
  highest open severity / last activity. FR-6.1 defines "open": since
  2026-10-27 a case is open while a suggestion in it is not decided (gotcha #73;
  from Sprint 3 it was "a high or critical finding not Resolved", IAI-79). Cases without a customer (pre-FR-2.1) are a "No customer" row
  so the totals add up. A customer's name opens its **profile page**
  (`#/customers/<id>`, `CustomerDetail.jsx`, 2026-10-15 at the user's
  request, no story; laid out as a customer profile - header card, Profile
  column, At a glance + cases - which the user chose over KPI tiles and
  over a report-style page): onboarded date (`created_at`, i.e. the first
  upload for it), uploaders, the log sources its files were read as, cases /
  findings / flagged events / highest severity / AI analyses, and every
  case. Frontend only - it reads
  `/api/overview?company_id=` and `/api/cases?company_id=`. "Reports" is
  shown as **AI analyses** on purpose: no report feature exists yet (IAI-55).
- **Projects (2026-10-15, the user's request, no story).** A project is one
  investigation of one customer, grouping the cases uploaded for it
  (customer -> project -> case). Chosen on the Upload page under the
  customer ("+ Add new project..." creates one, idempotent by name within
  the customer, like customers); **required since 2026-10-28** (gotcha #75,
  docs/specs/projects.md P1 - the API refuses an upload naming none, so every
  script names one); cases from before stay "No project". Stored in the customer's own store
  (`customers/<id>/projects/<pj-id>.json`), so a project can only hold that
  customer's cases: an upload naming another customer's project id is 409
  and creates nothing. A merge keeps the project; sources of different
  projects are refused. **Open / Closed** (P1): closes only when every case is
  processed and every suggestion decided, reopens at any time (manager, admin),
  takes no new case while Closed. Shown on the customer profile (Projects panel + a Project column),
  on its own page `#/customers/<id>/projects/<pj-id>`, on the case header
  and under the customer in the Overview / recent-uploads tables. Also
  (docs/specs/projects.md, gotcha #75): an Overview and a Findings filter per project
  (P2), rename / move a case / delete a project (P3), and on the project page the
  attack timeline and attack path across its cases (P4).
- Not yet: **IAI-24 resumable chunked
  upload** (Sprint 6). The upload is one request, so a dropped connection
  restarts a 10 GB file from zero.

Pages whose story has not come up render `pages/Placeholder.jsx` and appear
dimmed in the menu (`ready: false` in `components/Sidebar.jsx`). Flip the flag
when a page is built. Timeline, Attack Graph and Reports were flipped when `#/result`
was retired (gotcha #51) and are steps of a case now; Settings is the Users page
(IAI-14). No menu item is a placeholder today.

## Decisions the user made, which the Figma does not show
- **There is no "incident" - the finding is the only unit (2026-10-05).**
  The spec and Figma had incidents as groups of findings; they were merged
  into one concept. The unit is the collapsed finding of gotcha #19
  (`rid|srcip|username`): it carries the review decision *and* the status
  workflow. Grouping survives only as **related findings** (IAI-43/44), and
  the old opening threshold decides which findings enter the workflow
  (IAI-42). The brand line is "Finding Response Console"; ids are
  `FD-YYYY-seq`. File names that say Incident (`docs/figma-export/Incidents.svg`,
  the FR PDF) are left as they are.
- **Every datum comes from an upload.** No "New finding" button, no live
  feed, no EDR/SIEM/email integrations, no ingest API key. The Figma's
  source column (CrowdStrike, Splunk, Proofpoint...) becomes the log type.
- **A customer is added only on the Upload page (2026-10-05)** - the
  "+ Add new customer..." option of its customer select. The Customers page
  has no "Add customer" button, although the Figma gives it one (its only
  action is Delete, 2026-10-28). The
  `POST /api/companies` route predates Sprint 1 and is kept; no page calls it.
- Uploads up to **10 GB per file, measured after decompression**, with `.gz`
  and `.zip` (a multi-file zip becomes one case, even with mixed formats),
  resumable chunked upload, and percentage progress. All built except the
  resumable upload (IAI-24). A `.gz` *inside* a zip is skipped and listed,
  because its decompressed size could not be held to the budget. Known gap:
  `/merge` looks for `raw/<id>.log`, so a line-log case uploaded as `.log.gz`
  cannot be merged ("Raw file missing").
- Alerts, Threat Intel, Playbooks and Assets pages are cut.
- **All UI text is English (2026-10-05; done 2026-10-12)** - the last Thai
  strings (case page, review panel, analysis panel, events table, upload
  history, `format.js`, `api.js`, the review reason codes) were translated,
  not kept alongside. The only Thai left is `Sidebar.jsx`'s initials helper,
  which skips Thai leading vowels in *users'* names. Times the app itself
  records (upload, review, custody) render as `YYYY-MM-DD HH:MM:SS +07:00`
  via `format.fmtTime` - they used to be a Thai-calendar date in the
  browser's own zone. Code comments were always English.
- Findings: created by the rule engine, related and admitted to the
  workflow per gotcha #24, no time window (the whole case).
- **Finding lifecycle (FR-4.1, 4.5, 4.7, 4.8)** - the rules below still hold in
  `lifecycle.py` and its API, but **no screen moves a status or sets an assignee
  since the Respond step went**; the pages follow the analyst's decision instead
  (2026-10-27, gotcha #73). The Figma has status only
  (Open → Investigating → Contained → Resolved) and nothing stopped an analyst
  closing a finding without looking at it. The spec now requires:
  - A new finding starts **Open with no assignee** - the system created it.
  - To close: an assignee, and **the finding reviewed** (accept / modify /
    reject). This reuses `review.py`
    decisions keyed by `finding_key` (gotcha #19); it is not a second review
    store.
  - At close: a classification - true positive / benign true positive /
    false positive - plus a written summary.
  - A true positive must pass through Contained, with the containment actions
    recorded. False and benign positives may close straight from
    Investigating and are **excluded from MTTC**. Forcing them through
    Contained would record a containment that never happened and skew the
    metric.
  - Every status change is timestamped. MTTC is creation → Contained.

## What the data forced onto the Figma, measured on the same corpus
- **ATT&CK map:** ~98% of findings are `T1071` (C2, 65,774) and `T1595`
  (Reconnaissance, 28,889) - neither is among the Figma's 9 tactic columns,
  nor is Discovery (`T1046`). Show the tactics actually found, out of the
  Enterprise tactics (15 since ATT&CK v20). The Attack timeline step does exactly that since
  2026-10-22: a row of chevrons, one per tactic its confirmed groups reach, in ATT&CK's order
  (`rule_meta.TACTIC_ORDER`, `tactics_of`), each filtering the time-ordered list.
- **Timeline "last 24h" is always empty:** uploaded events are months old
  (Dec 2025 - Jun 2026 in the corpus). Timelines use the case's event-time
  range. The Overview's chart counts suggestions by the day their first event
  happened, over the whole span, as the case page does (2026-10-27; it was
  findings by *creation* time, high / critical only).
- **No asset inventory exists**, so "affected segments" and node roles such
  as "domain controller" become risk-ranked hosts/accounts (`risk_scores()`)
  and internal / external / IOC labels.
- Most of the Figma's sample findings (PsExec, Kerberoasting, AMSI bypass,
  web shell, phishing, OAuth consent, S3, USB) need EDR / Windows / mail /
  cloud logs that no decoder reads.
- The Figma has **no case-detail or review screen**, though both exist in the
  app today (events, findings, AI narrative, review + export gate). The spec
  keeps them as FR-11/FR-12; they need designing.
