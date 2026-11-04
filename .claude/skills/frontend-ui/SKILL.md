---
name: frontend-ui
description: The React / Vite UI in frontend/: file map, the Overview's three levels and what each figure counts, the SENTRY-IR Figma and SOCRadar look with its colour tokens and light / dark themes, the static-SVG attack graph's layout and node rules, and the UI traps already paid for (autofill, cookies across ports). Load before changing anything under frontend/ or styles.css, or before judging how a page should look.
---

# Frontend UI

Moved out of `CLAUDE.md` on 2026-11-04, word for word; `CLAUDE.md` keeps the one-line rules and the gotcha index. **Before changing code a gotcha names, read `docs/gotchas/NN-*.md`.** If this file and the code disagree, the code is the fact - fix this file (doc-keeper).

## Overview (the dashboard)

**The Overview has three levels since 2026-10-28 (the user, gotchas #50, #75)** -
`#/dashboard` (every customer), `#/dashboard/<co>` (one customer), `#/dashboard/<co>/<pj>`
(one project). The first two are **overviews and nothing more**: three tiles (open cases of
N, to review, customers - or the customer's open projects of N), the attention banner when
something waits, and one table - **By customer**, or the customer's **Projects** - a row each
with its suggestions per area, not decided of all, the worst not decided, (open) cases and an
Evidence column (log source and period, days without events); a row opens the level below.
Only a project's Overview has the details: the summary card, Evidence coverage, the
detection areas, ATT&CK tactics reached (all 15), severity, top affected, Top rules (with the
analysts' decisions), urgent findings, activity - the SIEM-style sections the user chose on
2026-10-28; EPS, MTTx, a geo map and compliance were left out on purpose (gotcha #50). Cases
in "No project" have no detail page: move them into one. What follows is the detail level:

The Overview was redesigned on 2026-10-19 (gotcha #50) - an attention banner,
a KPI strip (since 2026-10-27 the summary card's right column, SOCRadar layout), the
detection-area cards (eight since 2026-10-26 - the host areas, gotcha #66), a per-day
chart, top affected, urgent findings and recent activity. **Since 2026-10-27 it counts
as the case page counts** (the user: the dashboard must match what a case shows):
the big total is the suggestions not decided, an area card every suggestion in the
area (and how many are not decided) and opens the case holding most of them, the
chart suggestions by the day their first event happened over the whole span, the
urgent list the high / critical findings not decided; no MTTC (gotchas #50, #73). The
case table is no longer on it. No figure is a placeholder. "Top affected"
ranks by accumulated risk score, not by case count: ranked by count, the
benign admin account seen in every seeded case came out first (gotcha #16
again). **The page always says whose data it shows (2026-10-15, the
user's requirement):** the header names the customer, or every customer
when unscoped; each top-affected row and activity line carries its
customer; and top-affected is aggregated *per customer* - the same address
in two customers' cases is two hosts, and used to add up into one row.
A technique card stays *one* card and lists every customer it was seen in:
the same technique is the same behaviour whoever it happened to. **An account on
Top affected names where it was seen** (2026-10-27): "on" the computers whose logs
hold its flagged events and "from" the source addresses - `NT AUTHORITY\SYSTEM` or a
local `Administrator` is a different account on every computer (`db.account_origins`,
a query of its own because `risk_scores()` feeds the narrative's prompt).

## The app, its look and the attack graph

The UI is a **Vite + React** app whose source is `frontend/` and whose build
output is `static/` — which is generated, gitignored, and never edited by
hand. `app/main.py` serves `static/index.html` at `/` and the bundle through
the `/static` mount, so `vite.config.js` sets `base: '/static/'` to match.

```
frontend/src/
  App.jsx              session gate + hash router (#/dashboard, #/upload,
                       #/finding/<case>/<key>, #/reports|attack-graph|timeline
                       [/<case>[/<tab>]], and the menu routes of Sidebar.jsx);
                       the old #/result/<case>[/<key>] redirects (gotcha #51);
                       signed out -> #/login, and signing in always
                       lands on the Overview (the user's call, 2026-10-16)
  api.js               every call the UI makes, and nothing else
  format.js            fmtBytes/fmtTime/shortTs + the status & severity maps
  theme.js             light / dark, kept per browser in localStorage fa_theme
  pages/               Overview (#/dashboard[/<co>[/<pj>]], three levels) ·
                       Upload · Cases · CaseFlow (one
                       case as six steps, #/case/<id>/<step>, gotcha #52) ·
                       Findings · FindingDetail · Customers (Delete per row) ·
                       CustomerDetail (also a project's page: close / reopen,
                       rename, delete, move a case, timeline and path) ·
                       Users (the Settings menu item, admin) · Login ·
                       Placeholder (a menu page not built yet - none today)
  components/          Sidebar (app shell, FR-0, theme button) · StepBar
                       cards.jsx (summary card, area card, stat tile, folding
                       section) · icons.jsx (stroke icons, inline SVG)
                       EventsTable · ReviewPanel (Attack events, by area and
                       rule) · AiReview · FindingEvents · RuleCard (Sigma/ADS)
                       Evidence (custody) · Mapping (how each file was read) ·
                       Period · Question · Reprocess · ProfilePanel · Veris ·
                       DeleteCase · DeleteCustomer · AttackGraph ·
                       AttackTimelineView (a case's and a project's) · analysis.jsx (chain/timeline/
                       risk/meta, grounding warnings) · common.jsx (severity
                       pill, status badge, MITRE tags). Workspace.jsx (left
                       over from #/result) was removed on 2026-10-29; Lifecycle.jsx
                       went with the status workflow's buttons (gotcha #73)
```

It replaced a hand-written 1,212-line `static/index.html`, whose URLs were
kept unchanged so pasted case links survived the rewrite. Neither of its
localStorage keys is read any more: `analyst-name` (the reviewer is the
signed-in account, see `case-api` *Login*) and `fa_recent_uploads` (since IAI-28 the
Upload page's "My recent uploads" are the cases whose `evidence.recorded_by`
is the signed-in account, from `GET /api/cases` - they follow the analyst
across browsers, and a case that no longer exists cannot linger). The
original was kept as `legacy/index.html.orig` until 2026-10-29; it is in git
history now (`git show fb61af5:legacy/index.html.orig`).

**What "no external JS" now means.** The old page took it literally: no build
step and no dependency, because a vis-network CDN import had been removed
after a physics simulation added interactivity nobody needed and read worse in
a report. The constraint that actually matters is **nothing fetched at
runtime**, and Vite satisfies it - every asset is bundled locally, so a case
is still workable air-gapped (gotcha #17). The build needs the network; an
analysis never does. Dependencies are pinned exactly and the Dockerfile builds
the bundle in its own `node:22-slim` stage rather than copying the host's
`static/`, so an image can never ship a stale bundle and the output stays
reproducible - which matters because the output is evidence. Verified: the
in-image build produced a byte-identical bundle hash to the host build. The
SigmaHQ rules follow the same rule since 2026-10-29: the image's `sigma` stage
fetches a pinned commit's archive (checked by SHA-256) and converts it with
pySigma into `/opt/sigma/windows_rules.json`; the app never imports pySigma
(gotcha #79). The archive build and a git checkout gave the same file byte for byte.

**Look and feel follow the SENTRY-IR Figma (since 2026-09-29).** The palette
in `styles.css` `:root` was sampled from the rendered frames (light
`#EEF0F3` page, white panels, amber `#B36B00` as the only action colour - red since 2026-10-27, below), and
the type is IBM Plex Sans / Plex Sans Thai / Plex Mono, bundled via
`@fontsource` so the nothing-fetched-at-runtime rule above still holds.
Plex Sans has no Thai glyphs, and most UI text is Thai, which is why the Thai
cut is there too. Severity, review-status and job colours kept their meanings
and were only re-mapped onto the Figma tokens. The attack graph kept a dark
canvas until IAI-61 (2026-10-29) put it on the panel colours, below. The
whole UI is in English, as the Figma is (since 2026-10-12, see the `sentry-ir-console` skill, *Decisions*).

**The SOCRadar layout, light and dark (2026-10-27, the user's request).** The
user asked for the whole app to look like SOCRadar's dark-web report and
approved a mockup (claude.ai artifact "SENTRY-IR redesign"); it is built in
steps: 1 tokens + theme button + menu, 2 shared summary card / area card /
stat tile / collapsible section (`components/cards.jsx`, icons in `icons.jsx`),
3 Overview, 4 the case page (all four done: a summary card above the steps -
suggestions by the day their first event happened, how many the AI explained
and the analyst decided - the steps as six boxes, and Attack events as one
folding section per detection area with a block per rule, each suggestion
keeping its whole card), 5 the other pages (Findings, Cases and Customers open
on a row of stat tiles - Findings' critical / high tiles are its severity
filter - and every panel and list head is the cards' shape). All five done
2026-10-27. A section folds only when the analyst clicks; its head keeps its
counts. Then, at the user's word ("too much"), the Ingest step became folding
sections: Files read (a file whose reading needs attention - not analysed,
columns guessed or missing, rows not loaded, time unreadable - is always shown,
`Mapping.needsAttention`; the others fold under one line), question, custody and
method open; periods, rules per product, lines and the events table folded
(`lazy`: not fetched until opened). Attack events dropped its "N not decided",
"final report cannot be issued" and "AI explaining N of M" lines, Ingest its
"events read, digest verified" line - the summary card (polled while the AI
runs) and the step box say it; the AI line returns only when explanations are
missing, with Review again. **Say a figure once on a page** (the user). Light stays the default; dark is `[data-theme=dark]` on
`<html>`, set by the button beside the brand (`theme.js`) and kept per browser
in localStorage `fa_theme` - the OS setting is deliberately not followed (no
look the analyst did not ask for). The action colour is red now (`--accent`,
the user's choice over blue, knowing it sits near critical), so **`--accent`
means "act here" only**: amber high severity and warnings, which used to share
it, are `--warn` - give any new severity or warning colour `--warn`, never
`--accent`, or every high reads as a button. A colour belongs in a token with a
value under both themes; a literal hex in a rule is wrong in one of them.

The attack graph is still a **static SVG** with no library
(`components/AttackGraph.jsx`), and its layout keeps the old page's logic,
because these diagrams get screenshotted into reports: nodes in columns by role
(pure sources left, pure sinks right, anything with both in/out in the middle),
and edge labels anchored just past the *source* node rather than at the edge
midpoint — these graphs are usually many sources converging on one target, so
every midpoint lands in the same spot and the labels pile up on top of each other.
**Its look since IAI-61 (2026-10-29, the user's choice between the Figma and a
Microsoft attack-path picture: "three columns, the attack-path look")**: column
heads (SOURCES / PIVOTS / SINKS), round nodes coloured by role with an icon for
the node's kind (address, host, account), the name underneath and callouts
(*On threat feed*, *External*), curved edges in the colour of their highest
finding's level, technique labels in capsules tinted by level (cut at 34
characters, the whole label its tooltip); every colour a token
(`.ag-*` in styles.css). A node says only what the evidence does
(`db.node_facts`): internal is RFC 1918 / loopback / link-local - not
`ipaddress.is_private`, which also calls the RFC 5737 documentation ranges the
synthetic attackers use private - and no role such as "domain controller".
**What a node is (2026-10-30, gotcha #80):** an edge goes to the address it
reached, else to the computer that logged the event (a Windows logon's Computer),
and only when a row has neither to the account; the account rides on the edge
(`accounts`, "· as adm.hd +4 accounts" at the end of the label). An address is
drawn as its host when the case's own Windows events tie it to that one computer
(its Sysmon 3, its `NAME$` sign-in / TGT), so a pivot reads as one node: the
mockup chain `198.51.100.66 -> rds01 -> fs01 / sql01`. The risk ranking under
the graph still counts the address and each `DOMAIN\user` spelling apart - it
feeds the narrative's prompt and was left alone.

Two things the rewrite changed on purpose:
- **`escapeHtml()` is gone.** The old page concatenated `innerHTML`, so every
  filename, company name and rule description had to be escaped by hand. The
  discipline was actually held - audited before porting, no gaps - but JSX
  escapes text nodes for us, so the class of mistake is removed rather than
  guarded.
- **No `window.prompt()`/`alert()`.** Choosing a rejection reason used to mean
  typing a number 1-N into a browser prompt, and the analyst name was another
  prompt. Both are now inline: `reason_code` is a `<select>` fed by the API's
  own `reason_codes`, with the confirm button disabled until one is chosen, so
  FR-4.6 is enforced in the UI instead of discovered as a 400.

**Never gate a form's submit button on React state that autofill feeds.**
Chrome fills a saved account into the login fields without firing input
events, so `Login.jsx`'s button - disabled until `email`/`password` state was
non-empty - sat greyed out beside two visibly filled fields, and the analyst
could not sign in (found 2026-10-05). The inputs are now uncontrolled and
`submit()` reads `form.elements` at click time, which is after Chrome releases
the autofilled values; an empty field is reported as an error instead.

`npm run dev` in `frontend/` serves the UI with hot reload and proxies `/api`
to the container on 8091, so the UI can be worked on against real cases.

**Two instances on one machine log each other out.** Browsers do not scope
cookies by port, so a host-run copy (`uvicorn` on e.g. 8097 with its own
`DATA_DIR`) and the container on 8091 share one `fa_session` cookie on
`localhost`. Signing in to either overwrites it with a token the other's
secret rejects, and the other bounces to the login page on its next request -
which looks exactly like a session bug and is not one (2026-10-05: the
"logged out ~7s after login" was a sign-in on 8091 in another tab). Test the
host copy on `127.0.0.1:<port>` instead, a different host name with its own
cookie jar, or stop the container.
