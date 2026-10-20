# Gotcha #51

**51. The case page `#/result` is gone, Sprint 3 was reviewed and fixed, and the
architecture work ADR-3/4 is done (2026-10-19). Nothing of this is pushed or merged.**
Branches, each stacked on the one before: `sprint/findings-workflow` (Sprint 3 + its
review fixes `04fcd99`) -> `arch/split-routers` (ADR-4, ADR-3) and, separately,
`IAI-fd-detail` (the page split and review #4-#6). Worktrees: `D:/forensic-analyzer-wt`
(sprint), `-adr4` (split-routers), `-fd` (IAI-fd-detail). Jira IAI-40..49, 78, 79 are Done.
- **`#/result` was retired at the user's request ("the old format").** What it held:
  - one finding -> **`#/finding/<case>/<key>`** (`FindingDetail.jsx`: `ReviewPanel`
    with `onlyKey`, source events open, related chips link to their own pages). Opened
    from the Findings page and the Overview's urgent list.
  - a case -> three menu pages, one component (`CaseView.jsx`, `view` prop, so the
    analysis polling lives in one place): **Reports** (`#/reports/<case>`: summary +
    Analyse, mapping, VERIS, exports, chain, recommendations, Events, **Findings**,
    Evidence), **Attack Graph** (graph + risk ranking), **Timeline**. Opened from the menu
    with no case, each shows `CasePicker`. `#/reports/<case>/findings` opens a tab.
  - **The Findings tab of Reports is where medium / low / informational findings are
    reviewed** (the user's choice): they are outside the workflow and have no page of
    their own. The Overview's "awaiting review" link opens it.
  - `#/result/<case>` redirects to Reports, `#/result/<case>/<key>` to the finding page,
    so links pasted into tickets still work. Attack Graph and Timeline say "run the
    analysis from Reports" when a case has none.
- **Review of Sprint 3 (code-reviewer)**, fixed and tested in `check_workflow.py`:
  - **The MCP server wrote the FD-id registry** - `findings_view()` called
    `finding_ids.ensure()`, from a second process whose lock is in-process (duplicate ids
    possible). It now passes `assign_ids=False` and reads with `finding_ids.lookup()`.
  - **Log type was the file kind** (`log`, `zip`) for every line log and zip: it read
    `mapping["profiles"]`; line logs write `line_profiles`, and a zip's mapping is per
    member - `case_views.log_type(manifest, row_id)` now picks the member holding the row.
  - **Caches** (`overview._case_facts`, `findings_index.case_rows`) stamp with
    `filestamp.of()` = `(mtime_ns, size)` of DuckDB, review log, custody log **and** the
    id registry. The Overview's stamp missed the registry (a stale "findings per day"
    right after deploy), the Findings page's missed custody (stale reliability grade).
  - **"When were the findings created"** was written three times; it is now
    `custody.created_at()`. An id's year is that moment **in GMT+7**: an upload at
    01:00 +07:00 on 1 January is the new year.
  - **#4** "awaiting review" counts **workflow** findings not yet reviewed (8 vs 31 on
    the test store - informational ones kept the banner up for ever); "cases failed"
    links the failed case.
  - **#5** Overview links carry `company_id`; an area card opens
    `#/findings/area=<id>&status=open` - `status=open` (not Resolved) is a new filter,
    the number on the card.
  - **#6** a case **refused for integrity** (`case_views.integrity_refused`: `failed` +
    `IntegrityError`) kept its findings but vanished from the Findings page, badge,
    Overview and Customers. `case_views.holds_findings()` lists it again, rows carry
    `evidence_problem` ("evidence changed"), source events open; **exports stay 409**.
  - Not fixed: a pivot host relates every finding that targets it (review #9, measured
    only on synthetic data); a `|` inside a username makes its source events 400 (#11);
    `check_workflow` iterates `RULE_LABELS`, not `rules.RULES`.
- **ADR-4** (`docs/adr/ADR-004-split-routers.md`, a pure move): `services/llm.py`
  (provider switch, `_chat`, Ollama mapping, `_OtpmPacer`, the errors - re-exported by
  `analysis.py`), `services/merge.py` (refusals are `MergeRefused(status, message)`, so no
  service imports FastAPI), `services/analysis_jobs.py` (job state + map-reduce worker).
  `routers/cases.py` 664 -> ~400 lines. Verified: check_mcp, check_workflow,
  check_customer_isolation, check_jobs, check_manifest_atomic, and `bench_llm` x3
  byte-identical, 0 unsupported stages / ids. Still open: `on_event` -> lifespan.
- **ADR-3** (`docs/adr/ADR-003-authz-seam.md`): `services/authz.py` `can(user, action,
  company_id)` returns True until IAI-14; review, lifecycle, verify and merge ask it
  (`cases._authorize` -> 403). `tests/check_authz.py`. Reads, upload and analyze do not.
- **Testing in a container without touching production:** `docker build -t fa-x .` in a
  worktree, then `docker run --rm -v "$(pwd -W)/tests:/ro:ro" fa-x python /ro/check_...`.
  For a browser check, `docker run -d -p 8199:8000` and open `127.0.0.1:8199` (not
  `localhost`, gotcha on two instances). `tests/bench_llm_one.py` hardcodes
  `localhost:11434`; inside a container change it to `host.docker.internal`.
- **Scripted edits on this machine:** a Python edit that `open()`s without
  `encoding="utf-8"` reads cp1252 and wrote a lone `\xb7` into a `.jsx` - vite refuses
  the file ("stream did not contain valid UTF-8"). And an `\n` inside a Bash heredoc
  passed to Python became a real newline in the written source. Prefer the Edit tool.
