---
name: validate-changes
description: Which test proves what in the forensic analyzer: every tests/check_*.py and how it must be run (host, container, scratch AUTH_DIR, Ollama, --evtx / --sigma inputs), the synthetic datasets with ground truth, check_parity.py and its baseline, the corpora and anchor counts, the Check Point real-world benchmark, scale and timing numbers, and pruning the store after validation. Load before running tests, claiming nothing regressed, updating the baseline, or quoting a corpus figure.
---

# Validating changes

Moved out of `CLAUDE.md` on 2026-11-04, word for word; `CLAUDE.md` keeps the one-line rules and the gotcha index. **Before changing code a gotcha names, read `docs/gotchas/NN-*.md`.** If this file and the code disagree, the code is the fact - fix this file (doc-keeper).

## Checks

`tests/gen_usecase.py` generates a synthetic attack scenario whose every rule hit is
known in advance (see `tests/README.md` for the expected counts). Run it
after touching `decode.py`, `rules.py`, or the ingest pipeline - it catches
both missed detections and false positives, and it is how the R2001 MITRE
mis-tag below was found.

Real JSON captures live in `tests/samples/` (Entra sign-ins from Splunk
attack_data, Apache-2.0, with a README of what each must produce);
`python tests/check_parity.py tests/samples` checks them (gotcha #39).

Two more checks, each for its own layer:
- **Narrative** - `python tests/bench_llm.py <scratch> qwen3.5:9b --runs 3`
  (needs Ollama on localhost:11434): grades the AI narrative against the
  same ground truth - expected stages, unsupported stages, invented ATT&CK
  ids, grounding warnings. Run it after touching `analysis.py`,
  `grounding.py` or anything that feeds the prompt; with the schema and
  seed in place the three runs should be byte-identical (gotcha #37).
- **MCP server** - `tests/check_mcp.py` (all 19 tools, pivots, refusals, access log), run in the container
  as its docstring shows, because the concurrent-writer check needs Linux
  `flock` (gotcha #38).
- **Job queue and manifests** - `tests/check_jobs.py` (45 checks, no DuckDB) and
  `tests/check_manifest_atomic.py` (gotcha #48); run in the container or on the host.
- **Finding workflow and Overview** - `tests/check_workflow.py <scratch> --repo /app`
  (~110 checks: threshold, ids, source events, related findings, the Findings page
  and its decision filter, every refusal and both close paths of the lifecycle API,
  Customers - open while a suggestion is not decided -, the Overview figures against
  the cases (undecided, the case a card opens, the whole-span trend, an account's
  computers and sources), a forged custody log); needs the container (`static/`).
  Run it in a throwaway container with `AUTH_DIR` on a scratch path - in the live
  one its test accounts land in the real `users.json`. Gotchas #49 / #50 / #73.
- **Report drafts** - `tests/check_report.py [repo] [--scratch DIR]` (gotcha #83, 67 checks): the
  skeleton's refusals, the gate, a draft's every section from the confirmed groups only (no other
  customer's data), the attack path PNG + SVG twin, versions kept, finals, the summary check - a
  skeleton built in code and a stand-in model, no Ollama. `tests/bench_report_summary.py <case>` measures
  the real model's Thai summary on a project in the store (~12 s, runs identical).
- **Sign in with Google** - `tests/check_google_login.py [repo]` (gotcha #82): PKCE / state / nonce,
  every ID-token check, the domain, `sub` binding, who is made and as what, the audit lines - against a
  stand-in for Google's token endpoint, so no network and no Google account; needs `static/`.
- **Authorisation** - `tests/check_authz.py [repo]` (ADR-3, gotcha #51, IAI-14): the permission
  table per role, every case route answering 403 exactly where `authz.can` says no, the Users
  routes, wrong-typed account changes refused; deleting a case and a customer (gotcha #74).
- **Projects** - `tests/check_projects.py [repo] [--scratch DIR]` (gotcha #75): a project required
  on upload, close / reopen and its gate, a Closed project refused for upload and merge, the
  Overview and Findings per project, the customer's project rows against each project's own
  Overview, rename / move / delete, the timeline and the joined graph across cases (empty while
  a suggestion is not decided, the rejected one left out once all are).
- **Customer isolation** - `tests/check_customer_isolation.py <scratch>
  --repo /app` (31 checks, gotchas #40/#41, and projects); run it in the container the same
  way as check_mcp. Run it after touching `storage.py`, any path helper or
  a route that lists or merges cases.
- **Log identification** - `tests/check_identify.py [--corpus]` (gotcha #53, branch
  IAI-92): each sample identified as its log source and no other, negatives
  unrecognised; `--corpus` adds the real customer files. No store, no network.
- **Behaviour profiles** - `tests/check_profiles.py [--repo DIR]` (gotcha #57): windows and their
  edges, ranks and the 20-address floor, n/a, bytes to public addresses; duckdb only.
- **Windows event logs** - `tests/check_windows.py <scratch> --repo /app [--evtx D:/logtest/windows]`
  (gotcha #60): event XML from the committed samples; with `--evtx` (lab folder outside the repo,
  copied into the container) every .evtx record counted against its chunk header and compared item
  by item with Windows' own `.ToXml()` rendering. Check Point Log Exporter: `tests/check_checkpoint_le.py`.
  It failed from story 6 (2026-10-29) to 2026-10-30: the Winlogbeat sample holds a 1102 (the Security
  log cleared), and SigmaHQ's "Security Eventlog Cleared" rightly fired beside WIN-BRUTE-1 + WIN-AUTH-1;
  the check now asserts the in-house rules and SigmaHQ's apart. **Run every `tests/check_*.py` before a
  rule change is merged** - story 6 ran the rule and flow checks but not this one.
- **Detection accuracy** - `tests/gen_checkpoint_quarter.py <outdir>` (seeded): three months of
  Check Point Log Exporter records with attacks I1-I6 buried in an office's traffic and a
  `ground_truth.csv` for every non-benign row. Upload the zip, then score findings and the AI's
  advice per incident against the ground truth (gotchas #62, #64). In git since 2026-10-26; the
  scoring scripts are not.
- **Firewall rules** - `tests/check_firewall_rules.py` (gotcha #62): Palo Alto and Check Point -
  TRW, the measured line and the no-line case, each behaviour's non-events, service names where a
  log has no port, Detect as neither verdict, no product's rule on another product's rows.
- **Windows sign-in rules** - `tests/check_windows_rules.py <scratch>` (gotcha #65): one attempt per
  4625 + 4771 / 4776, then `tests/gen_windows_domain.py` (seeded: a domain's three months, incidents
  W1-W11 and look-alikes, `ground_truth.csv`) scored per incident - no plain or look-alike row may be
  flagged - and the real PurpleSharp spray; the lateral-movement and host rules (gotcha #66) on the same
  quarter and the real OTRF RDP / LSASS capture; story 5d (gotcha #68): W3 / W10 / W11, the CUSUM on a
  known series, 4768 0x6, the OTRF reconnect; one suggestion per behaviour (gotcha #69); story 5e
  (gotcha #70): a sprayer's own `...$`, a fleet-wide beacon; story 5f (gotcha #76): Defender detections
  and their outcome (medium only when remediated), a lone 1011, turned off / back on, tamper protection,
  exclusions vs a routine 5007; story 5g (gotcha #77): a deployment tool's two-day service not flagged - and with `--winevents "D:/logtest/window test/WinEvents.log"` the
  user's file (3 suggestions, nothing else). Also the attack path (gotcha #80): W7 / W8 drawn from
  `ws023` to `rds01` / `sql01`, WS023's address as WS023, every edge naming its account.
- **A chain to look at** - `D:/mockup-logs/bruteforce-pivot/gen_bruteforce_pivot.py <outdir>` (outside
  the repo; imports `tests/gen_windows_domain.py`'s writers, seed 20260917): three weeks of Mekong's
  ordinary work and, on 2026-09-17, RDP guessing from 198.51.100.66 onto RDS01, the success, then RDP
  to FS01 and PsExec to SQL01 from it - one zip (`out/bruteforce-pivot-2026-09.zip`, 21,801 events)
  and `ground_truth.csv` (475 attack events). Measured: 13 suggestions, all the chain's (WIN-BRUTE-2,
  WIN-AUTH-1, WIN-LAT-1 x2, WIN-LAT-2, WIN-LAT-4, 7 SigmaHQ high), nothing of the ordinary work; not
  WIN-BRUTE-1 - the guesser tries five names, so it is a spray. Not in the parity baseline.
- **The user's blind Windows quarter** - `D:\logtest\blind-windows` (`gen_windows_blind.py`, seed
  20260401, Kinnaree Textiles, K1-K15, `out/answer_key/`). **Its key has been read** (gotcha #70): it
  measures fixes now, not the rule set; a fair blind test needs another seed whose key nobody reads.
  Its `answer_key/*.csv` and `evidence/COLLECTION.txt` show as NEW in the `D:/logtest` parity run -
  not logs, never `--update` them.
- **AI review of suggestions** - `tests/check_triage.py <scratch>` (gotchas #64, #71): the facts, the
  schema's enums, the address and cross-citation checks, a model that cannot be reached; no cap (90
  suggestions), every rule first, retry then one by one, Review again, the background queue; a fake
  model, no Ollama - run it with `TRIAGE_ENABLED=1`.
- **Products and periods** - `tests/check_products.py <scratch>` (gotcha #61): product per row, a
  product rule on its rows only, periods and gaps, the n/a matrix, findings unchanged end to end.
- **Case flow** - `tests/check_case_flow.py <scratch>` (gotcha #52): step states (Attack timeline
  and Attack path wait for every decision; `/graph` empty until then, never a rejected group), and
  every step citing a standard marked read in `docs/standards/SOURCES.md`.
- **SigmaHQ** - `tests/check_sigma.py <scratch> --sigma <checkout> --dockerfile <Dockerfile>` (gotcha #79,
  `specs/sigma_windows.md`): the bundle at `/opt/sigma` matches the Dockerfile's pin and attributes every
  rule; SigmaHQ's 445 Windows regression samples through the pipeline, 439 exact and only the six named
  differences; a failing SigmaHQ rule never fails a case. Needs a dev image built after story 6
  (`--build`) and the pinned commit's `regression_data/` copied in (`D:/sigma-spike/sigma`); ~30 min.

**`tests/check_parity.py` asserts it, so nobody has to read a table.** Until
2026-09-15 every ingest change was validated by uploading files, curling
`/api/cases` and eyeballing the counts - which is why the R2002/R2003 defect
of gotcha #23 sat in plain sight in the anchor numbers for months. The script
uploads, polls, and diffs per-file `rows / flagged / per-rule` counts against
`tests/baseline.json`, printing every drift and exiting non-zero:

```bash
export FA_EMAIL=you@example.com FA_PASSWORD=...          # an account, see Login
# uploads go to customer "Parity check" - FR-2.1 refuses a case without one
python tests/gen_usecase.py /tmp/usecase
python tests/check_parity.py /tmp/usecase                  # ground truth, ~5s
python tests/check_parity.py "D:/forensic system/Logtest"  # full corpus, ~3min
python tests/check_parity.py <dir> --update                # accept the change
```

stdlib only, so it runs without the app's dependencies. Three details worth
keeping, each of which was a bug in the checker before it was a feature:

- 0-byte files are reported as notes, not failures - the API rejects them
  with 400 by design.
- Results are keyed **name -> list of variants matched by md5**, because the
  corpus contains two different files both called `log_30_.csv`. Keying by
  name alone silently dropped one of them, so the first "PARITY OK" printed
  was one file short. **When a run claims everything matches, reconcile its
  totals against the previous number before believing it** - a 102-row
  discrepancy is how that was caught.
- `--update` **merges** and prints what it added, changed and left alone.
  The first version rewrote the file from whatever the run covered, so a
  `--update` pointed at one directory took the baseline from 70 entries to
  67 and silently deleted the ground-truth pair and the Check Point
  benchmark. A tool whose job is catching silent drift must not be able to
  cause it; if `--update` ever reports 0 left untouched on a partial run,
  something is wrong.

The Check Point benchmark is in the baseline but is not under `Logtest`;
check it with `python tests/check_parity.py D:/logtest` (gotcha #43).
Since W2 that run also covers `D:/logtest/windows` (gotcha #60): `.evtx` is a parity suffix,
and the 278 EVTX-ATTACK-SAMPLES files (GPL-3.0, so outside the repo) plus two exports from this
PC are in the baseline - 279 names, 127,519 rows, 0 flagged at W2, before any Windows rule. That
folder is gone; since 2026-10-29 the samples are re-cloned at `D:/logtest/internet/evtx-attack-samples`
beside OTRF's host datasets (`otrf/`, zips - no parity suffix), and 5 of them flag now, as the Windows
rules intend (gotcha #78). The clone's stray `.log` / `.txt` / `.json` files
came in with them. W3 added `splunk-text/` (attack_data's account_lockout, 9,245 rows, R2000 24 /
R2006 177 / R2008 3, and 54 files of the lab's Security events rendered in Splunk's layout by
`tests/make_splunk_text.ps1`) and, in `tests/samples`, `windows-security.log` 0 -> 4 rows plus
`windows-security-text-spray.log` (162 rows, R2000 20 / R2009 20 - since 2026-10-26 WIN-BRUTE-2
40, and `windows-security-xml-spray.log` 50 -> WIN-BRUTE-2 100: each attempt is a 4625 + a 4776,
both flagged now, gotcha #65; the lab's Windows entries were not re-run - the folder is gone;
`otrf/rdp_interactive_taskmanager_lsass_dump.json` 0 -> WIN-LAT-3 1, gotcha #66, then WIN-LAT-1 0 -> 8 -
the RDP reconnect, gotcha #68).
W4 added `winlogbeat/` (Elastic's 105 test `.evtx` and the 113 JSON files Winlogbeat wrote from
them) and `nxlog/` (7 OTRF datasets, 2 of them flat JSON kept as no_reader) - 225 entries, 0
flagged - and `tests/samples/otrf/` (283 NXLog records, 0 flagged).

**Real-world benchmark.** A Check Point export was analysed alongside the
human SOC report written from the same data ("Firewall Port Scanning &
Implied Rule Bypass", Jun 2026). The source file is **not** under
`d:\forensic system\Logtest` and searching there for it (by name, or by
grepping for `171.6.30.201`) finds nothing - it is at
`D:/logtest/Logs_Jun_24__2026_11_09_44_102_AM_Logs_Table.csv` (since the
store reset of 2026-10-14 the only copy; it used to be in the store's
`raw/` too). The benchmark is reproducible; don't conclude it is lost.

Every figure in that report reproduced
exactly: 45,209 rows, 905 distinct services, 22,617 hits on the top service,
one source IP (171.6.30.201), 42,071 drops + 135 IPS prevents + 17 rejects,
2,978 accepted, and the accepted breakdown (https 1,022 / FW1_ica_services
1,005 / http 910). `R2004` independently flagged exactly those 2,978 rows —
rediscovering the report's central finding (Check Point's Implied Rule
overriding an explicit drop) from a log-source-neutral rule that knows nothing
about Check Point.

What the tool could not produce, and a human analyst did: the OSINT pivot
(the source is a compromised MikroTik RouterOS v6.45.3 on residential 3BB
broadband, i.e. a botnet node), Check Point's own mechanism behind the bypass, and
the reading that Check Point's "Key Install" action is an IKE Phase 1
handshake rather than a successful compromise. The system quantifies and
localises; interpretation still needs an analyst.


## Scale notes

Verified on real customer data: 36 Palo Alto CSVs, 424,948 rows, 123,861
findings — all 36 ingested in **~7 seconds** total (60MB of DuckDB vs 289MB
of source files). The largest single file (45MB / 65,534 rows) takes ~1s.
Upload returns in ~0.25s regardless of file size.

For reference, the same workload took 3.5 minutes per large file before the
DuckDB bulk-load fix, and ~38s total while decode was still Python-per-row.

Any change to ingest or rules should be checked for **parity**, and the
baseline to check against is `tests/baseline.json`, not this file - per-file
`rows / flagged / per-rule` counts, **676 entries** since 2026-11-02 (re-taken on the dev
container for the product rules - gotcha #63; the Elastic PAN-OS samples added; the user's
WinEvents.log, 4 flagged - gotcha #76; this PC's own six exports, `D:/logtest/this-pc`, and its
Security log since 2026-11-02 - 31,578 rows, WIN-BRUTE-1 12 / WIN-AUTH-1 36 on the owner's own
mistyped passwords, no SigmaHQ suggestion (specs/sigma_windows.md); and a
`sigma` section on 217 Windows entries - SigmaHQ's commit, flagged, rules and marks, kept apart so
`flagged` / `rules` stay ours, gotcha #79; story 6d, 2026-11-02, moved five `sigma` sections only -
4688 without Sysmon read by SigmaHQ's process creation rules: PurpleSharp's own 4688, attack_data's
comsvcs lsass dump, and three EVTX-ATTACK-SAMPLES - RDP tunnel, ATSVC tasklist, MalSecLogon's lsass
clone - gotcha #81), asserted by
`tests/check_parity.py`. Run it against the dev container (`--url http://127.0.0.1:8092`) with
the AI review off there (gotcha #64) - with it on, a hundred uploads take hours. A silent drop to 0 findings
is exactly the failure mode gotcha #2 describes, and a *plausible* wrong
finding is gotcha #22.

The four anchors still worth knowing by heart, as of 2026-09-15:
`log_13_.csv` 65534/11324 · `src10-8-3-215.csv` 25579/**18888** ·
`log_22_.csv` 20530/14832 · `auth.log` 776/329. Two of those moved from the
numbers recorded before that date and both moves are deliberate:
`src10-8-3-215.csv` 25579 → 18888 from the R2002/R2003 deny restriction
(gotcha #23), `log_22_.csv` 14514 → 14838 from `R3004` (+324), the
threat-intel rule of gotcha #17, which postdates the original figure -
and since the feed refresh of 2026-10-14 it is 14832 (R3004 318).

The corpus behind the baseline: **98 cases / 988,818 rows** from
`d:\forensic system\Logtest`, plus the Check Point export (in `raw/`, see
*Real-world benchmark* above) and the two `gen_usecase` files. `Logtest` holds 108
log-shaped files; the other 10 are 0-byte and the API rejects them with 400,
and 6 more are not logs at all (email headers, a placeholder, and two
artefacts the ransomware itself dropped) which ingest as 0 findings. About a
third of the corpus is duplicated content: `Data log Firewall paloalto/` (36
files) and `Virus Dec28-2025/` (33) overlap, several byte-identical, and
`log(30).csv` exists in two different versions under one name - so
**dedupe before quoting a corpus total**, and expect 98 cases from 92 usable
files. As of 2026-09-28 those folders sit under
`Logtest/2026-01/2026 SUMMITGROUP info Virus/` (with `log esxi 131/log/`
for `auth.log`), and the Azure sign-in export is
`Logtest/2026-02/KM23 ITSupport_InteractiveSignIns_2026-06-04_2026-06-11.csv`.

**Without Docker** the pipeline still runs on the host: `pip install duckdb`,
set `DATA_DIR` to a scratch folder, then `storage.create_company(...)` once
(a case needs a customer - gotcha #40), `storage.create_case(..., company_id=)` +
`pipeline.process_case(case_id, Path(file), kind)` per file. That
reproduces the baseline anchors exactly except the intel rules
(`R3003`-`R3006`), because `DATA_DIR/intel/` is empty - so `log_22_.csv`
gives 14514, not 14832. It is how gotcha #24 was measured while the Docker
daemon was down.

Zero-finding files are expected for ESXi system logs (not auth logs) and for
Palo Alto exports whose every row is `allow`; check with the gotcha #7 query
before assuming a mapping bug. The auth-on-CSV work of gotcha #11 was
validated this way (92 of 93 files byte-identical, the 93rd being the Azure
sign-in export going 0 → 79 findings), and it is what caught the Exchange
false positive.

**Timing claims need more than one run** (gotcha #18). Repeat runs of the
unchanged corpus took 52s, 60s, 67s and 74s - that spread is host I/O for a
hundred sequential uploads, not the pipeline. Re-processing all 211 cases
already in the store, which skips upload entirely, takes **53s**.

**Validating costs store space.** Since 2026-10-22 an admin or a manager can delete a case
(`DELETE /api/cases/{id}`, specs/case_delete.md); duplicates are still pruned with the tool below.
`check_parity.py` uploads the whole corpus on every run and a re-process
replaces nothing, so a handful of validation runs took one store from ~99 to
**619 cases** - 547 of them byte-identical re-uploads of 71 files, 4.8 GB on
disk and a dashboard nobody can read. `tools/prune_cases.py` is the bulk cleanup, dry-run by
default:

```bash
docker exec forensic-analyzer-forensic-analyzer-1 python tools/prune_cases.py
docker exec forensic-analyzer-forensic-analyzer-1 python tools/prune_cases.py --apply --keep-reviewed
```

It groups cases by **md5 of the preserved raw file**, not by filename - the
corpus has two different exports both called `log_30_.csv` - and keeps one
per group, preferring a case with analyst decisions, then one with a cached
analysis, then the newest. **That order matters and was learned the hard
way**: keeping merely the newest meant keeping a fresh validation duplicate
and deleting the older case that held the AI analysis, which destroyed 10
cached analyses (each a Groq call under a ~1/minute budget). A duplicate has
identical content by definition, so the copy worth keeping is the one with
work attached. Always run it without `--apply` first, and pass
`--keep-reviewed` unless you mean to delete audit logs - a case's
`review/{case_id}.jsonl` goes with it.

Remaining known ceiling: `.log`/JSON still decode in Python (~15k rows/sec).
Only worth moving to SQL `regexp_extract` if large syslog files show up;
CSV (the bulk of real data) already bypasses Python entirely. The 10 GB
upload requirement makes this real: measured on the host, CSV ran at ~77 MB/s
(45 MB in 0.59s, so ~2-3 min for 10 GB) and the Python path at ~21 MB/s on a
28 MB file (~8 min or more for 10 GB). Neither was measured on a GB-sized
file.

~~Known, not investigated: the ESXi `auth.log` has no year in its timestamps~~ -
**wrong, corrected 2026-10-14 (gotcha #42):** every line carries a full ISO
8601 UTC timestamp, and the 2014-07-02 minimum is real - 138 monthly
`vpxuser` password rotations by vCenter reach back to the host's install.
