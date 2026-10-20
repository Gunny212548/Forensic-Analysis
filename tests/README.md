# Ground-truth regression scenario

`gen_usecase.py` writes a synthetic incident ("Nightfall") whose every rule
hit is known in advance, so the rule engine can be graded exactly rather
than eyeballed. Use it after touching `decode.py`, `rules.py`, or the ingest
pipeline.

```bash
python tests/gen_usecase.py /tmp/usecase
python tests/check_parity.py /tmp/usecase     # asserts the table below, exits 1 on drift
```

`check_parity.py` compares per-file `rows / flagged / per-rule` counts against
`baseline.json` and prints every difference, so the expected counts below do
not have to be checked by eye. Point it at a corpus directory to check real
data, and pass `--update` when a change in the numbers is intended:

```bash
python tests/check_parity.py "D:/forensic system/Logtest"
python tests/check_parity.py "D:/forensic system/Logtest" --update
```

To look at one case by hand instead:

```bash
curl -s -X POST http://localhost:8091/api/upload -F "file=@/tmp/usecase/nightfall-auth.log"
curl -s -X POST http://localhost:8091/api/upload -F "file=@/tmp/usecase/nightfall-firewall.csv"
curl -s http://localhost:8091/api/cases    # compare rules_matched to the table below
```

## The planted attack

1. `10.20.30.40` port-scans `10.10.1.5` — 15 distinct ports, all denied
2. …then brute-forces SSH `root` — 8 failed passwords
3. …tries 3 invalid usernames (admin, oracle, backup)
4. …succeeds: `Accepted password for root`
5. service account `svc_backup` password changed minutes later
6. `10.10.1.5` then talks out to `203.0.113.77` over high-risk SSL:
   3 ordinary sessions, 2 transfers >50MB, 1 flagged as malware

Benign noise is mixed in on purpose: `10.10.1.9` browsing/logging in
normally, plus 5 low-risk allowed firewall rows. **These must produce zero
findings** — they're the false-positive check.

## Expected results

`nightfall-auth.log` — 19 rows, 19 flagged:

| rule | meaning | count |
|---|---|---|
| R1000 | SSH auth failed | 8 |
| R2000 | repeated brute-force (same source) | 8 |
| R1002 | invalid user | 3 |
| R1001 | login success | 3 |
| R1003 | connection opened | 4 |
| R1004 | password changed | 1 |

`nightfall-firewall.csv` — 26 rows, **21** flagged (5 benign rows unflagged):

| rule | meaning | count |
|---|---|---|
| R2002 | port scan (>=10 distinct dst ports) | 15 |
| R2001 | repeated blocked connections | 15 |
| R3000 | high-risk app allowed | 6 |
| R3001 | large outbound transfer | 2 |
| R3002 | malware-flagged category | 1 |

A row can match several rules, so per-rule counts sum to more than the
flagged-row count. `flagged_count` is DISTINCT rows.

The firewall CSV carries PAN-OS's documented `Category` (URL category) column
since IAI-92, so R3002's malware match reads it rather than a guessed column.

The two JSON twins (IAI-35) carry the same 26 firewall rows:

| file | layout | identified / read by | rows | flagged |
|---|---|---|---|---|
| `nightfall-firewall.json` | pretty-printed array, PAN-OS column names | documented PAN-OS profile (same as the CSV) | 26 | 21 |
| `nightfall-firewall-nested.jsonl.gz` | gzipped JSON-lines, nested generic keys | **unrecognised** - no documented profile, so kept as evidence and not analysed | **0** | **0** |

The JSON array must give **exactly the firewall table above**. The nested file
was read by guessing its keys until IAI-92 (28 rows, 21 flagged); since then
nothing is guessed, and its result is the test that an undocumented file is
identified as unrecognised and produces nothing.

## Expected severity (CLAUDE.md gotcha #26)

Not asserted by `check_parity.py` - check the case's `severity` and
`escalations` on its manifest:

| file | case level | escalation |
|---|---|---|
| `nightfall-auth.log` | high | `credential-compromise` (17 findings): `10.20.30.40` brute-forced `root`, then logged in from the same address |
| `nightfall-firewall.csv` | critical | `compromised-host` (3): `10.10.1.5` has both the malware-flagged and the two >50MB transfers |
| both JSON twins | critical | the same as the CSV |

`10.10.1.9`'s ordinary logins stay `informational`. If either file stops
escalating, or the benign host starts, the attack-path patterns in
`severity.py` have drifted.

## What the AI layer should say

Not exact-matchable, but the analysis should reconstruct the planted chain:
Reconnaissance (T1046) → Credential Access (T1110.001) → Initial Access →
Persistence (T1098) → Command and Control (T1071) → Exfiltration (T1041),
link `10.20.30.40 → root` and `10.10.1.5 → 203.0.113.77`, and describe
`10.10.1.9` as legitimate rather than folding it into the attack.

Known soft spots seen in testing: the model calls RFC1918 addresses
"external", and occasionally tags a successful login T1110.001 instead of
T1078. Treat AI stage labels as a lead, not a verdict — the rule hits above
are the part that must be exact.
