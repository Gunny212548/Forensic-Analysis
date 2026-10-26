# Gotcha #69

**69. A finding is keyed on what its rule decided on, not on each row - and the AI needs the account's history**

`specs/finding_entities.md` (2026-10-26, Q93-Q97 as recommended), after the synthetic Windows quarter
was uploaded to 8091 and checked.

**One behaviour was hundreds of suggestions.** The review unit is `rid|srcip|username` (gotcha #19),
read from each flagged row. A rule that decides on a source or an account across many rows made one
suggestion per distinct row value: the quarter was 517 suggestions - WIN-BRUTE-2 262 (one per
guessed name), WIN-BRUTE-4 152 (one per rotating address), WIN-BRUTE-3 33 - and the AI, capped at
80 (`triage.MAX_SUGGESTIONS`), reviewed 80. Rows also split one finding: a 4776 and a 4688 have no
address, and Sysmon writes `MEKONG\adm.backup` where Security writes `adm.backup` - W7's one RDP
session was 3 suggestions, 2 with no source.

**Fix: `findings.entity_src` / `entity_user`.** A rule in `RULE_ENTITY` (the module's `ENTITY`)
writes them after `mitre` - `''` for "none on that side"; both NULL means the row keys it as before.
`apply_rules` rewrites every other rule's `INSERT INTO findings` to name its five columns, so no
generic, Palo Alto or Check Point key moved (parity: samples 11, `D:/logtest` 59, `Logtest` 67 -
all exact). Every reader that builds or matches a key goes through `db.entity_sql(con)`; a case DB
from before the columns gets the row's values. Inserting into `findings` positionally with five
values now fails - name the columns (check_authz / check_triage did). Graph edges and the severity
patterns stay row-based: they describe what happened, not who is reviewed.

Quarter: **517 -> 26 suggestions** (24 without the test feed): WIN-BRUTE-2 2 (W1 and W11 are one
device, one suggestion - Q96), WIN-BRUTE-4 4 (an account each), WIN-BRUTE-3 1, W7's session 1 with
its source. A Windows case keeps its old keys until re-processed; decisions recorded on the old keys
do not follow (the keys are different findings now).

**IPv4-mapped addresses.** A DC writes `::ffff:10.20.50.23` (RFC 4291 §2.5.5.2); the timeline column
now holds `10.20.50.23` (17,322 rows of the quarter), `win_events` keeps Windows' text. The AI had
called the guest device "an external IP". `triage._side` also stops calling a workstation name
"external": it says "a host name, not an address".

**The account's history is a fact.** "Other findings of account X, any source, earliest first", with
days before / after the suggestion. Re-run on the quarter (qwen3.5:9b, 24 of 24 reviewed), the attack
suggestions the AI advised to reject went from **8 of 76** (W6 x3, W7 x5) to **2 of 22**:
- W6's guessing and sign-in: accept (was reject - "a service with an old password").
- W7's LSASS dump: accept (was reject - "a security product"); the facts now say adm.backup was
  guessed and signed in 15 days earlier.
- **Still wrong:** W7's RDP session (uncertain, reject - "an internal host ran admin tools"), and W1's
  sprayed account signing in (WIN-AUTH-1, "likely attack" yet reject, citing the owner false positive
  its text does not claim). Measured, not fixed: the facts were there.

Check: `tests/check_windows_rules.py` (suggestions per rule, W7 one suggestion, no `::ffff:` in the
timeline, the account history in the dump's facts).
