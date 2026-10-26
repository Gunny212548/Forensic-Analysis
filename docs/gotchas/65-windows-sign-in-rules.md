# Gotcha #65

**65. Windows sign-in rules: one attempt, however many events record it**

Story 5a of `specs/windows_rules.md` (approved 2026-10-26, Q81-Q86): `app/services/rules_windows.py`,
WIN-BRUTE-1 (B1 guessing), WIN-BRUTE-2 (B2 spray, TRW over accounts), WIN-BRUTE-3 (B3 one account
from many sources), WIN-AUTH-1 (B4 success after flagged failures). They supersede R2000 / R2005 /
R2006 / R2008 / R2009 on Windows rows (`RULE_SUPERSEDED`, gotcha #63).

**The same failed sign-in is logged twice, and the two records disagree on the source.** On the
real PurpleSharp capture (attack_data, `tests/samples/attack-data/windows-security-xml-spray.log`)
the DC logged each of the 50 attempts as a 4625 (`IpAddress` 10.0.1.15) and a 4776 (no address,
only `Workstation` WIN-HOST-MVELAZ). A mistyped password at a workstation is a 4625 on the
workstation (`IpAddress` 127.0.0.1) and a 4771 on the DC (`::ffff:` + the workstation's address).
Counted per event, every attempt is two, and keyed on the source the pair lands on two sources.
So the rules read `win_attempts` (built in each BRUTE rule's PREPARE, from `win_events.data`): a
4771 / 4776 / 4768 within one second of a 4625 / 4624 of the same account and outcome joins that
attempt; the address is taken from whichever record has one (`::ffff:` read as IPv4), else the
4776's workstation name, else the host's console. Two events with the *same* id in the same second
stay two attempts. All rows of a flagged attempt are flagged - the spray sample went from 50
flagged rows (R2000 / R2009 on the 4625s) to 100 (WIN-BRUTE-2 on 4625 + 4776): a re-base, not a
new finding. The text capture went 20 -> 40 the same way.

**Q41 reversed (Q84).** 4771 (0x18 bad password, 0x6 unknown user) and 4776 (0xC000006A /
0xC0000064) are counted - without them a Kerberos spray against the DC is invisible: on the
synthetic quarter W1 (71 accounts, all 4771) was missed by every generic rule.

**Codes as Windows writes them.** 4625 carries the reason in `SubStatus` (0xc000006a) with Status
0xc000006d; both are compared lower-case. The 4625 page has no code table any more (an NTSTATUS
link); the codes come from its monitoring section and the 4776 page (SOURCES.md, read 2026-10-26).

**What the synthetic quarter measured** (`tests/gen_windows_domain.py`, seed 20260701: 88 files,
98,403 events, ground truth): the generic rules found W2 / W3 / W6 and flagged 203 plain rows
(R2000 / R2009: every workstation's console mistype has source 127.0.0.1, one "source" for all)
and 2,876 plain rows (R2008); the WIN rules find W1, W2, W6, W9 and W7's reuse of the guessed
account, with **0 plain or look-alike rows**. Lines on that evidence: B1 137 episodes, p99 3 ->
above 6; B3 42 accounts, p99 1 -> above 2; TRW 2 sprayers, 0 benign, 464 pending (a source tries
few accounts - the measured benign success ratio is null and the case says so). The stale
`svc_backup` password (4 failures an hour for two days, label btp) stays under B1's line.

Known, not fixed: a failed **4768** (a TGT request refused) is not counted - its Microsoft page
has not been read for its failure codes, and which failures a DC writes as 4768 rather than 4771
(an unknown name?) is unconfirmed; the generator writes unknown names as 4771 0x6. W3
low-and-slow guessing (3 a day from rotating addresses) is missed - B5 has
no rule (D16's CUSUM); `D:\logtest\windows` is gone, so the 278 EVTX-ATTACK-SAMPLES and the
account_lockout capture were not re-run (their baseline entries are as of 2026-10-22).

Check: `tests/check_windows_rules.py <scratch>` (attempt merging on small files, the quarter
against its ground truth, the real spray).
