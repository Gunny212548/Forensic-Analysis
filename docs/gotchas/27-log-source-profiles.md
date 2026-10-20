# Gotcha #27

**27. A column is read from the log source's documentation when one exists,
and a guess says it is a guess (2026-10-12).** `decode.match_column()` maps
any header by substring-matching column names, on purpose, so an unseen
export still yields something. Gotchas #2, #12 and #22 are all that guessing
going wrong. `logsources.py` now holds **profiles**: a header signature, then
each canonical field from the column the log source documents for it, the
value vocabulary that documentation lists, and the page it came from. The
manifest's `mapping` records `documented` / `heuristic` / `unrecognised`
and the UI states it on the case, with the doc links, so an analyst knows
which mappings to check.

- **Say "log source", not "vendor"** (the user's call: "vendor" misleads).
  A log source is the product that wrote the log, as in Sigma's `logsource`
  - PAN-OS traffic log, Entra ID sign-in log, OpenSSH sshd - not the company.
  Microsoft alone ships the Entra sign-in log and the Exchange message trace,
  two unrelated formats; the format is what a profile describes.
- Profiles exist only where there is **both a format document and a real
  file to test against**: PAN-OS traffic log, Microsoft Entra ID sign-in log
  (CSV, and since 2026-10-14 its Azure Monitor JSON export - gotcha #39),
  Exchange Online message trace. Line logs cite the message formats they
  match (OpenSSH `auth.c` / `kex.c` / `session.c` / `packet.c`, Linux-PAM
  `pam_unix`, Broadcom KB 321910 for ESXi, FortiOS Log Message Reference),
  plus ESXi lines read as *observed* - real file, no published format
  (gotcha #42). The Check Point SmartConsole export got its profile once
  the real file was found again (gotcha #43); until then there was none,
  because a profile no file has tested is a guess with a citation attached.
- A documented profile still falls back **per field** when an export lacks
  a column (the UI names the field). `gen_usecase`'s `nightfall-firewall.csv`
  is exactly that: it has no `Category`, so its malware marker - written into
  `Threat/Content Type` - is read by guess, flagged, and R3002 still fires.
- A line log in which no documented format matched is `unrecognised`, not
  `heuristic`: nothing was guessed, only timestamps and IPs were taken, and
  no rule can fire. That is 28 of the corpus files (ESXi `hostd.log` & co.)
  and it answers gotcha #7's "0 findings - schema mismatch or boring?" on
  the page itself.

What reading the documentation fixed - no count moved, but the values did:
- PAN-OS `category` came from `Threat/Content Type`, which PAN-OS documents
  as the log **subtype** (start/end/drop/deny). The documented `Category` is
  the URL category - what R3002's `malware|command-and-control` is for.
- Entra ID `username` came from `User`, the **display name** (an exact match
  on "user" won). Microsoft documents `Username` as the UPN, the account.
  **This changes finding keys** (`rid|srcip|username`, gotcha #19): a review
  recorded against the display name no longer attaches after re-processing.
- Entra ID `verdict` came from `Status` (a sign-in outcome read as a
  firewall verdict). The profile maps no verdict for a sign-in.

Measured: host run over 63 distinct corpus files, rows / flagged / every
per-rule count identical to `tests/baseline.json`; 33 CSVs documented
(31 PAN-OS - one with a guessed field - 1 Entra, 1 Exchange), 2 line logs
documented, 28 unrecognised.

**The Check Point benchmark was found again (2026-10-14):**
`D:/logtest/Logs_Jun_24__2026_11_09_44_102_AM_Logs_Table.csv`, md5
`1dd88109...` = the baseline entry. (On 2026-10-12 it was missing from the
store and nobody looked outside `D:/forensic system`.) The store copy no
longer exists - the store was reset - so `D:/logtest` is the copy.
