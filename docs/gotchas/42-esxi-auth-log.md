# Gotcha #42

**42. ESXi's auth.log is now read line for line - and its most important
lines were the ones not read (2026-10-14, IAI-29).** On the SUMMIT
ransomware host's `auth.log` (776 lines) the decoder recognised 383; the
rest kept a timestamp and maybe an IP, and no rule could ever see them.
Among them, the only record of the attack itself: `User 'root' running
command '/tmp/esxi_encryptor'`, `'chmod 777 /tmp/esxi_encryptor'`,
`'rm -rf /.ash_history'`, `vim-cmd vmsvc/getallvms` loops. Now all 776 are
read, each by a cited profile:

| lines | action | profile (source) |
|---|---|---|
| `Session opened/closed for 'root' on /dev/char/pty/tN` (100) | `shell_session_open` / `_close` | `vmware-esxi` (Broadcom KB 321910) |
| `login[]: root login on 'char/tty/1'` | `console_login` | `vmware-esxi` |
| `pam_unix(...:session): session opened/closed for user root` (71) | `session_open` / `_close` | `linux-pam` (`pam_unix_sess.c`) |
| `Did not receive identification string` / `Bad protocol version identification` (59) | `ssh_probe` | `openssh-sshd` (`kex.c`) |
| `subsystem request for sftp by user root` (1) | `sftp_session` | `openssh-sshd` (`session.c`) |
| `Connection closed by`, `Timeout, client not responding` | none | `openssh-sshd` (`packet.c`) |
| `User 'root' running command '...'` (33) | `command_exec` | `vmware-esxi-observed` |
| `pam_per_user: create_subrequest_handle()` (166) | none | `vmware-esxi-observed` |

- **Profiles are per pattern set, not per program** (`decode._PROGRAM_PATTERNS`):
  sshd writes pam_unix's and ESXi's messages under its own name, so a
  line now cites the source that defines *it*.
- **"observed" is its own honesty level.** VMware/Broadcom publish no format
  for `running command` or `pam_per_user` (searched: KB 321910 shows the
  session lines only; the Google/Mandiant UNC3944 write-up describes
  auth.log without the format). Gotcha #27 says a profile needs a document
  *and* a real file; these have only the file, and the command text is too
  important to leave unread. So `vmware-esxi-observed` has no docs and
  `observed: true`; the case page says "format observed in real logs, not
  documented by the vendor", and a file read *only* that way is
  `method: observed`, never `documented`.
- **No rule moved**: no rule keys on the new actions. `auth.log` stays
  776 / 329 with every per-rule count equal; plain, `.gz` and inside a
  `.zip` are identical (rows, flagged, rules, actions, mapping); corpus
  parity unchanged. The new actions are input for rules not yet written.
- **The year was never wrong** - see *Scale notes*: the file has full ISO
  timestamps, and the 2014 rows are `vpxuser` rotations (12 a year, every
  30 days, vCenter's default). Which is also a finding for the rules:
  **R1004 fires 138 times on that benign rotation** - follow-up, not parser.
