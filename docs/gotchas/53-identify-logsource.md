# Gotcha #53

**53. Every file is identified before a row is read, and nothing is guessed
(2026-10-20, IAI-92; branch `IAI-92-identify-logsource`, not merged).** The user's rule:
the system must not guess what a log is - every file has its product's format.

- **`app/services/identify.py`** answers in the Sigma logsource taxonomy v2.1.0 (read):
  category / product / service where it defines them; where it does not - it has no
  firewall vendor, no ESXi, no CrowdStrike (verified) - `custom` names the product and the
  case says it is not a Sigma value. `logsources.LOGSOURCE` holds the mapping per profile.
  - a table (CSV, or a `.log` / `.txt` whose first line is a documented header) by its
    header against `logsources.PROFILES`;
  - JSON by the keys of its first 200 records;
  - a line log by running the documented line decoders over its first 2,000 lines and
    counting which format matched (the same code that later reads it; any ESXi line makes
    the file ESXi, because ESXi writes OpenSSH's lines too);
  - formats with no reader yet by their vendor's marker: `%ASA-<sev>-<id>:`,
    `%FTD-...`, the Windows event XML channel, Splunk's `LogName=Security` rendering,
    FTD eStreamer JSON (`EventType` + `DeviceUUID`); CrowdStrike by `event_simpleName` +
    `aid` + `cid` - *observed* only, its dictionary needs a Falcon login.
- **The name of a file proves nothing.** The first version missed two files: JSON-lines
  saved as `.log` (CrowdStrike, eStreamer) - identify now looks at the first character -
  and an Azure Monitor export that starts with a blank line.
- **Statuses** `supported` / `no_reader` / `unrecognised`. Only `supported` is read; the
  others return 0 rows with the identification on the mapping, the file is kept as
  evidence (digest, custody), and the Ingest step says which (the user's Q8).
- **Guessing removed.** `decode.match_column`, `_find_field`, `_FIELD_CANDIDATES`,
  `_AVOID_SUBSTRINGS` and `logsources.resolve_keys` are gone; `resolve(header)` maps only
  through the documented profile, a documented column an export lacks stays empty and is
  listed as `missing_fields`. `pipeline._is_profiled_table` is replaced by identify's
  `read_as`.
- **gen_usecase** now writes PAN-OS's documented `Category` column (R3002 reads it). Its
  nested JSON twin has no profile and is the unrecognised test (28 rows / 21 flagged -> 0).
- **Measured, old code against new, both with the production intel feeds copied out of the
  container**: every finding count unchanged except that twin; 26 unrecognised files (ESXi
  system logs, text notes) went from rows to 0 rows, none had a finding. Baseline updated
  (79 names). Without the feeds R3004 drifts on 12 files in both runs - the host-run caveat
  of the scale notes, not this change.
- **Tests** - `tests/check_identify.py [--corpus]`: 22/22 - committed samples (Splunk
  attack_data, Apache-2.0, in `tests/samples/attack-data/` with their original SHA-256;
  FTD and Sysmon trimmed to their first lines), gen_usecase, 6 negatives, and with
  `--corpus` the real customer files at the paths the scale notes name.
- **Trap:** `sed -i` on Git Bash rewrote `pipeline.py` from CRLF to LF (a 1,255-line diff).
  Check `git diff --stat` after any shell edit; restore with a binary-mode rewrite.
