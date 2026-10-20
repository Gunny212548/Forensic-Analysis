# Gotcha #46

**46. A PAN-OS export saved as "Unicode Text" was read as garbage, and
nothing said so (2026-10-14, IAI-30).** `log(8)-01.txt` in the corpus is
the same PAN-OS traffic log as `log(8).csv`, saved by Excel as UTF-16
(BOM) and tab-separated. Named `.txt`, it was a line log read as UTF-8:
37,555 rows (each NUL-split) and 0 findings, where its twin gives 18,776
rows and R3000 x14,434 - gotcha #7's silent failure again.
- `parsers.detect_encoding` reads the BOM; `open_text` and the SQL fast
  path (`read_csv(..., encoding='utf-16')`, DuckDB 1.5.6) both use it.
- `pipeline._is_profiled_table`: a `.log` / `.txt` whose first line is the
  header of a documented profile is read as that table. Only a documented
  header counts - general format detection stays IAI-26.
- The case says both (`mapping.encoding`, `mapping.read_as`).
Now the two files are identical: 18,776 / 14,434, same timestamps, every
field 18,776; plain / .gz / .zip identical. Baseline: only `log_8_-01.txt`
changed (37,555 / 0 -> 18,776 / 14,434); everything else in the corpus,
Check Point, gen_usecase and tests/samples equal. All 90,923 sampled
PAN-OS rows in the corpus are TRAFFIC (subtypes end / drop) - no THREAT or
URL export has been seen.

Observed once while testing, not fixed: a parity poll got a 404 for a case
it had just uploaded; a rerun passed. Likely the manifest's
write-then-rename on a Windows bind mount (test containers only - the
production volume is a native Docker volume). If it is ever seen on the
real store, `load_manifest` needs to retry on a known owner.
