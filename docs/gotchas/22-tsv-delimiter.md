# Gotcha #22

**22. A TSV export decodes into one garbage column, and the findings it
produces look plausible.**
`pipeline._csv_header()` reads the header with `csv.reader(fh)`, whose
delimiter is **comma, hardcoded**. Given a tab-separated Palo Alto export the
whole header comes back as one field - verified, `_csv_header()` returns
exactly 1 field for it - and `decode.match_column()` then loose-matches its
candidates *inside that one giant string*. Measured on the real file:
`ts`, `app` and `category` all resolve **to the same bogus column**, while
`srcip`, `dstip` and `verdict` resolve to `None`, because the giant string
also contains `destination`, `user` and `log action`, which the
`_AVOID_SUBSTRINGS` guards of gotchas #2/#12 correctly reject. `ts` then
parses to NULL because the value is a whole tab-joined row.

The result is worse than the silent 0-findings of gotcha #7, because it is
not silent: `R3002` fired **78 times** on one 102-row file purely because the
row text contains `used-by-malware`. The findings read like real malware hits
and are useless - no `srcip`, no `dstip`, nothing that can reach the attack
graph. The comma-separated twin of the same export (same 102 rows, different
md5) correctly yields `R3000` x78 with real `risk` values.

DuckDB is not the problem: `read_csv` sniffs the tab itself and returns all
117 columns for both files. The mapping is computed from the Python-read
header, which is wrong, so the generated SQL references a column that does not
exist, the fast path throws, and the Python fallback - `csv.DictReader`, comma
again - decodes the file into a one-key dict. Confirmed from the stored data
rather than inferred: the `raw` column of that case contains exactly one `=`
(`<whole header>=<whole row>`), which only the Python decoder produces; the
SQL path writes one `Col=value` pair per real column.

**Fixed 2026-09-15.** `parsers.sniff_delimiter()` counts `,` `\t` `;` `|` in
the header line and the result is handed to *all three* readers -
`csv.DictReader`, `pipeline._csv_header()` and `read_csv(delim=...)` - so the
header Python maps and the columns DuckDB returns cannot disagree about the
shape of the file. Counting beats `csv.Sniffer` because the answer is
explainable, and on a real 117-column export it is unambiguous (116 tabs vs 0
commas); ties and empty headers fall back to comma. The tab export now
ingests with all 102 rows carrying `ts`/`srcip`/`dstip`/`verdict`/`app`, and
`R3002` x78 became `R3000` x78 - identical to its comma-separated twin, which
is the whole point: same data, different format, same findings.

Those two lines were the *entire* whole-corpus diff for the day's work, which
is also the evidence that the `username` avoid-list, the R2007 off-by-one and
the CGNAT filter changed no counts at all.
