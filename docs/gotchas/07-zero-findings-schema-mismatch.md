# Gotcha #7

**7. "ready with 0 findings" on a firewall export means a schema mismatch, not a clean log.**
This is the failure mode to be most suspicious of, because nothing errors.
A real Check Point export ingested 45,209 rows and produced zero findings:
every rule needs `srcip`, and `srcip` was NULL for every row. Diagnose by
counting non-NULL canonical columns before assuming the log is boring:

```sql
SELECT count(ts), count(srcip), count(dstip), count(verdict), count(app) FROM raw_events;
```

Log sources differ in three ways that all had to be handled:
- **Address format** — Check Point writes `object-name (1.2.3.4)`, Palo Alto
  writes a bare IP. `decode.extract_ip()` / the SQL `regexp_extract` pull the
  IP out and fall back to the original text so named entities survive.
- **Column names** — `Source`/`Destination` vs `Source address`/
  `Destination address`. Both are in `_FIELD_CANDIDATES`, specific ones
  first. `_AVOID_SUBSTRINGS` stops the loose pass from grabbing
  `Source User Name` as an IP.
- **Verdict vocabulary** — `accept`/`reject`/`prevent` vs `allow`/`deny`.
  `decode.normalize_verdict()` and the SQL `CASE` fold synonyms into the
  canonical spellings so rules stay readable.
