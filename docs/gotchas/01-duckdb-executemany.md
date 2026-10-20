# Gotcha #1

**1. DuckDB `executemany()` is catastrophically slow — never bulk-insert with it.**
Benchmarked here at ~300 rows/sec (20k rows = 65 seconds); a 65k-row file
took 3.5 minutes end-to-end. It's a per-row prepared-statement call. The
pipeline instead writes decoded rows to a staging CSV and lets DuckDB's CSV
reader ingest it in one statement — same file now processes in ~6 seconds.
(pandas/pyarrow would also work but add tens of MB of dependency for no
gain here.)
