# Gotcha #21

**21. Every timestamp is normalised to GMT+7, and both ingest paths used to
get this wrong in opposite directions.**
`config.EVENT_TZ_*` is the single policy: a timestamp that states an offset
(`Z`, `+00:00`, `-03:00`) is **converted** into GMT+7; one that states none is
**taken to already be** GMT+7. So `raw_events.ts` is always GMT+7 wall-clock
and two rows from two log sources are directly comparable, which is the whole
point - the deliverable is a timeline. `ts_raw` still keeps the source text
verbatim.

What it replaced, on the same file:
- `pipeline._ingest_csv_sql` cast to `TIMESTAMP`, which silently converted
  every offset-bearing row **to UTC**: a Palo Alto `+07:00` export stored
  13:13 as 06:13.
- `decode.parse_ts` dropped `tzinfo` **without converting**, keeping the UTC
  wall clock: an Azure `03:12:00Z` stayed 03:12 instead of becoming 10:12.

So the SQL path and the Python path disagreed by seven hours on the same
input, and `db.top_distinct_findings()` then fed the model `ts_raw` (local)
while the events table rendered `ts` (UTC) - the narrative and the evidence
table quoted different times for the same event.

- SQL does it with `try_cast(x AS TIMESTAMPTZ) AT TIME ZONE 'Asia/Bangkok'`
  (ICU is already in the image; verified before writing it). `db.connect()`
  sets `SET TimeZone` on **every** connection so a zone-less string means the
  same thing wherever it is cast. The `try_strptime` fallbacks carry no offset
  at all, so what they return is already GMT+7 and needs no conversion.
- Python uses a fixed `timezone(timedelta(hours=7))` rather than
  `zoneinfo`, so the image needs no tzdata. Asia/Bangkok has been +07:00 with
  no DST since 1920, so the two spellings cannot disagree.
- `db._fmt_ts()` stamps `+07:00` onto every rendered time and the prompt says
  so in one line, so neither the analyst nor the model has to infer a zone.
- `ts_first`/`ts_last` now come from `min(ts)`/`max(ts)`. They used to be
  `min/max(ts_raw)`, which compares the **source text as strings** - it only
  happens to order correctly for ISO input, so a Check Point
  (`Jun 23, 2026...`) or Palo Alto (`04/06/2026...`) case reported a range
  that was not its earliest and latest event.

Verified 2026-09-15: six spellings of one instant (`Z`, `+07:00`, naive ISO,
`07/06/2026`, `Jun 7, 2026 10:12:00 AM`, `-03:00`) all produce
`2026-06-07 10:12:00` through both paths. Across 211 re-processed cases the
row count did not move by one (2,278,792 before and after) and 557 sampled
rows whose source states `+07:00` all match their source wall clock.

**A re-process is required after any change here**, and the old cases will
not tell you they are stale: they hold UTC and nothing flags it.
