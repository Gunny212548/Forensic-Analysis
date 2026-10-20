# Gotcha #18

**18. Measure before optimising - twice here the bottleneck was not where it
looked.** The corpus wall-clock moved from ~18s to ~60s when IOC matching
landed, which looked like the per-case indicator load. It was not: measured
directly, `intel.fill()` costs **13ms** and *all sixteen rules together* cost
**56ms** on the largest case (65,534 rows). A Parquet copy of the feed was
built to "fix" it, saved 5ms, and was removed again. Repeat runs of the
unchanged corpus took 52s, 60s, 67s and 74s - the variance is host I/O for
93 uploads, not anything the pipeline does. Time a stage before rewriting it.
