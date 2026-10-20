# Gotcha #25

**25. An upload is fully received and spooled to disk before the handler runs,
so size and disk checks in `upload_log()` come too late.** Starlette parses the
multipart form - writing the whole file into a `SpooledTemporaryFile` in `/tmp`
(1MB in memory, the rest on disk) - before FastAPI calls the handler. The
"stream to disk in 1MB chunks" in `upload_log()` is true for memory but not for
disk or time: a 10 GB file has already crossed the network and landed in `/tmp`
when the handler's size check first sees it, and it sits on disk twice until
the spool is freed. Verified in the image (starlette 0.38.6,
`formparsers.spool_max_size = 1MB`).

So FR-2.2's refusals (`upload.capacity_problem()`: > `MAX_UPLOAD_BYTES` = 10
GB, or free space on `DATA_DIR` < `UPLOAD_DISK_FACTOR` = 2.5x the size) run
from **Content-Length in the middleware in `main.py`, before the body is
read**. Measured: an 11 GB upload declared in headers with no body sent gets
413 in 0.00s. The upload page also calls `GET /api/upload/check?size=` first,
because a browser that is still sending may report a network error instead of
the early 413/507. The 2.5x is not padding: spool copy + raw copy + DuckDB.
The handler's own byte count stays authoritative for the limit, because that
is the size *after* decompression. IAI-25 (.gz/.zip) must keep counting
decompressed bytes there, since Content-Length only knows the compressed size.
