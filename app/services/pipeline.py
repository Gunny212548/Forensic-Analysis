"""Ingest pipeline: raw file on disk -> canonical rows in DuckDB -> findings.

Runs off the request path (see routers/upload.py) so a large upload never
blocks or times out an HTTP request.

Rows stream through decode and are written to a temporary staging CSV, which
DuckDB then bulk-loads in one statement. That detour exists for a reason:
DuckDB's executemany() is a per-row prepared-statement call and benchmarks at
roughly 300 rows/sec here (20k rows took 65s), while its CSV reader ingests
the same data in well under a second. Peak memory stays flat either way.
"""

import csv
import logging
import os
import tempfile
import threading
import time
import traceback
from pathlib import Path

from .. import config
from . import archive, db, decode, intel, parsers, rules, storage

log = logging.getLogger(__name__)

# Column order must match db.RAW_COLUMNS / the raw_events table.
_STAGE_COLUMNS = {
    "row_id": "BIGINT", "ts": "TIMESTAMP", "ts_raw": "VARCHAR",
    "srcip": "VARCHAR", "dstip": "VARCHAR", "dstport": "VARCHAR",
    "username": "VARCHAR", "program": "VARCHAR", "hostname": "VARCHAR",
    "action": "VARCHAR", "verdict": "VARCHAR", "app": "VARCHAR",
    "risk": "INTEGER", "bytes_sent": "BIGINT", "category": "VARCHAR",
    "raw": "VARCHAR",
}


# ------------------------------------------------------------------ progress
# FR-2.5: the processing stage reports its own percentage, separately from
# the upload's (which the browser measures). Ingest is by far the longest
# part, so it gets most of the bar; intel and rules are short and exact.
INGEST_END = 90
INTEL_END = 92

# The CSV fast path is ONE DuckDB statement and DuckDB 1.1.3 has no
# query_progress(), so its share is estimated from elapsed time against the
# measured CSV rate (~77 MB/s on the host, CLAUDE.md scale notes) - set a
# little lower so the estimate trails reality - and held at 95% of the file
# until the statement returns. The manifest marks it `estimated` so the UI
# can say so; every other stage is measured.
_CSV_BYTES_PER_S = 60 * 1024 * 1024


class Progress:
    """Writes {stage, pct, estimated} onto the case manifest, at most about
    once a second and never backwards. Thread-safe: the CSV estimator writes
    from its own thread."""

    def __init__(self, case_id: str):
        self.case_id = case_id
        self._lock = threading.Lock()
        self._last = 0.0
        self._pct = -1

    def set(self, stage: str, pct: float, estimated: bool = False, force: bool = False) -> None:
        pct = int(max(0, min(100, pct)))
        with self._lock:
            now = time.monotonic()
            if not force and (pct <= self._pct or now - self._last < 1.0):
                return
            self._last, self._pct = now, max(pct, self._pct)
            storage.update_case(self.case_id, progress={
                "stage": stage, "pct": self._pct, "estimated": estimated})

    def ingest(self, fraction: float, estimated: bool = False) -> None:
        self.set("ingest", fraction * INGEST_END, estimated)


def _estimate_while(report, expected_bytes: int) -> tuple[threading.Event, threading.Thread]:
    """Feed report() an elapsed-time estimate until the returned event is set."""
    expected_s = max(0.5, expected_bytes / _CSV_BYTES_PER_S)
    stop = threading.Event()

    def run():
        t0 = time.monotonic()
        while not stop.wait(1.0):
            report(min(0.95, (time.monotonic() - t0) / expected_s), True)

    th = threading.Thread(target=run, daemon=True)
    th.start()
    return stop, th


def _noop(*_args, **_kw) -> None:
    pass


def _stage_row(row_id: int, e: dict) -> list:
    ts = e["ts"]
    return [
        row_id,
        ts.isoformat(sep=" ") if ts else "",
        e["ts_raw"] or "", e["srcip"] or "", e["dstip"] or "", e["dstport"] or "",
        e["username"] or "", e["program"] or "", e["hostname"] or "",
        e["action"] or "", e["verdict"] or "", e["app"] or "",
        "" if e["risk"] is None else e["risk"],
        "" if e["bytes_sent"] is None else e["bytes_sent"],
        e["category"] or "", e["raw"] or "",
    ]


def _q(name: str) -> str:
    """Quote a SQL identifier."""
    return '"' + name.replace('"', '""') + '"'


def _csv_header(path: Path, delimiter: str) -> list[str]:
    with parsers.open_text(path, newline="") as fh:
        try:
            return next(csv.reader(fh, delimiter=delimiter))
        except StopIteration:
            return []


def _ingest_csv_sql(con, path: Path, start: int = 0) -> int:
    """Ingest a CSV entirely inside DuckDB: it reads the file, maps source
    columns onto the canonical schema, and inserts - no row ever crosses
    into Python. Column mapping is resolved once from the header. A .csv.gz
    is read the same way - DuckDB decompresses it as it reads.

    Row ids continue from `start`, so several files can share one case
    (a zip, FR-2.3). Returns the number of rows inserted, or -1 if the header
    carried no recognisable fields (caller falls back to the Python path).
    """
    # One sniff, handed to both readers, so the header Python maps and the
    # columns DuckDB returns cannot disagree about the shape of the file
    # (gotcha #22).
    delimiter = parsers.sniff_delimiter(path)
    header = _csv_header(path, delimiter)
    if not header:
        return -1

    mapping = {
        field: decode.match_column(header, field)
        for field in ("ts", "srcip", "dstip", "dstport", "username",
                      "verdict", "app", "risk", "bytes_sent", "category",
                      "auth_status")
    }
    if not any(mapping.values()):
        return -1

    def col(field: str) -> str:
        src = mapping.get(field)
        return _q(src) if src else "NULL"

    ts_col = col("ts")
    # ISO/standard first, then Palo Alto's DD/MM/YYYY "Receive Time" shapes,
    # then Check Point's "Jun 23, 2026 10:03:02 PM".
    #
    # The first branch does the zone normalisation the whole tool depends on
    # (config.EVENT_TZ_*): casting to TIMESTAMPTZ reads whatever offset the
    # source states - or, for a zone-less string, the connection's zone, which
    # db.connect() has already set to GMT+7 - and AT TIME ZONE then renders it
    # as GMT+7 wall-clock. Casting straight to TIMESTAMP instead (what this
    # used to do) silently converted every offset-bearing row to UTC, so a
    # Palo Alto "+07:00" export and an Azure "Z" export could not be read on
    # one timeline. The try_strptime fallbacks carry no offset at all, so what
    # they return is already GMT+7 by the ingest rule and needs no conversion.
    ts_expr = (
        "NULL" if ts_col == "NULL" else
        f"coalesce("
        f"try_cast({ts_col} AS TIMESTAMPTZ) AT TIME ZONE '{config.EVENT_TZ_NAME}', "
        f"try_strptime({ts_col}, '%d/%m/%Y %H:%M:%S'), "
        f"try_strptime({ts_col}, '%d/%m/%Y %H:%M'), "
        f"try_strptime({ts_col}, '%b %d, %Y %I:%M:%S %p'), "
        f"try_strptime({ts_col}, '%b %d, %Y %H:%M:%S'))"
    )

    # Check Point writes addresses as "object-name (1.2.3.4)"; Palo Alto
    # writes a bare IP. Pull the IP out when present, otherwise keep the
    # original text so named entities still appear.
    def ip_expr(field: str) -> str:
        c = col(field)
        if c == "NULL":
            return "NULL"
        return f"coalesce(nullif(regexp_extract({c}, '[0-9]{{1,3}}(\\.[0-9]{{1,3}}){{3}}'), ''), {c})"

    # Vendors spell verdicts differently (Check Point: accept/drop/reject);
    # rules are written against the canonical spellings.
    verdict_col = col("verdict")
    verdict_expr = (
        "NULL" if verdict_col == "NULL" else
        f"CASE lower(trim({verdict_col})) "
        f"WHEN 'accept' THEN 'allow' WHEN 'permit' THEN 'allow' "
        f"WHEN 'allowed' THEN 'allow' WHEN 'denied' THEN 'deny' "
        f"WHEN 'dropped' THEN 'drop' WHEN 'rejected' THEN 'reject' "
        f"ELSE lower(trim({verdict_col})) END"
    )

    # Sign-in outcome -> the semantic `action` the R1xxx/R2000 auth rules
    # match on. Without this, CSV auth exports (Azure AD sign-in logs and
    # the like) ingest cleanly and match nothing at all, because `action` was
    # only ever set by the line-log decoder. Only the auth vocabulary is
    # translated, so a firewall "Action" column of allow/deny still yields
    # NULL here and no auth rule can fire on firewall traffic.
    # An authentication event is about an account, so require one: without
    # this guard an Exchange message-trace export (columns MessageId,
    # SenderAddress, ..., Status) matched "Status" and turned 335 *failed
    # email deliveries* into 335 failed logins. Requiring a username column,
    # and a non-NULL username on the row, keeps the auth vocabulary attached
    # to something that can actually authenticate.
    auth_col = col("auth_status")
    user_col = col("username")
    action_expr = (
        "NULL" if auth_col == "NULL" or user_col == "NULL" else
        f"CASE WHEN {user_col} IS NULL OR {user_col} = '' THEN NULL "
        f"ELSE CASE lower(trim({auth_col})) "
        f"WHEN 'success' THEN 'auth_success' WHEN 'succeeded' THEN 'auth_success' "
        f"WHEN 'failure' THEN 'auth_failed' WHEN 'failed' THEN 'auth_failed' "
        f"WHEN 'fail' THEN 'auth_failed' ELSE NULL END END"
    )

    # `raw` mirrors the Python decoder: "Col=value" for the first handful of
    # non-empty columns, for analyst context only.
    parts = []
    for name in header[:14]:
        if not name:
            continue
        q = _q(name)
        label = name.replace("'", "''")
        parts.append(f"CASE WHEN {q} IS NOT NULL AND {q} <> '' THEN '{label}=' || {q} END")
    raw_expr = f"concat_ws(', ', {', '.join(parts)})" if parts else "''"

    con.execute(
        f"""
        INSERT INTO raw_events
        SELECT
            row_number() OVER () - 1 + {start}    AS row_id,
            {ts_expr}                             AS ts,
            {ts_col}                              AS ts_raw,
            {ip_expr('srcip')}                    AS srcip,
            {ip_expr('dstip')}                    AS dstip,
            {col('dstport')}                      AS dstport,
            {col('username')}                     AS username,
            NULL                                  AS program,
            NULL                                  AS hostname,
            {action_expr}                         AS action,
            {verdict_expr}                        AS verdict,
            {col('app')}                          AS app,
            try_cast({col('risk')} AS INTEGER)    AS risk,
            try_cast({col('bytes_sent')} AS BIGINT) AS bytes_sent,
            {col('category')}                     AS category,
            substr({raw_expr}, 1, 2000)           AS raw
        FROM read_csv(?, all_varchar=true, header=true, sample_size=-1,
                      delim='{delimiter}')
        """,
        [str(path)],
    )
    return con.execute("SELECT count(*) FROM raw_events WHERE row_id >= ?", [start]).fetchone()[0]


def _write_stage(path: Path, kind: str, stage_path: Path, start: int = 0,
                 progress=None) -> tuple[int, bool]:
    total = 0
    truncated = False
    with open(stage_path, "w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh)
        for row in parsers.iter_rows(path, kind, progress):
            if config.MAX_ROWS and total >= config.MAX_ROWS:
                truncated = True
                break
            writer.writerow(_stage_row(start + total, decode.decode(row, kind)))
            total += 1
    return total, truncated


def _stage_dir() -> Path:
    d = Path(config.DATA_DIR) / "tmp"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _next_row_id(con) -> int:
    return con.execute("SELECT coalesce(max(row_id) + 1, 0) FROM raw_events").fetchone()[0]


def _ingest_file(con, case_id: str, path: Path, kind: str, start: int,
                 report=_noop, expected_bytes: int | None = None) -> tuple[int, bool]:
    """Decode one file into raw_events with row ids from `start`.
    `report(fraction, estimated)` gets this file's progress (FR-2.5).
    Returns (rows added, truncated)."""
    if kind == "csv" and not config.MAX_ROWS:
        # Fast path: DuckDB reads and decodes the CSV itself.
        stop, th = _estimate_while(report, expected_bytes or path.stat().st_size)
        try:
            added = _ingest_csv_sql(con, path, start)
            if added >= 0:
                return added, False
        except Exception:  # noqa: BLE001
            log.warning("case %s: SQL CSV ingest failed for %s, falling back", case_id,
                        path.name, exc_info=True)
            # Only this file's rows - earlier members of a zip stay.
            con.execute("DELETE FROM raw_events WHERE row_id >= ?", [start])
        finally:
            stop.set()
            th.join()

    # Python path: line logs, JSON, or any CSV the fast path couldn't map.
    # Decoded rows go through a staging CSV because DuckDB's executemany()
    # is far too slow for bulk insert.
    fd, stage_name = tempfile.mkstemp(suffix=".csv", dir=str(_stage_dir()))
    os.close(fd)
    stage_path = Path(stage_name)
    try:
        # Parsing is most of the work; the bulk load that follows is quick.
        total, truncated = _write_stage(path, kind, stage_path, start,
                                        progress=lambda f: report(0.9 * f))
        report(0.9)
        if total:
            cols = ", ".join(f"'{name}': '{typ}'" for name, typ in _STAGE_COLUMNS.items())
            con.execute(
                f"""
                INSERT INTO raw_events
                SELECT * FROM read_csv(
                    ?, columns={{{cols}}}, header=false, nullstr='',
                    ignore_errors=true, auto_detect=false
                )
                """,
                [str(stage_path)],
            )
        return total, truncated
    finally:
        stage_path.unlink(missing_ok=True)


_MEMBER_SUFFIX = {"csv": ".csv", "json": ".json", "log": ".log"}


def _ingest_zip(con, case_id: str, path: Path, report=_noop) -> tuple[bool, list[dict], list[dict]]:
    """Every log member of a zip into this one case (FR-2.3), one at a time.
    Returns (truncated, members ingested, members skipped)."""
    members, skipped = archive.plan_zip(path)
    if not members:
        raise ValueError("the zip contains no log files"
                         + (f" ({len(skipped)} skipped - see skipped_members)" if skipped else ""))
    budget = config.MAX_UPLOAD_BYTES  # FR-2.2, over the whole decompressed zip
    truncated = False
    done = []
    all_bytes = max(1, sum(m.size for m in members))
    before = 0  # bytes of the members already ingested, for progress
    for m in members:
        base, width = before / all_bytes, m.size / all_bytes
        fd, tmp_name = tempfile.mkstemp(suffix=_MEMBER_SUFFIX[m.kind], dir=str(_stage_dir()))
        os.close(fd)
        tmp = Path(tmp_name)
        try:
            size = archive.extract_member(path, m, tmp, budget)
            budget -= size
            start = _next_row_id(con)
            added, cut = _ingest_file(
                con, case_id, tmp, m.kind, start,
                report=lambda f, est=False, base=base, width=width: report(base + f * width, est))
            truncated = truncated or cut
        finally:
            tmp.unlink(missing_ok=True)
        # Which rows came from which file - raw_events has no source column,
        # so the manifest carries the ranges instead.
        done.append({"name": m.name, "kind": m.kind, "bytes": size, "rows": added,
                     "row_id_first": start if added else None,
                     "row_id_last": start + added - 1 if added else None})
        log.info("case %s: zip member %s -> %s rows", case_id, m.name, added)
        before += m.size
    return truncated, done, skipped


def process_case(case_id: str, path: Path, kind: str) -> None:
    """Synchronous - callers run this in a worker thread."""
    storage.update_status(case_id, "processing")
    progress = Progress(case_id)
    progress.set("ingest", 0, force=True)
    con = None
    try:
        db.drop(case_id)  # re-processing a case starts clean
        con = db.init(case_id)

        extra = {}
        if kind == "zip":
            truncated, members, skipped = _ingest_zip(con, case_id, path, progress.ingest)
            extra = {"members": members, "skipped_members": skipped}
        else:
            # A .gz is read at its decompressed size; the upload recorded it.
            expected = (storage.load_manifest(case_id) or {}).get("uncompressed_bytes")
            _, truncated = _ingest_file(con, case_id, path, kind, 0, progress.ingest, expected)

        # Threat-intel indicators are loaded now that the traffic is known,
        # so only the ones this case can match are stored (see intel.fill).
        progress.set("intel", INGEST_END, force=True)
        indicators = intel.fill(con)
        if indicators:
            log.info("case %s: %s threat-intel indicators apply", case_id, indicators)

        progress.set("rules", INTEL_END, force=True)
        matched = rules.apply_rules(
            con, on_rule=lambda i, n: progress.set("rules", INTEL_END + (99 - INTEL_END) * i / n))
        severity = db.severity_summary(con)
        con.close()
        con = None

        total_rows, flagged = db.counts(case_id)
        storage.update_case(
            case_id,
            status="ready",
            total_rows=total_rows,
            flagged_count=flagged,
            rules_matched=matched,
            truncated=truncated,
            severity=severity,
            error=None,
            progress={"stage": "done", "pct": 100, "estimated": False},
            **extra,
        )
        log.info("case %s ready: %s rows, %s flagged", case_id, total_rows, flagged)

    except Exception as exc:  # noqa: BLE001 - surface any ingest failure to the UI
        log.exception("case %s failed", case_id)
        if con is not None:
            try:
                con.close()
            except Exception:  # noqa: BLE001
                pass
        storage.update_case(
            case_id,
            status="failed",
            error=f"{type(exc).__name__}: {exc}",
            traceback=traceback.format_exc()[-2000:],
        )
