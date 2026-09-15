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
import traceback
from pathlib import Path

from .. import config
from . import db, decode, intel, parsers, rules, storage

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
    with open(path, "r", encoding="utf-8-sig", errors="replace", newline="") as fh:
        try:
            return next(csv.reader(fh, delimiter=delimiter))
        except StopIteration:
            return []


def _ingest_csv_sql(con, path: Path) -> int:
    """Ingest a CSV entirely inside DuckDB: it reads the file, maps source
    columns onto the canonical schema, and inserts - no row ever crosses
    into Python. Column mapping is resolved once from the header.

    Returns the number of rows inserted, or -1 if the header carried no
    recognisable fields (caller falls back to the Python path).
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
            row_number() OVER () - 1              AS row_id,
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
    return con.execute("SELECT count(*) FROM raw_events").fetchone()[0]


def _write_stage(path: Path, kind: str, stage_path: Path) -> tuple[int, bool]:
    total = 0
    truncated = False
    with open(stage_path, "w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh)
        for row in parsers.iter_rows(path, kind):
            if config.MAX_ROWS and total >= config.MAX_ROWS:
                truncated = True
                break
            writer.writerow(_stage_row(total, decode.decode(row, kind)))
            total += 1
    return total, truncated


def process_case(case_id: str, path: Path, kind: str) -> None:
    """Synchronous - callers run this in a worker thread."""
    storage.update_status(case_id, "processing")
    con = None
    stage_path = None
    try:
        db.drop(case_id)  # re-processing a case starts clean
        con = db.init(case_id)

        truncated = False
        ingested = -1

        if kind == "csv" and not config.MAX_ROWS:
            # Fast path: DuckDB reads and decodes the CSV itself.
            try:
                ingested = _ingest_csv_sql(con, path)
            except Exception:  # noqa: BLE001
                log.warning("case %s: SQL CSV ingest failed, falling back", case_id,
                            exc_info=True)
                con.execute("DELETE FROM raw_events")
                ingested = -1

        if ingested < 0:
            # Python path: line logs, JSON, or any CSV the fast path
            # couldn't map. Decoded rows go through a staging CSV because
            # DuckDB's executemany() is far too slow for bulk insert.
            stage_dir = Path(config.DATA_DIR) / "tmp"
            stage_dir.mkdir(parents=True, exist_ok=True)
            fd, stage_name = tempfile.mkstemp(suffix=".csv", dir=str(stage_dir))
            os.close(fd)
            stage_path = Path(stage_name)

            total, truncated = _write_stage(path, kind, stage_path)
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

        # Threat-intel indicators are loaded now that the traffic is known,
        # so only the ones this case can match are stored (see intel.fill).
        indicators = intel.fill(con)
        if indicators:
            log.info("case %s: %s threat-intel indicators apply", case_id, indicators)

        matched = rules.apply_rules(con)
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
    finally:
        if stage_path is not None:
            stage_path.unlink(missing_ok=True)
