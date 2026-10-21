"""Ingest pipeline: raw file on disk -> canonical rows in DuckDB -> findings.

Runs off the request path (see routers/upload.py) so a large upload never
blocks or times out an HTTP request.

Rows stream through decode and are written to a temporary staging CSV, which
DuckDB then bulk-loads in one statement. That detour exists for a reason:
DuckDB's executemany() is a per-row prepared-statement call and benchmarks at
roughly 300 rows/sec here (20k rows took 65s), while its CSV reader ingests
the same data in well under a second. Peak memory stays flat either way.
"""

import contextlib
import csv
import gzip
import json
import logging
import os
import shutil
import tempfile
import threading
import time
import traceback
from collections import Counter
from itertools import chain, islice
from pathlib import Path

from .. import config
from . import (archive, checkpoint_le, custody, db, decode, finding_ids, identify, intel, logsources,
               parsers, profiles, provenance, repro, rules, severity, storage, winevent)

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

# The CSV fast path is ONE DuckDB statement, and DuckDB 1.1.3 - which this
# was written for - had no query_progress(), so its share is estimated from elapsed time against the
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


def _sql_values(mapping: dict[str, str]) -> str:
    """`WHEN 'a' THEN 'b' ...` for a value vocabulary."""
    def lit(s: str) -> str:
        return "'" + s.replace("'", "''") + "'"
    return " ".join(f"WHEN {lit(k)} THEN {lit(v)}" for k, v in mapping.items())


def _ingest_csv_sql(con, path: Path, start: int = 0,
                    encoding: str = "utf-8-sig") -> tuple[int, dict | None]:
    """Ingest a CSV entirely inside DuckDB: it reads the file, maps source
    columns onto the canonical schema, and inserts - no row ever crosses
    into Python. Column mapping is resolved once from the header, from the
    log source's documentation (logsources.py) - identify.py has already
    refused any file no profile documents. A .csv.gz is read the same way -
    DuckDB decompresses it as it reads.

    Row ids continue from `start`, so several files can share one case
    (a zip, FR-2.3). Returns (rows inserted, how the columns were mapped), or
    (-1, None) if the header carried no recognisable fields (caller falls
    back to the Python path).
    """
    # One sniff, handed to both readers, so the header Python maps and the
    # columns DuckDB returns cannot disagree about the shape of the file
    # (gotcha #22).
    delimiter = parsers.sniff_delimiter(path)
    header = _csv_header(path, delimiter)
    # DuckDB reads UTF-8 (with or without a BOM) by default; UTF-16 is named.
    enc_opt = ", encoding='utf-16'" if encoding == "utf-16" else ""
    if not header:
        return -1, None

    mapping = logsources.resolve(header)
    if not any(mapping.columns.values()):
        return -1, None
    profile = mapping.profile

    def col(field: str) -> str:
        cols = mapping.columns.get(field)
        return _q(cols[0]) if cols else "NULL"

    def raw(column: str) -> str:
        """A column's value, with any documented "no data" placeholder
        (e.g. PAN-OS 9.1's 1969 high-res timestamp) read as NULL."""
        q = _q(column)
        bad = (profile.null_values.get(column, ()) if profile else ())
        for prefix in bad:
            q = f"CASE WHEN {q} LIKE '{prefix}%' THEN NULL ELSE {q} END"
        return q

    def parse_ts(c: str) -> str:
        return (
            f"coalesce("
            f"try_cast({c} AS TIMESTAMPTZ) AT TIME ZONE '{config.EVENT_TZ_NAME}', "
            f"try_strptime({c}, '%Y/%m/%d %H:%M:%S'), "
            f"try_strptime({c}, '%d/%m/%Y %H:%M:%S'), "
            f"try_strptime({c}, '%d/%m/%Y %H:%M'), "
            f"try_strptime({c}, '%b %d, %Y %I:%M:%S %p'), "
            f"try_strptime({c}, '%b %d, %Y %H:%M:%S'))"
        )

    ts_cols = [raw(c) for c in mapping.columns.get("ts", ())]
    ts_col = f"coalesce({', '.join(ts_cols)})" if ts_cols else "NULL"
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
    # Where a profile documents several time columns, the first that parses
    # wins, row by row.
    ts_expr = (
        f"coalesce({', '.join(parse_ts(c) for c in ts_cols)})" if ts_cols else "NULL"
    )

    # Check Point writes addresses as "object-name (1.2.3.4)"; Palo Alto
    # writes a bare IP. Pull the IP out when present, otherwise keep the
    # original text so named entities still appear.
    def ip_expr(field: str) -> str:
        c = col(field)
        if c == "NULL":
            return "NULL"
        return f"coalesce(nullif(regexp_extract({c}, '[0-9]{{1,3}}(\\.[0-9]{{1,3}}){{3}}'), ''), {c})"

    # Log sources spell verdicts differently (Check Point: accept/drop/reject);
    # rules are written against the canonical spellings.
    # A matched profile uses the vocabulary its documentation lists instead.
    verdict_col = col("verdict")
    verdict_whens = _sql_values(
        profile.verdict_values if profile and profile.verdict_values else decode.VERDICT_ALIASES)
    verdict_expr = (
        "NULL" if verdict_col == "NULL" else
        # NULLIF: a vocabulary entry of "" means "not a verdict" (Check
        # Point's "Key Install"), the same None decode_row gives it.
        f"NULLIF(CASE lower(trim({verdict_col})) {verdict_whens} "
        f"ELSE lower(trim({verdict_col})) END, '')"
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
    auth_whens = _sql_values(
        profile.auth_values if profile and profile.auth_values else decode.AUTH_STATUS)
    action_expr = (
        "NULL" if auth_col == "NULL" or user_col == "NULL" else
        f"CASE WHEN {user_col} IS NULL OR {user_col} = '' THEN NULL "
        f"ELSE CASE lower(trim({auth_col})) {auth_whens} ELSE NULL END END"
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
                      delim='{delimiter}'{enc_opt})
        """,
        [str(path)],
    )
    added = con.execute("SELECT count(*) FROM raw_events WHERE row_id >= ?", [start]).fetchone()[0]
    return added, mapping.describe()


def _write_stage(path: Path, kind: str, stage_path: Path, start: int = 0,
                 progress=None) -> tuple[int, bool, dict]:
    """Returns (rows, truncated, how the file was mapped)."""
    total = 0
    truncated = False
    # A CSV is mapped once from its header by its documented profile, the
    # same way the SQL fast path maps it; JSON by the keys of its first
    # records; line logs count which documented format read each line.
    mapping = None
    json_stats: dict = {}
    rows = parsers.iter_rows(path, kind, progress, json_stats)
    if kind == "csv":
        header = _csv_header(path, parsers.sniff_delimiter(path))
        mapping = logsources.resolve(header)
    elif kind == "json":
        # JSON has no header, so the first records stand in for one: their
        # keys, in order of first appearance, are mapped exactly as a CSV
        # header would be - by a documented profile when one matches - and
        # then every record is read through that one mapping (IAI-35).
        head = list(islice(rows, JSON_HEADER_RECORDS))
        keys = list(dict.fromkeys(k for r in head if "_raw" not in r for k in r))
        if keys:
            mapping = logsources.resolve(keys)
        rows = chain(head, rows)
    line_counts: Counter = Counter()
    # Which syslog header each line had (decode.decode_line, IAI-34).
    syslog_counts: Counter = Counter()
    with open(stage_path, "w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh)
        for row in rows:
            if config.MAX_ROWS and total >= config.MAX_ROWS:
                truncated = True
                break
            event = decode.decode(row, kind, mapping)
            if kind == "log" or "_raw" in row:
                line_counts[event["profile"]] += 1
                if event.get("envelope"):
                    syslog_counts[event["envelope"]] += 1
                if event.get("syslog_pri") is not None:
                    syslog_counts["pri"] += 1
                if event.get("year_inferred"):
                    syslog_counts["year_inferred"] += 1
            writer.writerow(_stage_row(start + total, event))
            total += 1
    if mapping is not None:
        described = mapping.describe()
    elif kind == "log" or any(line_counts):
        described = logsources.line_mapping(line_counts)
    else:
        described = {"method": "unrecognised", "profile": None, "fields": {},
                     "heuristic_fields": [], "docs": [], "notes": []}
    if syslog_counts:
        # rfc5424 / rfc3164 / iso header lines, how many carried a <PRI>, and
        # how many RFC 3164 timestamps had their year inferred.
        described["syslog"] = dict(syslog_counts)
    if kind == "json":
        # What could not be read as a record is reported, never dropped
        # silently: those rows are still in the case, read as text lines.
        described["json"] = {k: json_stats.get(k) for k in
                             ("layout", "records", "wrapper", "unparseable",
                              "unparseable_at", "broken_at_byte")}
    return total, truncated, described


# How many records of a JSON file stand in for its header.
JSON_HEADER_RECORDS = 200


def _stage_dir() -> Path:
    d = Path(config.DATA_DIR) / "tmp"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _next_row_id(con) -> int:
    return con.execute("SELECT coalesce(max(row_id) + 1, 0) FROM raw_events").fetchone()[0]


# Canonical mapped field -> the raw_events column it lands in.
_FIELD_COLUMN = {"ts": "ts", "srcip": "srcip", "dstip": "dstip", "dstport": "dstport",
                 "username": "username", "verdict": "verdict", "app": "app", "risk": "risk",
                 "bytes_sent": "bytes_sent", "category": "category", "auth_status": "action"}


def _coverage(con, start: int, written: int, mapping: dict) -> int:
    """What of this file actually got read (IAI-31 - "unparseable rows
    counted and reported, not silently dropped"), put on its mapping:

    - `rows` in the case, and `not_loaded`: rows decoded but refused by the
      bulk load (the staging read skips a row it cannot type) - nothing
      reported that before;
    - `time_unparsed`: rows with a timestamp text that did not parse;
    - `fields`: per mapped field, how many rows carry a value - the gotcha #7
      query (`count(srcip)`...) run on every case instead of by hand.
    Returns the rows actually in the case."""
    fields = [f for f in (mapping.get("fields") or {}) if f in _FIELD_COLUMN]
    counts = ", ".join(f"count({_FIELD_COLUMN[f]})" for f in fields)
    row = con.execute(
        "SELECT count(*), count(*) FILTER (WHERE ts IS NULL AND coalesce(ts_raw, '') <> '')"
        + (f", {counts}" if counts else "") + " FROM raw_events WHERE row_id >= ?",
        [start],
    ).fetchone()
    loaded = row[0]
    mapping["coverage"] = {
        "rows": loaded,
        "not_loaded": max(0, written - loaded),
        "time_unparsed": row[1],
        "fields": dict(zip(fields, row[2:])),
    }
    return loaded


def _file_notes(mapping: dict, encoding: str | None, read_as: str | None, found: dict) -> None:
    """What the case page should say about how the file itself was read, and
    what it was identified as (identify.py). A binary file has no encoding."""
    mapping["logsource"] = found
    if encoding and encoding != "utf-8-sig":
        mapping["encoding"] = encoding
    if read_as:
        mapping["read_as"] = read_as


def _ingest_file(con, case_id: str, path: Path, kind: str, start: int,
                 report=_noop, expected_bytes: int | None = None) -> tuple[int, bool, dict]:
    """Decode one file into raw_events with row ids from `start`.
    `report(fraction, estimated)` gets this file's progress (FR-2.5).
    Returns (rows added, truncated, how its columns were mapped - logsources.py)."""
    # What the file is, decided before a row is read (identify.py, IAI-92). A
    # file that is not a documented format this tool reads is kept as evidence
    # and not analysed - nothing is guessed from it.
    found = identify.identify(path, kind)
    read_as = found.get("read_as")
    if read_as:
        kind = read_as
    if found["status"] != identify.SUPPORTED:
        report(1.0)
        return 0, False, {"method": found["status"], "profile": None, "name": found["name"],
                          "fields": {}, "heuristic_fields": [], "docs": [], "notes": [],
                          "logsource": found}
    if found.get("profile") in _WIN_CONTAINERS:
        # Windows event XML (W1), Splunk's WinEventLog text (W3) or Winlogbeat /
        # NXLog JSON (W4): timeline rows and the native win_events rows.
        mapping = _ingest_winevents(con, path, start, report, _WIN_CONTAINERS[found["profile"]])
        _file_notes(mapping, parsers.detect_encoding(path), None, found)
        return _coverage(con, start, mapping["windows"]["rows"], mapping), False, mapping
    if found.get("profile") == winevent.EVTX_PROFILE_ID:
        # .evtx (W2): the same rows, from records the evtx library renders.
        with _plain_copy(path) as plain:
            mapping = _ingest_winevents(con, plain, start, report, "evtx")
        _file_notes(mapping, None, None, found)
        return _coverage(con, start, mapping["windows"]["rows"], mapping), False, mapping
    encoding = parsers.detect_encoding(path)
    if found.get("profile") == checkpoint_le.PROFILE_ID:
        # Check Point Log Exporter records inside an EventLog Analyzer export
        # (IAI-85): its own SQL reader. No fallback - the generic paths would
        # read the wrapper's columns, not the record.
        stop, th = _estimate_while(report, expected_bytes or path.stat().st_size)
        try:
            added, mapping = checkpoint_le.ingest_sql(con, path, start, encoding)
        finally:
            stop.set()
            th.join()
        _file_notes(mapping, encoding, read_as, found)
        return _coverage(con, start, added, mapping), False, mapping
    if kind == "csv" and not config.MAX_ROWS:
        # Fast path: DuckDB reads and decodes the CSV itself.
        stop, th = _estimate_while(report, expected_bytes or path.stat().st_size)
        try:
            added, mapping = _ingest_csv_sql(con, path, start, encoding)
            if added >= 0:
                _file_notes(mapping, encoding, read_as, found)
                return _coverage(con, start, added, mapping), False, mapping
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
    # The year an RFC 3164 timestamp is put in: the case's upload time
    # (decode.infer_year, IAI-34).
    uploaded = (storage.load_manifest(case_id) or {}).get("uploaded_at")
    year_ref = decode.REFERENCE_TIME.set(decode.parse_ts(uploaded))
    try:
        # Parsing is most of the work; the bulk load that follows is quick.
        total, truncated, mapping = _write_stage(path, kind, stage_path, start,
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
        _file_notes(mapping, encoding, read_as, found)
        return _coverage(con, start, total, mapping), truncated, mapping
    finally:
        decode.REFERENCE_TIME.reset(year_ref)
        stage_path.unlink(missing_ok=True)


_WIN_STAGE_COLUMNS = {
    "row_id": "BIGINT", "channel": "VARCHAR", "provider": "VARCHAR", "event_id": "INTEGER",
    "record_id": "VARCHAR", "computer": "VARCHAR", "user_sid": "VARCHAR", "time_created": "VARCHAR",
    "data": "VARCHAR",
}


@contextlib.contextmanager
def _plain_copy(path: Path):
    """The file itself, or a .gz decompressed into staging: an .evtx is read by
    chunk offset, which a gzip stream cannot seek to cheaply. The upload already
    held the decompressed size to the limit and the disk check (FR-2.2)."""
    if not str(path).lower().endswith(".gz"):
        yield path
        return
    fd, name = tempfile.mkstemp(suffix=".evtx", dir=str(_stage_dir()))
    os.close(fd)
    tmp = Path(name)
    try:
        with gzip.open(path, "rb") as src, open(tmp, "wb") as dst:
            shutil.copyfileobj(src, dst, 1024 * 1024)
        yield tmp
    finally:
        tmp.unlink(missing_ok=True)


_WIN_CONTAINERS = {winevent.PROFILE_ID: "xml", winevent.SPLUNK_PROFILE_ID: "splunk",
                   winevent.WINLOGBEAT_PROFILE_ID: "winlogbeat", winevent.NXLOG_PROFILE_ID: "nxlog"}


def _ingest_winevents(con, path: Path, start: int, report=_noop, container: str = "xml") -> dict:
    """Windows events into raw_events (the timeline row) and win_events (the
    event as Windows wrote it) - winevent.py. `container`: "xml" (event XML),
    "evtx" (records rendered as event XML), "splunk" (Splunk's WinEventLog
    text, items named from Windows' message templates), "winlogbeat" or
    "nxlog" (JSON records). Streamed one event at a time through two staging
    CSVs and bulk-loaded (gotcha #1). Returns the mapping."""
    evtx, splunk = container == "evtx", container == "splunk"
    as_json = container in ("winlogbeat", "nxlog")
    json_stats: dict = {}
    stage = []
    for _ in range(2):
        fd, name = tempfile.mkstemp(suffix=".csv", dir=str(_stage_dir()))
        os.close(fd)
        stage.append(Path(name))
    rows = events = damaged = bad_chunks = unmatched = 0
    errors: list[str] = []
    channels: Counter = Counter()
    types: Counter = Counter()
    outside: Counter = Counter()  # NXLog keys the event's Windows template does not name
    progress = lambda f: report(0.9 * f)  # noqa: E731
    texts = (winevent.iter_evtx(path, progress, errors, scratch=_stage_dir()) if evtx
             else winevent.iter_splunk_records(path, progress=progress) if splunk
             else winevent.iter_json_records(path, progress, json_stats) if as_json
             else winevent.iter_event_texts(path, progress=progress))
    try:
        with open(stage[0], "w", encoding="utf-8", newline="") as f_raw, \
                open(stage[1], "w", encoding="utf-8", newline="") as f_win:
            w_raw, w_win = csv.writer(f_raw), csv.writer(f_win)
            for text in texts:
                row_id = start + rows
                if isinstance(text, winevent.Damage):
                    # What the chunk headers name and the reader did not return.
                    damaged += text.records
                    bad_chunks += not text.records
                    w_raw.writerow(_stage_row(row_id, winevent.damaged_row(text.text, prefix="")))
                    rows += 1
                    continue
                prefix = "[unreadable event XML] "
                if isinstance(text, winevent.EvtxRecord):
                    text, ev = text.xml, winevent.parse_event(text.xml, text.fixes, text.empty_in_array)
                elif isinstance(text, winevent.SplunkRecord):
                    text, ev = text.text, winevent.parse_splunk(text.text)
                    prefix = "[unreadable Splunk WinEventLog record] "
                elif isinstance(text, dict):
                    # A JSON record that is not a Windows event of this file's shape
                    # (or did not parse - `_raw`) is kept as its text.
                    ev = winevent.parse_json_event(text)
                    text = text.get("_raw") or json.dumps(text, ensure_ascii=False)
                    prefix = "[not a readable Windows event record] "
                else:
                    ev = winevent.parse_event(text)
                if ev is None:
                    damaged += 1
                    w_raw.writerow(_stage_row(row_id, winevent.damaged_row(text, prefix)))
                else:
                    events += 1
                    unmatched += splunk and not ev["template_matched"]
                    outside.update(ev.get("outside_template") or ())
                    channels[ev["channel"] or "-"] += 1
                    timeline = winevent.timeline_row(ev)
                    types[timeline["action"] or f"untyped {ev['provider']} {ev['event_id']}"] += 1
                    w_raw.writerow(_stage_row(row_id, timeline))
                    w_win.writerow(winevent.native_row(row_id, ev))
                rows += 1
        report(0.9)
        for table, path_, cols in (("raw_events", stage[0], _STAGE_COLUMNS),
                                   ("win_events", stage[1], _WIN_STAGE_COLUMNS)):
            spec = ", ".join(f"'{n}': '{t}'" for n, t in cols.items())
            select = ("*" if table == "raw_events" else
                      "* REPLACE (CAST(data AS JSON)::MAP(VARCHAR, VARCHAR) AS data)")
            con.execute(f"""
                INSERT INTO {table}
                SELECT {select} FROM read_csv(?, columns={{{spec}}}, header=false, nullstr='',
                                            quote='"', escape='"', auto_detect=false)
            """, [str(path_)])
    finally:
        for p in stage:
            p.unlink(missing_ok=True)
    notes = ["Every item of every event is kept under its own name in win_events - the "
             "names SigmaHQ rules use.",
             "Which Sysmon items fill the timeline columns is observed in the events' own "
             "Data names; the Sysmon page lists the events, not their fields."]
    if evtx:
        notes.append("Records are rendered by the evtx library and counted against each chunk's "
                     "header: what a chunk names and was not returned is listed as unreadable.")
    if splunk:
        notes += ["Splunk's text carries only the rendered message: each value is named by matching "
                  "it against the event's message template that Windows publishes (Security-Auditing, "
                  "Eventlog). The values are as rendered - an account name where Windows stored a SID, "
                  "the text of a %% parameter (\"Yes\" for %%1842) - so a rule that matches a raw SID "
                  "or %% code does not match here (Q46).",
                  "The time line states no zone: it is taken as GMT+7 and flagged unconfirmed - "
                  "declare the source's zone at Ingest and re-process (Q44)."]
    windows = {"rows": rows, "events": events, "unreadable": damaged,
               "channels": dict(channels.most_common()), "types": dict(types.most_common())}
    if evtx:
        windows.update(unreadable_chunks=bad_chunks, reader_errors=errors)
    if splunk:
        windows["unmatched_messages"] = unmatched
    if container == "nxlog":
        windows["keys_outside_template"] = dict(outside.most_common(10))
    if container == "nxlog":
        notes += ["NXLog writes its own fields beside the event's items: the fields its reference "
                  "documents (and Logstash's) are set aside, every other key is an item under its "
                  "own name (Q50) - an item named like one of NXLog's fields would be among them; "
                  "the EventData XML is used instead when a record carries it.",
                  "EventTime states no zone in older NXLog output: it is taken as GMT+7 and flagged "
                  "unconfirmed - declare the source's zone at Ingest and re-process (Q49)."]
    profile, name, docs = {"evtx": (winevent.EVTX_PROFILE_ID, winevent.EVTX_NAME, winevent.EVTX_DOCS),
                           "splunk": (winevent.SPLUNK_PROFILE_ID, winevent.SPLUNK_NAME, winevent.SPLUNK_DOCS),
                           "winlogbeat": (winevent.WINLOGBEAT_PROFILE_ID, winevent.WINLOGBEAT_NAME,
                                          winevent.WINLOGBEAT_DOCS),
                           "nxlog": (winevent.NXLOG_PROFILE_ID, winevent.NXLOG_NAME, winevent.NXLOG_DOCS),
                           }.get(container, (winevent.PROFILE_ID, winevent.NAME, winevent.DOCS))
    return {
        "method": "documented",
        "profile": profile,
        "name": name,
        "docs": [{"title": t, "url": u} for t, u in docs],
        "notes": notes,
        "fields": {f: {"columns": [c], "source": "documented"} for f, c in (
            ("ts", {"splunk": "Splunk's time line", "winlogbeat": "@timestamp",
                    "nxlog": "EventTime"}.get(container, "System/TimeCreated/@SystemTime")),
            ("username", "TargetUserName / SubjectUserName / User"),
            ("srcip", "IpAddress / SourceIp"), ("dstip", "DestinationIp"), ("dstport", "DestinationPort"))},
        "heuristic_fields": [], "missing_fields": [],
        "windows": windows,
        # How the JSON was laid out, and what could not be read as a record (IAI-35).
        **({"json": {k: json_stats.get(k) for k in ("layout", "records", "wrapper", "unparseable",
                                                    "unparseable_at", "broken_at_byte")}}
           if as_json else {}),
    }


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
            added, cut, mapping = _ingest_file(
                con, case_id, tmp, m.kind, start,
                report=lambda f, est=False, base=base, width=width: report(base + f * width, est))
            truncated = truncated or cut
        finally:
            tmp.unlink(missing_ok=True)
        # Which rows came from which file - raw_events has no source column,
        # so the manifest carries the ranges instead.
        done.append({"name": m.name, "kind": m.kind, "bytes": size, "rows": added,
                     "row_id_first": start if added else None,
                     "row_id_last": start + added - 1 if added else None,
                     "mapping": mapping})
        log.info("case %s: zip member %s -> %s rows", case_id, m.name, added)
        before += m.size
    return truncated, done, skipped


def _apply_declared_time(con, manifest: dict, extra: dict) -> list[dict]:
    """Apply each evidence item's declared zone and clock offset to `ts`
    (provenance.py, D10) and count its rows with and without a stated offset.
    A declared zone moves only the rows whose source text states no offset -
    the ones gotcha #21 took to be GMT+7; a clock offset moves every row. One
    UPDATE per item over its row range; `raw_events` is rebuilt from `raw/` on
    every run, so a cleared setting gives back the first run's times."""
    members = extra.get("members")
    spans = ([(m["name"], m["row_id_first"], m["row_id_last"]) for m in members]
             if members else [(manifest.get("original_filename") or "", None, None)])
    applied = []
    for item, first, last in spans:
        if members and first is None:  # a member that produced no rows
            continue
        where, params = ("row_id BETWEEN ? AND ?", [first, last]) if members else ("TRUE", [])
        no_offset = f"NOT coalesce(regexp_matches(ts_raw, '{db.TZ_MARKER_PATTERN}', 'i'), false)"
        with_offset, without_offset = con.execute(
            f"SELECT count(*) FILTER (WHERE NOT {no_offset}), count(*) FILTER (WHERE {no_offset}) "
            f"FROM raw_events WHERE {where} AND ts IS NOT NULL", params).fetchone()
        zone, clock = provenance.declared_time(manifest, item)
        shifted = 0
        if zone is not None or clock:
            zone_shift = provenance.shift(zone, clock).total_seconds()
            clock_shift = provenance.shift(None, clock).total_seconds()
            con.execute(
                f"UPDATE raw_events SET ts = ts + to_seconds(CASE WHEN {no_offset} THEN ? ELSE ? END) "
                f"WHERE {where} AND ts IS NOT NULL", [zone_shift, clock_shift, *params])
            shifted = without_offset if not clock else with_offset + without_offset
        p = (manifest.get("provenance") or {}).get(item) or {}
        applied.append({"item": item, "zone": p.get("source_timezone"),
                        "clock_offset_seconds": clock, "rows_with_offset": with_offset,
                        "rows_without_offset": without_offset, "rows_shifted": shifted})
    return applied


class IntegrityError(Exception):
    """The preserved file no longer matches its acquisition digest."""


def _verify_evidence(case_id: str, path: Path) -> None:
    """Re-compute the raw file's SHA-256 before using it (custody.py). A
    mismatch stops the run: findings computed from altered evidence would
    look exactly as trustworthy as real ones."""
    recorded = (storage.load_manifest(case_id) or {}).get("evidence")
    ok, actual = custody.check(case_id, path, recorded)
    if ok is False:
        custody.record(case_id, "integrity_failed", "system", sha256=actual,
                       expected=recorded["sha256"], purpose="before processing")
        raise IntegrityError(
            f"SHA-256 of the preserved file is {actual}, but {recorded['sha256']} was "
            f"recorded when it was acquired - the evidence has changed, refusing to analyse it")
    custody.record(case_id, "verified" if ok else "unverified", "system", sha256=actual,
                   purpose="before processing",
                   **({} if ok else {"note": "no acquisition digest was recorded for this file"}))


def process_case(case_id: str, path: Path, kind: str) -> None:
    """Synchronous - callers run this in a worker thread."""
    storage.update_status(case_id, "processing")
    progress = Progress(case_id)
    progress.set("ingest", 0, force=True)
    con = None
    try:
        _verify_evidence(case_id, path)
        db.drop(case_id)  # re-processing a case starts clean
        con = db.init(case_id)

        extra = {}
        if kind == "zip":
            truncated, members, skipped = _ingest_zip(con, case_id, path, progress.ingest)
            extra = {"members": members, "skipped_members": skipped}
        else:
            # A .gz is read at its decompressed size; the upload recorded it.
            expected = (storage.load_manifest(case_id) or {}).get("uncompressed_bytes")
            _, truncated, mapping = _ingest_file(con, case_id, path, kind, 0, progress.ingest, expected)
            # How the columns were read, and from which log source's
            # documentation - or that they were guessed and need checking
            # (logsources.py).
            extra = {"mapping": mapping}

        # Declared source time zones and clock offsets (provenance.py, D10),
        # before anything reads a time: rules, windows and profiles all see the
        # corrected `ts`. `ts_raw` keeps the source text as written.
        time_applied = _apply_declared_time(con, storage.load_manifest(case_id) or {}, extra)

        # Threat-intel indicators are loaded now that the traffic is known,
        # so only the ones this case can match are stored (see intel.fill).
        progress.set("intel", INGEST_END, force=True)
        indicators = intel.fill(con)
        if indicators:
            log.info("case %s: %s threat-intel indicators apply", case_id, indicators)

        progress.set("rules", INTEL_END, force=True)
        matched = rules.apply_rules(
            con, on_rule=lambda i, n: progress.set("rules", INTEL_END + (99 - INTEL_END) * i / n))
        escalated = severity.escalate(con)
        sev_summary = severity.summary(con)
        # Behaviour profiles (layer C facts, profiles.py): after the rules,
        # because nothing in them is a finding and nothing below reads them.
        profiles.build(con)
        con.close()
        con = None

        total_rows, flagged = db.counts(case_id)
        # An id for every finding that enters the workflow (finding_ids.py) -
        # before the case reads `ready`, so nothing that waits for `ready` finds
        # it half-done. A failure here is not the case's failure: the ids are
        # handed out again on first read.
        try:
            finding_ids.ensure(case_id)
        except Exception:  # noqa: BLE001
            log.exception("case %s: could not assign finding ids", case_id)
        storage.update_case(
            case_id,
            status="ready",
            total_rows=total_rows,
            flagged_count=flagged,
            rules_matched=matched,
            truncated=truncated,
            severity=sev_summary,
            escalations=escalated,
            error=None,
            progress={"stage": "done", "pct": 100, "estimated": False},
            time_applied=time_applied,
            **extra,
        )
        # The reproducibility record (repro.py): what produced these findings.
        mappings = [m.get("mapping") or {} for m in extra.get("members") or []] or [extra.get("mapping") or {}]
        custody.record(case_id, "processed", "system", rows=total_rows, flagged=flagged,
                       rules=matched, method=repro.record(mappings, time_applied))
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
