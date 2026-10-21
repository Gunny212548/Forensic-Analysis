r"""Check Point Log Exporter records, read from a ManageEngine EventLog Analyzer
search export (IAI-85, specs/IAI-85_checkpoint_log_exporter.md).

The record is documented; the wrapper around it is not.

- **Record** - Log Exporter's default *syslog* format (Log Exporter
  Administration Guide, "Format Configuration"): the body starts with `[` and
  ends with `]`, fields are separated by `; `, a name from its value by `:`,
  values are in double quotes, and inside a value `\\` `\"` `\]` stand for a
  backslash, a quote and a bracket. Field names are Check Point's own, as
  sk144192 ("Description of Fields in Check Point Logs") defines them. `time`
  is a Unix epoch - the guide's Splunk settings read it with `%s` and its LEEF
  note calls it "Epoch time format" - so it states its zone (UTC).
- **Update logs** - the guide's Appendix B: in raw read-mode the updates of one
  connection "arrive as distinct logs"; "use the loguid field to correlate
  update logs". Every row stays an event (Q37); within a `loguid` only the
  first - by time, `sequencenum`, file order - carries the verdict, the later
  ones are typed `log_update` and carry none, so rules and behaviour profiles
  count connections, not updates. The same move as ESXi's second PAM report
  (gotcha #57).
- **Wrapper** - EventLog Analyzer's search-result CSV (the user, 2026-10-21):
  a `Search Results` line, a header (`#, Message, DisplayName, LogType,
  Device, Time, ...`), one row per log, the Log Exporter record in `Message`
  after a numeric prefix (`11241 - `). ManageEngine documents report exports,
  not this layout, so the wrapper is *observed* in a real file, like ESXi's
  undocumented lines (gotcha #42). Its own columns are not read: `Time` is the
  collector's wall clock and `Username` a display name, while the record
  carries Check Point's.

Reading is one SQL statement (gotcha #1): DuckDB reads the CSV, splits every
`Message` with the grammar above, and inserts - no row crosses into Python.
`parse_body` is the same grammar in Python, for identification and for a
future reader of Log Exporter syslog lines straight from a collector (no real
file of those yet - IAI-85 keeps that part open).
"""

import csv
import re
from itertools import islice
from pathlib import Path

from .. import config
from . import parsers

PROFILE_ID = "checkpoint-log-exporter"
NAME = ("Check Point Log Exporter records (syslog format) in a ManageEngine EventLog Analyzer "
        "search export")
LOGSOURCE = {"sigma": {"category": "firewall"}, "custom": "checkpoint_log_exporter"}

DOCS = (
    ("Check Point Log Exporter Administration Guide - Format Configuration (syslog body, "
     "separators, escapes)",
     "https://sc1.checkpoint.com/documents/Log_Exporter/EN/Content/Topics/Format-Configuration.htm"),
    ("Check Point Log Exporter Administration Guide - Appendix B (epoch time, update logs and loguid)",
     "https://sc1.checkpoint.com/documents/Log_Exporter/EN/Content/Topics/"
     "Appendix_B_Additional_Information.htm"),
    ("Check Point sk144192 - Description of Fields in Check Point Logs",
     "https://support.checkpoint.com/results/sk/sk144192"),
)

# The wrapper, as observed in the real export (no ManageEngine document).
ELA_PREAMBLE = "Search Results"
ELA_SIGNATURE = ("#", "Message", "LogType", "Device", "Time", "Host Type")
ELA_COLUMN = "Message"

# One field: a Check Point field name, `:`, a quoted value with backslash
# escapes. Matched left to right without overlap, so text inside a value (the
# `__policy_id_tag` value holds `;` and `=`) is never read as a field.
FIELD_PATTERN = r'([A-Za-z0-9_.-]+):"((?:[^"\\]|\\.)*)"'
_FIELD = re.compile(FIELD_PATTERN)
_UNESCAPE = re.compile(r"\\(.)")

# Canonical field -> Log Exporter field(s), first non-empty wins (sk144192).
FIELDS = {
    "ts": ("time",),                    # "The timestamp when the log was created" - epoch
    "srcip": ("src",),                  # "Client source IP address"
    "dstip": ("dst",),                  # "Destination IP address"
    "dstport": ("service",),            # "Connection (service) destination port"
    "username": ("src_user_name", "user"),  # "Username connected to the source IP"; "Source username"
    "verdict": ("action",),             # "Action of matched rule"
    "app": ("appi_name", "service_id"),  # "Application name"; "Service found for the connection"
    "risk": ("app_risk",),              # "Application risk", 0 Unknown - 5 Critical
    "bytes_sent": ("client_outbound_bytes",),  # "Number of bytes sent from the client"
}

# sk144192's action values that are traffic decisions -> canonical verdicts.
# Prevent is not in sk144192's list but is a documented filter value of
# cp_log_export (R81 CLI Reference) and the SmartConsole profile's spelling.
# Key Install (a VPN key exchange) and Log Out are not traffic decisions:
# empty means "not a verdict", as in the SmartConsole profile (gotcha #43).
VERDICTS = {"accept": "allow", "allow": "allow", "drop": "drop", "reject": "reject",
            "block": "block", "detect": "detect", "prevent": "prevent",
            "key install": "", "log out": ""}

NOTES = (
    "The record is Check Point's (documented); the EventLog Analyzer wrapper around it is "
    "observed in a real export - ManageEngine publishes no layout for it.",
    "Time is Check Point's `time` (Unix epoch, UTC), not EventLog Analyzer's `Time` column.",
    "Update logs of one connection share a `loguid`: only the first carries the verdict, the "
    "others are typed `log_update` (Log Exporter guide, Appendix B).",
    "Not mapped (no canonical column yet; kept in the raw record): NAT (`xlatesrc`, `xlatedst`), "
    "`origin`, `product`, `src_machine_name`, `rule_name`.",
)


def unescape(value: str) -> str:
    return _UNESCAPE.sub(r"\1", value)


def parse_body(text: str | None) -> dict[str, str]:
    """The fields of one Log Exporter syslog body, unescaped. {} when the text
    holds no body (no `[`)."""
    if not text or "[" not in text:
        return {}
    body = text[text.index("[") + 1:]
    return {name: unescape(value) for name, value in _FIELD.findall(body)}


def is_record(fields: dict[str, str]) -> bool:
    """A Log Exporter record names the gateway that reported it and its log id."""
    return "loguid" in fields and "origin" in fields


def identify_ela(path: Path, sample: int = 200) -> tuple[str, str] | None:
    """For a CSV whose first line is `Search Results`: ("record", evidence)
    when it is EventLog Analyzer's export of Log Exporter records,
    ("other", evidence) when it is that export of something else, None when it
    is not that export at all."""
    try:
        with parsers.open_text(path, newline="") as fh:
            rows = csv.reader(fh)
            first = next(rows, [])
            if [c.strip() for c in first if c.strip()] != [ELA_PREAMBLE]:
                return None
            header = [h.strip() for h in next(rows, [])]
            if not all(c in header for c in ELA_SIGNATURE):
                return None
            col = header.index(ELA_COLUMN)
            messages = [r[col] for r in islice(rows, sample) if len(r) > col]
    except (OSError, UnicodeError, csv.Error, StopIteration):
        return None
    records = sum(1 for m in messages if is_record(parse_body(m)))
    if messages and records * 2 > len(messages):
        return "record", (f"EventLog Analyzer search export (observed layout); {records} of the first "
                          f"{len(messages)} Message values are Log Exporter syslog records "
                          f"(documented format)")
    return "other", (f"EventLog Analyzer search export (observed layout), but {records} of the first "
                     f"{len(messages)} Message values are Log Exporter records - no reader for the rest")


def _sql_str(s: str) -> str:
    return "'" + s.replace("'", "''") + "'"


def ingest_sql(con, path: Path, start: int = 0, encoding: str = "utf-8-sig") -> tuple[int, dict]:
    """Read the export into raw_events with row ids from `start`. Returns
    (rows added, the manifest's mapping)."""
    enc_opt = ", encoding='utf-16'" if encoding == "utf-16" else ""
    pat = _sql_str(FIELD_PATTERN)

    def field(*names: str) -> str:
        """The first non-empty of these record fields, unescaped."""
        picks = [f"nullif(regexp_replace(v[list_position(k, {_sql_str(n)})], '\\\\(.)', '\\1', 'g'), '')"
                 for n in names]
        return picks[0] if len(picks) == 1 else f"coalesce({', '.join(picks)})"

    verdict_whens = " ".join(f"WHEN {_sql_str(a)} THEN {_sql_str(b)}" for a, b in VERDICTS.items())
    epoch = f"try_cast({field('time')} AS BIGINT)"
    con.execute(
        f"""
        INSERT INTO raw_events
        SELECT
            n - 1 + {start}                                     AS row_id,
            -- time-in-milli (R81 CLI Reference, cp_log_export) writes milliseconds.
            CASE WHEN e IS NULL THEN NULL
                 ELSE to_timestamp(CASE WHEN e > 100000000000 THEN e / 1000.0 ELSE e END)
                      AT TIME ZONE '{config.EVENT_TZ_NAME}' END  AS ts,
            t                                                   AS ts_raw,
            src AS srcip, dst AS dstip, svc AS dstport, usr AS username,
            NULL AS program, NULL AS hostname,
            CASE WHEN k > 1 THEN 'log_update' END               AS action,
            CASE WHEN k > 1 THEN NULL
                 ELSE NULLIF(CASE lower(trim(act)) {verdict_whens} ELSE lower(trim(act)) END, '')
            END                                                 AS verdict,
            app, try_cast(risk AS INTEGER) AS risk, try_cast(bytes AS BIGINT) AS bytes_sent,
            NULL AS category,
            substr(m, 1, 4000)                                  AS raw
        FROM (
            SELECT *,
                   CASE WHEN loguid IS NULL THEN 1 ELSE
                        row_number() OVER (PARTITION BY loguid ORDER BY e NULLS LAST,
                                           try_cast(seq AS BIGINT) NULLS LAST, n) END AS k
            FROM (
                SELECT n, m,
                       {field('time')} AS t, {epoch} AS e,
                       {field(*FIELDS['srcip'])} AS src, {field(*FIELDS['dstip'])} AS dst,
                       {field(*FIELDS['dstport'])} AS svc, {field(*FIELDS['username'])} AS usr,
                       {field(*FIELDS['verdict'])} AS act, {field(*FIELDS['app'])} AS app,
                       {field(*FIELDS['risk'])} AS risk, {field(*FIELDS['bytes_sent'])} AS bytes,
                       {field('loguid')} AS loguid, {field('sequencenum')} AS seq
                FROM (
                    SELECT n, m,
                           regexp_extract_all(body, {pat}, 1) AS k,
                           regexp_extract_all(body, {pat}, 2) AS v
                    FROM (
                        SELECT row_number() OVER () AS n, "{ELA_COLUMN}" AS m,
                               CASE WHEN strpos("{ELA_COLUMN}", '[') > 0
                                    THEN substr("{ELA_COLUMN}", strpos("{ELA_COLUMN}", '[') + 1) END AS body
                        FROM read_csv(?, all_varchar=true, header=true, skip=1, sample_size=-1,
                                      delim=','{enc_opt})
                    )
                )
            )
        )
        ORDER BY n
        """,
        [str(path)],
    )
    added, records, updates, connections = con.execute(
        "SELECT count(*), count(*) FILTER (WHERE ts_raw IS NOT NULL OR srcip IS NOT NULL OR verdict IS NOT NULL "
        "OR action IS NOT NULL), count(*) FILTER (WHERE action = 'log_update'), "
        "count(*) FILTER (WHERE action IS NULL AND (ts_raw IS NOT NULL OR srcip IS NOT NULL)) "
        "FROM raw_events WHERE row_id >= ?", [start]).fetchone()
    mapping = {
        "method": "documented",
        "profile": PROFILE_ID,
        "name": NAME,
        "docs": [{"title": t, "url": u} for t, u in DOCS],
        "notes": list(NOTES),
        "fields": {f: {"columns": [f"{ELA_COLUMN}: {n}" for n in names], "source": "documented"}
                   for f, names in FIELDS.items()},
        "heuristic_fields": [],
        "missing_fields": [],
        "wrapper": {"name": "ManageEngine EventLog Analyzer search export", "observed": True,
                    "preamble": ELA_PREAMBLE, "column": ELA_COLUMN},
        # "Unparseable rows counted and reported" (IAI-85 AC).
        "log_exporter": {"rows": added, "records": records, "not_records": added - records,
                         "connections": connections, "log_updates": updates},
    }
    return added, mapping
