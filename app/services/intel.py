"""Offline threat-intelligence indicators.

Files dropped in `DATA_DIR/intel/` are parsed into one canonical indicator
table that the R30xx rules join against. Analysis never touches the network:
feeds are refreshed out-of-band by `tools/refresh_intel.py`, so a case can be
worked on an air-gapped machine and two runs over the same feed files always
produce the same findings - which matters when the output is evidence.

Deliberately format-agnostic rather than one parser per vendor. Public feeds
come as either a comment-prefixed CSV (abuse.ch Feodo, ThreatFox) or a bare
list of addresses (blocklist.de, CINS, Tor exit nodes), and an analyst should
be able to drop in a customer-supplied IOC list without writing code. Anything
that is not an IP address is ignored: the canonical schema has no URL, hash or
domain column to match one against.
"""

import csv
import ipaddress
import logging
import re
from pathlib import Path

from .. import config

log = logging.getLogger(__name__)

# Column names that hold the indicator itself, most specific first (same
# precedence rule as decode._FIELD_CANDIDATES, and for the same reason).
_VALUE_COLUMNS = ["ioc_value", "dst_ip", "ip_address", "indicator", "value",
                  "ip", "address"]
# Columns worth carrying into the finding text, so an analyst reading
# "known-bad indicator" learns *which* malware family without leaving the UI.
_NOTE_COLUMNS = ["malware_printable", "malware", "fk_malware", "threat_type",
                 "c2_status", "description", "note", "tags"]

_IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")


def intel_dir() -> Path:
    return Path(config.DATA_DIR) / "intel"


def staging_path() -> Path:
    return Path(config.DATA_DIR) / "tmp" / "ioc_indicators.csv"


def _clean_ip(value: str) -> str | None:
    """Accept "1.2.3.4", "1.2.3.4:443" and "name (1.2.3.4)"; reject the rest."""
    if not value:
        return None
    match = _IP_RE.search(value)
    if not match:
        return None
    try:
        ip = ipaddress.ip_address(match.group(0))
    except ValueError:
        return None
    # A feed listing private space would flag every internal flow in a case.
    if ip.is_private or ip.is_loopback or ip.is_multicast or ip.is_unspecified:
        return None
    return str(ip)


def _parse_csv(path: Path, source: str) -> list[tuple[str, str, str, str]]:
    """abuse.ch style: '#' banner lines, the header repeated as a comment,
    then quoted rows. Take the header from the last commented line that looks
    like one, or from the first uncommented line."""
    header: list[str] | None = None
    data_lines: list[str] = []
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            stripped = line.strip()
            if not stripped:
                continue
            if stripped.startswith("#"):
                candidate = stripped.lstrip("#").strip()
                if any(c in candidate.lower() for c in _VALUE_COLUMNS):
                    header = next(csv.reader([candidate]))
                continue
            data_lines.append(line)

    if not data_lines:
        return []
    if header is None:
        header = [h.strip() for h in next(csv.reader([data_lines.pop(0)]))]

    header = [h.strip().strip('"').lower() for h in header]
    value_col = next((c for c in _VALUE_COLUMNS if c in header), None)
    if value_col is None:
        return []
    note_cols = [c for c in _NOTE_COLUMNS if c in header]

    out = []
    for row in csv.reader(data_lines):
        if not row:
            continue
        record = {h: (v.strip().strip('"') if isinstance(v, str) else v)
                  for h, v in zip(header, row)}
        ip = _clean_ip(record.get(value_col, ""))
        if not ip:
            continue
        notes = [record[c] for c in note_cols
                 if record.get(c) and record[c].lower() not in ("none", "null", "")]
        out.append((ip, "ip", source, ", ".join(dict.fromkeys(notes))[:120]))
    return out


def _parse_list(path: Path, source: str) -> list[tuple[str, str, str, str]]:
    """One indicator per line, '#' comments - blocklist.de, CINS, Tor."""
    out = []
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            ip = _clean_ip(line.split()[0])
            if ip:
                out.append((ip, "ip", source, ""))
    return out


def load_indicators() -> list[tuple[str, str, str, str]]:
    """Every indicator across every feed file, de-duplicated by address.

    The first feed to mention an address wins its note, so a specific
    attribution ("QakBot") is not overwritten by a bare blocklist entry;
    feeds are read in filename order to keep that deterministic.
    """
    directory = intel_dir()
    if not directory.is_dir():
        return []

    seen: dict[str, tuple[str, str, str, str]] = {}
    for path in sorted(directory.iterdir()):
        if not path.is_file() or path.suffix.lower() not in (".csv", ".txt", ".list"):
            continue
        source = path.stem
        try:
            rows = (_parse_csv(path, source) if path.suffix.lower() == ".csv"
                    else _parse_list(path, source))
        except (OSError, csv.Error):
            log.warning("intel: could not parse %s", path, exc_info=True)
            continue
        for row in rows:
            seen.setdefault(row[0], row)
        log.info("intel: %s -> %s indicators", path.name, len(rows))
    return list(seen.values())


def build_staging() -> tuple[Path | None, int]:
    """Normalise every feed into one CSV that DuckDB can bulk-load.

    Rebuilt only when a feed file is newer than the staging file: parsing
    25k+ lines per case would be pure waste, and DuckDB's executemany is far
    too slow to insert them row by row (CLAUDE.md gotcha #1).
    """
    directory = intel_dir()
    staging = staging_path()
    if not directory.is_dir():
        return None, 0

    feeds = [p for p in directory.iterdir()
             if p.is_file() and p.suffix.lower() in (".csv", ".txt", ".list")]
    if not feeds:
        return None, 0

    newest = max(p.stat().st_mtime for p in feeds)
    if staging.exists() and staging.stat().st_mtime >= newest:
        with open(staging, encoding="utf-8") as fh:
            return staging, sum(1 for _ in fh)

    indicators = load_indicators()
    if not indicators:
        return None, 0

    staging.parent.mkdir(parents=True, exist_ok=True)
    with open(staging, "w", encoding="utf-8", newline="") as fh:
        csv.writer(fh).writerows(indicators)
    log.info("intel: staged %s indicators", len(indicators))
    return staging, len(indicators)


def create_table(con) -> None:
    """Always create `ioc`, even with no feeds present, so the rules that
    join it are valid SQL on every case."""
    con.execute("""
        CREATE TABLE IF NOT EXISTS ioc (
          value  VARCHAR,
          type   VARCHAR,
          source VARCHAR,
          note   VARCHAR
        )
    """)


def fill(con) -> int:
    """Load the indicators this case can actually match, after ingest.

    Only indicators whose address appears in the case's own traffic are
    inserted. Storing all ~43k in all 93 case files took ingest from 18s to
    52s and inflated every DuckDB file for nothing; the semi-join costs one
    scan and leaves a handful of rows behind. The rules are unchanged either
    way - an indicator nobody talked to cannot produce a finding.
    """
    create_table(con)
    staging, count = build_staging()
    if staging is None or not count:
        return 0

    # Measured on the largest case (65,534 rows): 13ms to read the CSV and
    # semi-join it. A Parquet copy was tried and dropped - it saved 5ms per
    # case, which is noise next to the upload itself, and cost a second
    # generated file to keep in sync.
    con.execute(
        """
        INSERT INTO ioc
        SELECT * FROM read_csv(?, header=false, nullstr='',
                               columns={'value': 'VARCHAR', 'type': 'VARCHAR',
                                        'source': 'VARCHAR', 'note': 'VARCHAR'})
        WHERE value IN (SELECT srcip FROM raw_events WHERE srcip IS NOT NULL
                        UNION
                        SELECT dstip FROM raw_events WHERE dstip IS NOT NULL)
        """,
        [str(staging)],
    )
    return con.execute("SELECT count(*) FROM ioc").fetchone()[0]
