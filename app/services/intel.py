"""Offline threat-intelligence indicators.

Files dropped in `DATA_DIR/intel/` are parsed into one canonical indicator
table that the R30xx rules join against. Analysis never touches the network:
feeds are refreshed out-of-band by `tools/refresh_intel.py`, so a case can be
worked on an air-gapped machine and two runs over the same feed files always
produce the same findings - which matters when the output is evidence.

Deliberately format-agnostic rather than one parser per feed. Public feeds
come as either a comment-prefixed CSV (abuse.ch Feodo, ThreatFox) or a bare
list of addresses (blocklist.de, CINS, Tor exit nodes), and an analyst should
be able to drop in a customer-supplied IOC list without writing code. A
`.json` file is read as a STIX 2.1 bundle (OASIS) - the standard form a TAXII
collection, OpenCTI or MISP exports - see _parse_stix(). Anything
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

# Feed files read from DATA_DIR/intel. One list, used both to parse and to
# decide whether the staging file is stale - a second copy once left .json
# feeds parsed but never staged.
FEED_SUFFIXES = (".csv", ".txt", ".list", ".json")


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


# One comparison inside a STIX pattern: an IP SCO's value tested for equality.
_STIX_IP_CMP = re.compile(r"(ipv4-addr|ipv6-addr):value\s*=\s*'([^']+)'")
# Anything that makes a pattern mean more than "this address": other object
# paths, AND / FOLLOWEDBY, inequality and set operators, qualifiers.
_STIX_OTHER = re.compile(
    r"\bAND\b|\bFOLLOWEDBY\b|\bWITHIN\b|\bREPEATS\b|\bSTART\b|\bSTOP\b|"
    r"!=|<|>|\bLIKE\b|\bMATCHES\b|\bISSUBSET\b|\bISSUPERSET\b|\bIN\b|\bNOT\b"
)


def _stix_ip(value: str) -> str | None:
    """A STIX ipv4/ipv6 value - possibly with a /32 or /128 - as a public
    host address; a wider CIDR has no single row to match and is skipped."""
    host, _, prefix = value.strip().partition("/")
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return None
    if prefix and (not prefix.isdigit() or int(prefix) != ip.max_prefixlen):
        return None
    if ip.is_private or ip.is_loopback or ip.is_multicast or ip.is_unspecified:
        return None
    return str(ip)


def _parse_stix(path: Path, source: str) -> list[tuple[str, str, str, str]]:
    """A STIX 2.1 (or 2.0) bundle - what a TAXII client, OpenCTI or MISP
    exports. Only `indicator` objects whose pattern is nothing but IP
    equality comparisons joined by OR are taken: a pattern that also
    constrains a port, a time window or anything else would be widened into
    "this address, always" by keeping just the IP, and is skipped instead.
    Revoked indicators are skipped. `valid_until` is quoted in the note but
    does not filter: comparing it to the clock would make two runs over the
    same feed file give different findings."""
    import json

    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    objects = data.get("objects", []) if isinstance(data, dict) and data.get("type") == "bundle" \
        else data if isinstance(data, list) else [data]
    names = {o.get("id"): o.get("name") for o in objects
             if isinstance(o, dict) and o.get("type") == "identity"}
    out, skipped = [], 0
    for o in objects:
        if not isinstance(o, dict) or o.get("type") != "indicator" or o.get("revoked"):
            continue
        pattern = o.get("pattern") or ""
        if o.get("pattern_type", "stix") != "stix":
            skipped += 1
            continue
        hits = _STIX_IP_CMP.findall(pattern)
        rest = _STIX_IP_CMP.sub("", pattern)
        if not hits or _STIX_OTHER.search(rest) or re.search(r"[a-z0-9-]+:[a-z_.]+", rest):
            skipped += 1
            continue
        note = ", ".join(p for p in [
            o.get("name"),
            "/".join(o.get("indicator_types") or o.get("labels") or []),
            f"confidence {o['confidence']}" if "confidence" in o else None,
            f"valid until {o['valid_until'][:10]}" if o.get("valid_until") else None,
        ] if p)[:120]
        src = names.get(o.get("created_by_ref")) or source
        for _, value in hits:
            ip = _stix_ip(value)
            if ip:
                out.append((ip, "ip", src, note))
    if skipped:
        log.info("intel: %s - %s STIX indicator(s) skipped: not plain IP equality", path.name, skipped)
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
        suffix = path.suffix.lower()
        if not path.is_file() or suffix not in FEED_SUFFIXES:
            continue
        source = path.stem
        try:
            rows = (_parse_csv(path, source) if suffix == ".csv"
                    else _parse_stix(path, source) if suffix == ".json"
                    else _parse_list(path, source))
        except (OSError, csv.Error, ValueError):
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
             if p.is_file() and p.suffix.lower() in FEED_SUFFIXES]
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

    # The dialect is stated, not sniffed: build_staging() wrote this file with
    # csv.writer, so it is known. Sniffing guessed it right on DuckDB 1.1.3 and
    # wrong on 1.5.x - the first quoted field (a ThreatFox note with commas)
    # sits past the sniffer's sample, so it chose no quote character and every
    # case failed on that row (CLAUDE.md gotcha #39).
    # Measured on the largest case (65,534 rows): 13ms to read the CSV and
    # semi-join it. A Parquet copy was tried and dropped - it saved 5ms per
    # case, which is noise next to the upload itself, and cost a second
    # generated file to keep in sync.
    con.execute(
        """
        INSERT INTO ioc
        SELECT * FROM read_csv(?, header=false, nullstr='',
                               columns={'value': 'VARCHAR', 'type': 'VARCHAR',
                                        'source': 'VARCHAR', 'note': 'VARCHAR'},
                               auto_detect=false, delim=',', quote='"', escape='"')
        WHERE value IN (SELECT srcip FROM raw_events WHERE srcip IS NOT NULL
                        UNION
                        SELECT dstip FROM raw_events WHERE dstip IS NOT NULL)
        """,
        [str(staging)],
    )
    return con.execute("SELECT count(*) FROM ioc").fetchone()[0]
