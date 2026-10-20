"""What log a file is, decided before anything is read from it (IAI-92).

Every upload is identified automatically and nothing is guessed: a file is
either a documented format this tool reads, a format it recognises but has no
reader for yet, or unrecognised. Only the first is analysed; the other two
are kept as evidence (digest, custody) and the case says which - the user's
call (specs/case_flow_design.md, revision 2, Q8).

The answer is given in the Sigma logsource taxonomy (v2.1.0): category /
product / service where the taxonomy defines them, and a `custom` product
where it does not - it has no firewall vendors, no ESXi and no CrowdStrike
(verified). How each file is recognised:

- a table (CSV, or a .log/.txt whose first line is a documented header) by
  its header, against the documented profiles (logsources.PROFILES);
- JSON by the keys of its first records, the same way;
- a line log by running the documented line decoders over its first lines and
  counting which format each line matched - the same code that later reads it;
- formats with no reader yet by the marker their vendor documents (Cisco's
  "%ASA-<sev>-<id>:" header, the Windows event XML channel) or, where no
  public document exists, the marker observed in a real file (CrowdStrike).

The decision is made on the head of the file only (SAMPLE_BYTES / SAMPLE_LINES),
so identifying a 10 GB file costs the same as a small one.
"""

import csv
import re
from collections import Counter
from itertools import islice
from pathlib import Path

from . import decode, logsources, parsers

SAMPLE_LINES = 2000
SAMPLE_BYTES = 256 * 1024
JSON_RECORDS = 200

SUPPORTED, NO_READER, UNRECOGNISED = "supported", "no_reader", "unrecognised"

# Recognised, not read yet. (marker, logsource, name, basis of the marker)
_LINE_MARKERS = [
    (re.compile(r"%ASA-[0-7]-\d{6}:"), {"sigma": {"category": "firewall"}, "custom": "cisco_asa"},
     "Cisco Secure Firewall ASA syslog",
     "message header %ASA-<severity>-<id>: (Cisco Secure Firewall ASA Series Syslog Messages)"),
    (re.compile(r"%FTD-[0-7]-\d{6}:"), {"sigma": {"category": "firewall"}, "custom": "cisco_ftd"},
     "Cisco Secure Firewall Threat Defense syslog",
     "message header %FTD-<severity>-<id>: (Cisco Secure Firewall Threat Defense Syslog Messages)"),
    (re.compile(r"<Channel>Microsoft-Windows-Sysmon/Operational</Channel>"),
     {"sigma": {"product": "windows", "service": "sysmon"}}, "Windows Sysmon event log (event XML)",
     "event XML with the Microsoft-Windows-Sysmon/Operational channel"),
    (re.compile(r"<Channel>Security</Channel>"), {"sigma": {"product": "windows", "service": "security"}},
     "Windows Security event log (event XML)", "event XML with the Security channel"),
    (re.compile(r"^LogName=Security\s*$", re.M), {"sigma": {"product": "windows", "service": "security"}},
     "Windows Security event log (Splunk WinEventLog text)",
     "LogName=Security record header - Splunk's rendering, not a Windows export format"),
]


def _result(status: str, source: dict | None, name: str | None, evidence: str,
            profile: str | None = None) -> dict:
    source = source or {}
    return {
        "status": status,
        "sigma": dict(source.get("sigma") or {}),
        "custom": source.get("custom"),
        "name": name,
        "profile": profile,
        "evidence": evidence,
        "taxonomy": "Sigma logsource taxonomy v2.1.0",
    }


def identify(path: Path, kind: str) -> dict:
    """`kind` is the file kind the upload decided (csv / json / log)."""
    if kind == "log":
        # The name says nothing reliable: a PAN-OS table saved as .txt
        # (IAI-30), JSON-lines exported as .log (CrowdStrike, eStreamer).
        table = _table(path)
        if table:
            return {**table, "read_as": "csv"}
        if _head_text(path).lstrip()[:1] in ("{", "["):
            return {**_json(path), "read_as": "json"}
        return _lines(path)
    if kind == "csv":
        return _table(path) or _result(UNRECOGNISED, None, None, "the header matches no documented log source")
    if kind == "json":
        return _json(path)
    return _result(UNRECOGNISED, None, None, f"file kind '{kind}' is not read")


def _table(path: Path) -> dict | None:
    try:
        delim = parsers.sniff_delimiter(path)
        with parsers.open_text(path, newline="") as fh:
            header = next(csv.reader(fh, delimiter=delim), [])
    except (OSError, UnicodeError, csv.Error):
        return None
    profile = logsources.match_profile([h.strip() for h in header])
    if profile is None:
        return None
    return _result(SUPPORTED, logsources.LOGSOURCE.get(profile.id), profile.name,
                   "header matches the documented columns", profile.id)


def _json(path: Path) -> dict:
    head = [r for r in islice(parsers.iter_rows(path, "json"), JSON_RECORDS) if "_raw" not in r]
    if not head:
        return _result(UNRECOGNISED, None, None, "no JSON record could be read")
    keys = list(dict.fromkeys(k for r in head for k in r))
    profile = logsources.match_profile(keys)
    if profile:
        return _result(SUPPORTED, logsources.LOGSOURCE.get(profile.id), profile.name,
                       "record keys match the documented fields", profile.id)
    first = head[0]
    if {"event_simpleName", "aid", "cid"} <= set(first):
        return _result(NO_READER, {"sigma": {}, "custom": "crowdstrike_falcon"},
                       "CrowdStrike Falcon sensor events (Falcon Data Replicator)",
                       "records carry event_simpleName, aid and cid - observed in real exports; "
                       "CrowdStrike's own event dictionary needs a Falcon login")
    if first.get("EventType") in ("ConnectionEvent", "IntrusionEvent", "FileEvent", "FileMalwareEvent") \
            and "DeviceUUID" in first:
        return _result(NO_READER, {"sigma": {"category": "firewall"}, "custom": "cisco_ftd"},
                       "Cisco Secure Firewall Threat Defense events (eStreamer JSON)",
                       f"records carry EventType={first['EventType']} and DeviceUUID")
    return _result(UNRECOGNISED, None, None, "record keys match no documented log source")


def _head_text(path: Path) -> str:
    with parsers.open_text(path) as fh:
        return fh.read(SAMPLE_BYTES)


def _lines(path: Path) -> dict:
    """Which documented line format the first lines are, by the decoders that
    will read them. ESXi writes OpenSSH's lines into its auth.log too, so a
    file with any ESXi line is ESXi; otherwise the format most lines matched."""
    counts: Counter = Counter()
    for row in islice(parsers.iter_rows(path, "log"), SAMPLE_LINES):
        counts[decode.decode_line(row["line"]).get("profile")] += 1
    read = {k: v for k, v in counts.items() if k}
    if read:
        esxi = [k for k in read if k.startswith("vmware-esxi")]
        top = "vmware-esxi" if esxi else max(read, key=lambda k: (read[k], k))
        name = (logsources.LINE_PROFILES[top]["name"] if not esxi else "VMware ESXi auth.log")
        evidence = ", ".join(f"{logsources.LINE_PROFILES[k]['name']}: {n}"
                             for k, n in sorted(read.items(), key=lambda kv: -kv[1]))
        return _result(SUPPORTED, logsources.LOGSOURCE.get(top), name,
                       f"{sum(read.values())} of the first {sum(counts.values())} lines read by a "
                       f"documented format ({evidence})", top)
    text = _head_text(path)
    for marker, source, name, basis in _LINE_MARKERS:
        if marker.search(text):
            return _result(NO_READER, source, name, basis)
    return _result(UNRECOGNISED, None, None,
                   f"none of the first {sum(counts.values())} lines matches a documented format")
