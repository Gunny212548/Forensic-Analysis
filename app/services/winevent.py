"""Windows event logs - the core every container shares (W1, specs/windows_event_logs.md).

Every Windows format carries the same event (Microsoft's Event schema,
`SystemPropertiesType` / `EventDataType`, read 2026-10-21): a `System` block -
Provider, EventID, TimeCreated/@SystemTime, EventRecordID, Channel, Computer,
Security/@UserID - and the event's own items, named `<Data Name='...'>` in
`EventData` or nested elements under `UserData` (1102 writes
`UserData/LogFileCleared`). This module turns one such event into

- a **native row** for `win_events`: the System values and every item under
  its own name. These are the names SigmaHQ rules match on (ADR-006
  decision 2), so they are kept exactly as Windows wrote them;
- a **timeline row** for `raw_events`, through the canonical mapping below.

W1 reads **event XML** (`wevtutil qe /f:xml`, `Get-WinEvent` `.ToXml()`,
Splunk's `XmlWinEventLog`): back-to-back `<Event>` elements with no root,
an event free to span lines (4672's PrivilegeList holds newlines). Events are
cut out of the stream at `</Event>` and parsed one at a time, so a damaged
event is counted and kept as text, never fatal and never dropped. Later
containers (Splunk text, JSON, Event Viewer CSV) feed the same
`parse_event()` / `timeline_row()`.

W2 reads **.evtx** (Event Viewer "Save All Events As", `wevtutil epl`, a copy
of `winevt\\Logs`): the `evtx` library (pyevtx-rs, MIT - Q42) renders each
record's Binary XML as event XML, which goes through `parse_event()` like W1.
The library drops what it cannot decode **without saying so** (measured: a
damaged chunk lost 138 of its 158 records, a cut file its last 165, no error
either time), so every record is accounted for against the chunk headers
(libyal's EVTX format document: a 4096-byte file header, then chunks of
65,536 bytes, each `ElfChnk\\0` + the first and last event record identifier
it holds): what a chunk says it holds and was not returned is counted as
unreadable, and named, never dropped.

Event types (layer A, D12) are named from each event's Microsoft page
(Security) and the event headings of the Sysmon page; an event not listed has
no type and is shown as "Windows event <id> (<provider>)" - never guessed.
Which Sysmon item names feed the canonical columns is **observed** in the
events themselves (their `Data Name` attributes): the Sysmon page lists the
events but not their fields.
"""

import bisect
import functools
import gzip
import io
import json
import os
import re
import struct
import tempfile
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from xml.etree import ElementTree

from .. import config
from . import parsers

NS = "http://schemas.microsoft.com/win/2004/08/events/event"
_NS = "{" + NS + "}"
# Any event XML: the Event element in Microsoft's event namespace.
MARKER = re.compile(r"<Event\s+xmlns=['\"]" + re.escape(NS) + r"['\"]")
_START = re.compile(r"<Event[\s>]")
_END = "</Event>"
CHUNK = 1024 * 1024
MAX_EVENT = 4 * 1024 * 1024  # one event this large is damage, not data

PROFILE_ID = "windows-event-xml"
NAME = "Windows event log (event XML)"
DOCS = (
    ("Microsoft - Windows Event schema: SystemPropertiesType",
     "https://learn.microsoft.com/en-us/windows/win32/wes/eventschema-systempropertiestype-complextype"),
    ("Microsoft - Windows Event schema: EventDataType",
     "https://learn.microsoft.com/en-us/windows/win32/wes/eventschema-eventdatatype-complextype"),
    ("Microsoft - Security auditing events (event-<id> pages, e.g. 4624, 4625, 4688)",
     "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/"
     "threat-protection/auditing/event-4624"),
    ("Microsoft Sysinternals - Sysmon (events 1-29)",
     "https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon"),
)

# .evtx (W2) - libyal's EVTX format document: file header, then 64 KB chunks.
EVTX_MAGIC = b"ElfFile\x00"
EVTX_CHUNK_MAGIC = b"ElfChnk\x00"
EVTX_HEADER = 4096
EVTX_CHUNK = 65536
_MAX_RECORDS = (EVTX_CHUNK - 512) // 28
EVTX_PROFILE_ID = "windows-evtx"
EVTX_NAME = "Windows event log (.evtx)"
EVTX_DOCS = (
    ("libyal - Windows XML Event Log (EVTX) format",
     "https://github.com/libyal/libevtx/blob/main/documentation/"
     "Windows%20XML%20Event%20Log%20(EVTX).asciidoc"),
    ("evtx (pyevtx-rs) - the reader that renders each record's Binary XML",
     "https://github.com/omerbenamram/pyevtx-rs"),
    *DOCS,
)

# Splunk's classic WinEventLog text (W3) - observed: Splunk's docs refuse
# automated access. A record is a time line, `LogName=` and the other header
# lines, then `Message=` and the rendered message.
_SPLUNK_TIME = re.compile(r"^\d{2}/\d{2}/\d{4} \d{1,2}:\d{2}:\d{2} [AP]M\s*$")
SPLUNK_PROFILE_ID = "windows-splunk-text"
SPLUNK_NAME = "Windows event log (Splunk WinEventLog text)"
SPLUNK_DOCS = (
    ("Microsoft - ProviderMetadata.Events: each event's message template and data item names "
     "(exported to app/data/windows by tools/export_win_templates.ps1)",
     "https://learn.microsoft.com/en-us/dotnet/api/"
     "system.diagnostics.eventing.reader.providermetadata.events"),
    *DOCS,
)
_TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "data" / "windows"

# JSON (W4): the shapes two shippers write. Winlogbeat / Elastic Agent nest the
# event under `winlog` (Elastic's exported fields); NXLog's im_msvistalog puts
# its own fields and the event's items side by side at the top (NXLog Agent
# reference, "Fields").
WINLOGBEAT_PROFILE_ID = "windows-winlogbeat-json"
WINLOGBEAT_NAME = "Windows event log (Winlogbeat / Elastic JSON)"
WINLOGBEAT_DOCS = (
    ("Elastic - Winlogbeat exported fields: winlog",
     "https://www.elastic.co/guide/en/beats/winlogbeat/current/exported-fields-winlog.html"),
    *DOCS,
)
NXLOG_PROFILE_ID = "windows-nxlog-json"
NXLOG_NAME = "Windows event log (NXLog im_msvistalog JSON)"
NXLOG_DOCS = (
    ("NXLog Agent reference - im_msvistalog fields",
     "https://docs.nxlog.co/agent/current/im/msvistalog.html"),
    *DOCS,
)
# NXLog's own fields (its reference, v5.11 and current), its core fields and two in its
# own output sample (ExecutionThreadID, EventData); `Task` is observed in the OTRF
# datasets' NXLog records, not listed. What is left of a record is the event's items.
_NXLOG_FIELDS = frozenset({
    "raw_event", "AccountName", "AccountType", "ActivityID", "Category", "Channel", "Domain",
    "ERROR_EVT_UNRESOLVED", "EventID", "EventTime", "EventType", "EventXML", "ExecutionProcessID",
    "Hostname", "Keywords", "Level", "LevelValue", "Message", "Opcode", "OpcodeValue",
    "ProviderGuid", "RecordNumber", "RelatedActivityID", "Severity", "SeverityValue", "SourceName",
    "TaskValue", "ThreadID", "UserID", "Version",
    "EventReceivedTime", "SourceModuleName", "SourceModuleType",
    "ExecutionThreadID", "EventData", "Task",
})
# What Logstash adds when it forwards a record (its event fields; host / port from its
# tcp input, as in the OTRF datasets).
_LOGSTASH_FIELDS = frozenset({"@timestamp", "@version", "tags", "host", "port"})

# Channel -> Sigma logsource (taxonomy v2.1.0). Any other channel is
# product windows with the channel named.
CHANNELS = {
    "Security": {"sigma": {"product": "windows", "service": "security"}},
    "Microsoft-Windows-Sysmon/Operational": {"sigma": {"product": "windows", "service": "sysmon"}},
    "System": {"sigma": {"product": "windows", "service": "system"}},
    "Application": {"sigma": {"product": "windows", "service": "application"}},
}
_CHANNEL_NAMES = {c.lower(): c for c in CHANNELS}


def channel_name(name: str) -> str:
    """A channel as Windows names it: channel names are not case-sensitive, and
    some shippers lower-case them (OTRF's NXLog records hold both `security` and
    `Security`)."""
    return _CHANNEL_NAMES.get(name.strip().lower(), name.strip())

SECURITY = "Microsoft-Windows-Security-Auditing"
SYSMON = "Microsoft-Windows-Sysmon"

# Security events -> event type (each from the event's own Microsoft page).
SECURITY_TYPES = {
    4624: "auth_success",            # "a logon session is created"
    4625: "auth_failed",             # "any logon failure"
    4648: "explicit_credentials",    # "an account logon by explicitly specifying that account's credentials"
    4672: "special_privileges",      # "sensitive privileges are assigned to the new logon session"
    4688: "process_created",         # "every time a new process starts"
    4697: "service_installed",       # "new service was installed in the system"
    4698: "scheduled_task_created",  # "a new scheduled task is created"
    4720: "account_created",         # "a new user object is created"
    4740: "account_locked_out",      # "a user account is locked out"
    4768: "kerberos_tgt",            # "issues a Kerberos Ticket Granting Ticket"
    4769: "kerberos_service_ticket",  # "gets a Kerberos Ticket Granting Service (TGS) ticket request"
    # Typed, not counted as sign-in failures (Q41): a pre-auth failure and an
    # NTLM validation are not the logon failure 4625 is, and a DC can log them
    # beside it for the same attempt.
    4771: "kerberos_preauth_failed",  # "fails to issue a Kerberos Ticket Granting Ticket"
    4776: "ntlm_validation",         # "a credential validation occurs using NTLM authentication"
    4778: "session_reconnected",     # "reconnects to an existing Terminal Services session"
    4779: "session_disconnected",    # "disconnects from an existing Terminal Services session"
    5140: "share_accessed",          # "network share object was accessed"
    5145: "share_object_checked",    # "checked to see whether client can be granted desired access"
    1102: "audit_log_cleared",       # "Windows Security audit log was cleared"
}

# Sysmon event IDs -> event type, from the event headings of the Sysmon page.
SYSMON_TYPES = {
    1: "process_created", 2: "file_time_changed", 3: "network_connection",
    4: "sysmon_state_changed", 5: "process_terminated", 6: "driver_loaded", 7: "image_loaded",
    8: "create_remote_thread", 9: "raw_access_read", 10: "process_access", 11: "file_created",
    12: "registry_object_create_delete", 13: "registry_value_set", 14: "registry_renamed",
    15: "file_stream_hash", 16: "sysmon_config_changed", 17: "pipe_created", 18: "pipe_connected",
    19: "wmi_filter", 20: "wmi_consumer", 21: "wmi_binding", 22: "dns_query",
    23: "file_deleted_archived", 24: "clipboard_changed", 25: "process_tampering",
    26: "file_deleted", 27: "file_block_executable", 28: "file_block_shredding",
    29: "file_executable_detected", 255: "sysmon_error",
}

# Event type -> what the timeline shows (merged into db.EVENT_TYPES).
TYPE_NAMES = {
    "explicit_credentials": "Logon with explicit credentials",
    "special_privileges": "Special privileges assigned to logon",
    "process_created": "Process created",
    "service_installed": "Service installed",
    "scheduled_task_created": "Scheduled task created",
    "account_created": "Account created",
    "account_locked_out": "Account locked out",
    "kerberos_tgt": "Kerberos TGT issued",
    "kerberos_service_ticket": "Kerberos service ticket requested",
    "kerberos_preauth_failed": "Kerberos pre-authentication failed",
    "ntlm_validation": "NTLM credential validation",
    "session_reconnected": "Session reconnected",
    "session_disconnected": "Session disconnected",
    "share_accessed": "Network share accessed",
    "share_object_checked": "Network share object checked",
    "audit_log_cleared": "Security audit log cleared",
    "file_time_changed": "File creation time changed",
    "network_connection": "Network connection",
    "sysmon_state_changed": "Sysmon service state changed",
    "process_terminated": "Process terminated",
    "driver_loaded": "Driver loaded",
    "image_loaded": "Image loaded",
    "create_remote_thread": "Remote thread created",
    "raw_access_read": "Raw disk access read",
    "process_access": "Process accessed",
    "file_created": "File created",
    "registry_object_create_delete": "Registry key created or deleted",
    "registry_value_set": "Registry value set",
    "registry_renamed": "Registry key or value renamed",
    "file_stream_hash": "File stream created",
    "sysmon_config_changed": "Sysmon configuration changed",
    "pipe_created": "Named pipe created",
    "pipe_connected": "Named pipe connected",
    "wmi_filter": "WMI event filter",
    "wmi_consumer": "WMI event consumer",
    "wmi_binding": "WMI consumer bound to filter",
    "dns_query": "DNS query",
    "file_deleted_archived": "File deleted (archived)",
    "clipboard_changed": "Clipboard changed",
    "process_tampering": "Process image tampered",
    "file_deleted": "File deleted",
    "file_block_executable": "Executable file blocked",
    "file_block_shredding": "File shredding blocked",
    "file_executable_detected": "Executable file detected",
    "sysmon_error": "Sysmon error",
}

# 4624's LogonType table (Microsoft, event 4624).
LOGON_TYPES = {"0": "System", "2": "Interactive", "3": "Network", "4": "Batch", "5": "Service",
               "7": "Unlock", "8": "NetworkCleartext", "9": "NewCredentials",
               "10": "RemoteInteractive", "11": "CachedInteractive",
               "12": "CachedRemoteInteractive", "13": "CachedUnlock"}

# Item names that carry the canonical values, first non-empty wins.
_USER = ("TargetUserName", "SubjectUserName", "User", "AccountName")
# 4778 / 4779 name the client ClientAddress, "LOCAL" for the console (their page).
_SRCIP = ("IpAddress", "SourceIp", "ClientAddress")
_PROCESS = ("NewProcessName", "Image", "ProcessName")
# Shown first in `raw` - what the analyst reads first.
_FIRST = ("CommandLine", "ParentCommandLine", "NewProcessName", "Image", "ParentImage",
          "ParentProcessName", "TargetUserName", "SubjectUserName", "User", "IpAddress",
          "SourceIp", "DestinationIp", "DestinationPort", "QueryName", "TargetFilename",
          "TargetObject", "ServiceName", "ServiceFileName", "TaskName", "LogonType")
_EMPTY = {"", "-", "NULL SID"}
_GMT7 = timezone(timedelta(hours=config.EVENT_TZ_OFFSET_HOURS))


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def is_event_xml(head: str) -> bool:
    return bool(MARKER.search(head))


def channels_in(head: str) -> list[str]:
    return re.findall(r"<Channel>([^<]*)</Channel>", head)


def iter_event_texts(path: Path, progress=None) -> Iterator[str]:
    """Each `<Event>...</Event>` of a file, as text, in order. Text between
    events (an XML declaration, a wrapping `<Events>` element, whitespace) is
    skipped. An event cut short ends where the next one begins, and one that
    never ends (or passes MAX_EVENT) is yielded as is - either way it is
    counted as damaged, never fatal. Scans by position, not by slicing, so
    the cost is linear in the file however many events a chunk holds."""
    report = parsers._reporter(path, progress)
    buf, pos = "", 0
    with parsers.open_text(path) as fh:
        while True:
            chunk = fh.read(CHUNK)
            buf = buf[pos:] + chunk
            pos = 0
            while True:
                start = _START.search(buf, pos)
                if not start:
                    pos = max(pos, len(buf) - 16)  # a tag may straddle the chunk edge
                    break
                s = start.start()
                end = buf.find(_END, s)
                nxt = _START.search(buf, s + 1)
                if nxt and (end < 0 or nxt.start() < end):
                    yield buf[s:nxt.start()]
                    pos = nxt.start()
                    continue
                if end < 0:
                    if chunk and len(buf) - s <= MAX_EVENT:
                        pos = s  # wait for the rest of it
                        break
                    yield buf[s:]
                    pos = len(buf)
                    break
                yield buf[s:end + len(_END)]
                pos = end + len(_END)
            if not chunk:
                break
            if report:
                report(fh)


# Characters XML 1.0 does not allow, which Windows still writes into a value
# (measured: garbage bytes in 4661's PrivilegeList). In event XML from any other
# tool they are parsed through a private-use stand-in and put back, so the value
# is kept as written.
_ILLEGAL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")
_STAND_IN = 0xF0000


def _restore(s: str | None) -> str | None:
    return s and "".join(chr(ord(c) - _STAND_IN) if _STAND_IN <= ord(c) < _STAND_IN + 32 else c
                         for c in s)


# The evtx library renders an empty value as the line break and indent of its
# closing tag (Windows: empty). A value of only "\r" (seen in a Sysmon
# SourceImage) is real and kept.
_LIB_EMPTY = re.compile(r"^\n {2,}$")


def parse_event(text: str, fixes: dict[str, str] | None = None,
                empty_in_array: bool = False) -> dict | None:
    """One event's System values and items, or None when it does not parse.
    `fixes`: an .evtx record rendered by the evtx library - its GUID, FILETIME
    and SYSTEMTIME values put in the form Windows renders them (evtx_typed_values),
    and empty values made empty; `empty_in_array` from the same record."""
    illegal = bool(_ILLEGAL.search(text))
    if illegal and fixes is not None:
        # Windows' own rendering (EvtRender, as `Get-WinEvent .ToXml()` shows
        # it) writes such a character as "_": the .evtx gives what event XML of
        # the same event would.
        text, illegal = _ILLEGAL.sub("_", text), False
    if illegal:
        text = _ILLEGAL.sub(lambda m: chr(_STAND_IN + ord(m.group())), text)
    try:
        root = ElementTree.fromstring(text)
    except ElementTree.ParseError:
        return None
    if illegal:
        for el in root.iter():
            el.text = _restore(el.text)
    system = root.find(_NS + "System")
    if system is None:
        return None

    def sys(tag: str, attr: str | None = None) -> str | None:
        el = system.find(_NS + tag)
        if el is None:
            return None
        return el.get(attr) if attr else (el.text or "").strip() or None

    data: dict[str, str] = {}
    event_data = root.find(_NS + "EventData")
    if event_data is not None:
        i = 0
        for d in event_data.findall(_NS + "Data"):
            if fixes is not None and not empty_in_array and not d.get("Name") \
                    and _LIB_EMPTY.match(d.text or ""):
                # A null value, which the library renders as an empty unnamed
                # item and Windows leaves out (EventLog 6005/6006). An empty
                # string in an array looks the same and Windows keeps it, so a
                # record holding one keeps every such item.
                continue
            i += 1
            # An unnamed item gets Winlogbeat's documented name, param<n>.
            data[d.get("Name") or f"param{i}"] = (d.text or "")
    user_data = root.find(_NS + "UserData")
    if user_data is not None:
        for holder in user_data:
            for child in holder:
                data[_local(child.tag)] = (child.text or "")
    time_created = sys("TimeCreated", "SystemTime")
    if fixes is not None:
        data = {k: "" if _LIB_EMPTY.match(v) else fixes.get(v, v) for k, v in data.items()}
        time_created = fixes.get(time_created, time_created)
    try:
        event_id = int(sys("EventID") or "")
    except ValueError:
        event_id = None
    return {
        "provider": (system.find(_NS + "Provider").get("Name")
                     if system.find(_NS + "Provider") is not None else None),
        "event_id": event_id,
        "time_created": time_created,
        "record_id": sys("EventRecordID"),
        "channel": sys("Channel"),
        "computer": sys("Computer"),
        "user_sid": sys("Security", "UserID"),
        "data": data,
    }


def _first(data: dict, names: tuple[str, ...]) -> str | None:
    for n in names:
        v = (data.get(n) or "").strip()
        if v not in _EMPTY:
            return v
    return None


def _when(text: str | None) -> datetime | None:
    """SystemTime (UTC, `...Z`, up to 100 ns), or any ISO time with an
    offset -> naive GMT+7. A time that states no zone (Splunk's `MM/DD/YYYY
    hh:mm:ss AM`, NXLog's `2020-08-07 10:32:22`) is taken as written - GMT+7
    by gotcha #21, flagged timezone-unconfirmed (Q44, Q49)."""
    if not text:
        return None
    m = _SPLUNK_TIME.match(text)
    if m:
        try:
            return datetime.strptime(text.strip(), "%m/%d/%Y %I:%M:%S %p")
        except ValueError:
            return None
    t = text.strip().replace("Z", "+00:00")
    m = re.match(r"^(.*\.\d{6})\d+(\+.*)$", t)  # fromisoformat takes 6 fraction digits
    if m:
        t = m.group(1) + m.group(2)
    try:
        dt = datetime.fromisoformat(t)
    except ValueError:
        return None
    if dt.tzinfo is None:
        return dt  # no zone stated (NXLog's EventTime): as written, gotcha #21 (Q49)
    return dt.astimezone(_GMT7).replace(tzinfo=None)


def event_type(ev: dict) -> str | None:
    if ev["provider"] == SECURITY or (ev["channel"] == "Security" and ev["event_id"] == 1102):
        return SECURITY_TYPES.get(ev["event_id"])
    if ev["provider"] == SYSMON:
        return SYSMON_TYPES.get(ev["event_id"])
    return None


def timeline_row(ev: dict) -> dict:
    """The canonical row for raw_events (the keys decode.decode returns)."""
    d = ev["data"]
    kind = event_type(ev)
    process = _first(d, _PROCESS)
    logon = LOGON_TYPES.get((d.get("LogonType") or "").strip())
    shown = [n for n in _FIRST if n in d] + [n for n in d if n not in _FIRST]
    # One line: the staging CSV takes no line breaks, and the full value (4672's
    # PrivilegeList spans lines) stays as written in win_events.
    body = " · ".join(f"{n}={re.sub(r'\s+', ' ', d[n].strip())}" for n in shown
                      if (d[n] or "").strip() not in _EMPTY)
    srcip = _first(d, _SRCIP)
    return {
        "ts": _when(ev["time_created"]),
        "ts_raw": ev["time_created"],
        "srcip": None if srcip == "LOCAL" else srcip,
        "dstip": _first(d, ("DestinationIp",)),
        "dstport": _first(d, ("DestinationPort",)),
        "username": _first(d, _USER),
        "program": process.replace("/", "\\").rsplit("\\", 1)[-1] if process else None,
        "hostname": ev["computer"],
        "action": kind,
        "verdict": None,
        "app": f"{logon} ({d['LogonType'].strip()})" if logon else None,
        "risk": None,
        "bytes_sent": None,
        "category": None,
        "raw": f"{ev['event_id']} {ev['provider'] or ''}: {body}"[:4000],
    }


def native_row(row_id: int, ev: dict) -> list:
    """A staging row for win_events; `data` as a JSON object."""
    return [row_id, ev["channel"] or "", ev["provider"] or "",
            "" if ev["event_id"] is None else ev["event_id"], ev["record_id"] or "",
            ev["computer"] or "", ev["user_sid"] or "", ev["time_created"] or "",
            json.dumps(ev["data"], ensure_ascii=False)]


def damaged_row(text: str, prefix: str = "[unreadable event XML] ") -> dict:
    """A piece of the file that is not a readable event: kept as text."""
    return {"ts": None, "ts_raw": None, "srcip": None, "dstip": None, "dstport": None,
            "username": None, "program": None, "hostname": None, "action": None, "verdict": None,
            "app": None, "risk": None, "bytes_sent": None, "category": None,
            "raw": (prefix + re.sub(r"\s+", " ", text))[:4000]}


# --- .evtx (W2) -------------------------------------------------------------

@dataclass
class Damage:
    """Part of a container that is not a readable event: the text row it
    becomes, and how many records it stands for (0 when unknown)."""
    text: str
    records: int


def _evtx_parser(source, threads: int = 0):
    # A compiled wheel, imported only where an .evtx is actually read.
    from evtx import PyEvtxParser
    return PyEvtxParser(source, number_of_threads=threads)


def evtx_head_channels(path: Path) -> tuple[int, list[str]]:
    """(records, their channels) in the first chunks of an .evtx, plain or
    .gz - what identification names the file by. Reads the head only: the
    records of complete chunks render without the rest of the file."""
    opener = gzip.open if str(path).lower().endswith(".gz") else open
    with opener(path, "rb") as fh:
        head, taken = fh.read(EVTX_HEADER), 0
        # The first four chunks, passing over damaged slots (the reader stops at one).
        for _ in range(64):
            block = fh.read(EVTX_CHUNK)
            if not block or taken == 4:
                break
            if block[:8] == EVTX_CHUNK_MAGIC:
                head, taken = head + block, taken + 1
    records, channels = 0, []
    for rec in _evtx_parser(io.BytesIO(head), threads=1).records():
        if isinstance(rec, Exception):
            continue
        records += 1
        m = re.search(r"<Channel>([^<]*)</Channel>", rec["data"])
        if m and m.group(1).strip():
            channels.append(m.group(1).strip())
    return records, channels


def evtx_chunks(path: Path) -> tuple[list[tuple[int, int, int, bool]], list[int]]:
    """What the file says it holds: each chunk's (slot, first record id, last
    record id, cut short by the end of the file) from its header, and the
    64 KB slots that are neither a chunk nor empty (a damaged chunk header -
    its records cannot be known). One small read per chunk."""
    chunks, bad = [], []
    with open(path, "rb") as fh:
        size = fh.seek(0, io.SEEK_END)
        slot = 0
        while EVTX_HEADER + slot * EVTX_CHUNK < size:
            offset = EVTX_HEADER + slot * EVTX_CHUNK
            fh.seek(offset)
            head = fh.read(40)
            first, last = struct.unpack("<QQ", head[24:40]) if len(head) == 40 else (1, 0)
            # A record takes at least 28 bytes of the chunk's 65,024: a header
            # naming more is damaged, and its count would be invented.
            if head[:8] == EVTX_CHUNK_MAGIC and 0 <= last - first < _MAX_RECORDS:
                chunks.append((slot, first, last, offset + EVTX_CHUNK > size))
            else:
                fh.seek(offset)
                if any(fh.read(EVTX_CHUNK)):  # a never-used slot is all zeros
                    bad.append(slot)
            slot += 1
    return chunks, bad


# Binary XML, as far as it is read here (libyal's EVTX document, "Binary XML"):
# a record's event is a template instance - token 0x0c, the offset of its
# template definition in the chunk (the definition follows inline when that
# offset is its own position: 24-byte header + data size), then the value
# count, a (size, type) descriptor per value and the values. Only the types the
# library renders differently from Windows are taken; a nested Binary XML value
# (type 0x21, how EventData is often carried) is read the same way.
_RECORD_MAGIC = b"\x2a\x2a\x00\x00"
_GUID, _FILETIME, _SYSTEMTIME, _BINXML, _STRING_ARRAY = 0x0F, 0x11, 0x12, 0x21, 0x81
_FILETIME_EPOCH = datetime(1601, 1, 1)


@dataclass
class EvtxRecord:
    """One record as the evtx library rendered it: {the library's form:
    Windows' form} of its GUID, FILETIME and SYSTEMTIME values (`fixes`),
    and whether a string array in it holds an empty string - the library
    renders that, and a null value, alike as an empty unnamed item."""
    xml: str
    fixes: dict
    empty_in_array: bool = False


def _guid(v: bytes) -> tuple[str, str]:
    d1, d2, d3 = struct.unpack_from("<IHH", v)
    hexed = f"{d1:08X}-{d2:04X}-{d3:04X}-{v[8:10].hex().upper()}-{v[10:16].hex().upper()}"
    return hexed, "{" + hexed.lower() + "}"  # the library's form, Windows' form


def _filetime(v: bytes) -> tuple[str, str]:
    ticks = struct.unpack("<Q", v)[0]
    when = _FILETIME_EPOCH + timedelta(microseconds=ticks // 10)
    stem = when.strftime("%Y-%m-%dT%H:%M:%S")
    # The library truncates to the microsecond; Windows writes 100 ns.
    return f"{stem}.{when.microsecond:06d}Z", f"{stem}.{ticks % 10_000_000:07d}Z"


def _binxml_values(b: bytes, pos: int, fixes: dict, flags: dict, depth: int = 0) -> None:
    if depth > 4:
        return
    if b[pos] == 0x0F:  # fragment header
        pos += 4
    if b[pos] != 0x0C:  # no template instance: no typed values to take
        return
    definition = struct.unpack_from("<I", b, pos + 6)[0]
    pos += 10
    if definition == pos:
        pos += 24 + struct.unpack_from("<I", b, pos + 20)[0]
    count = struct.unpack_from("<I", b, pos)[0]
    if count > 4096:
        raise ValueError("not a value count")
    descriptors = [struct.unpack_from("<HB", b, pos + 4 + 4 * i) for i in range(count)]
    pos += 4 + 4 * count
    for size, kind in descriptors:
        v = b[pos:pos + size]
        if kind == _GUID and size == 16:
            lib, win = _guid(v)
            fixes[lib] = win
        elif kind == _FILETIME and size == 8:
            try:
                lib, win = _filetime(v)
                fixes[lib] = win
            except OverflowError:  # past year 9999: left as the library renders it
                pass
        elif kind == _SYSTEMTIME and size == 16:
            # year, month, day of week, day, hour, minute, second, milliseconds
            y, mo, _, d, h, mi, s, ms = struct.unpack("<8H", v)
            stem = f"{y:04d}-{mo:02d}-{d:02d}T{h:02d}:{mi:02d}:{s:02d}"
            fixes[f"{stem}.{ms * 1000:06d}Z"] = f"{stem}.{ms * 10000:07d}Z"
        elif kind == _BINXML and size:
            _binxml_values(b, pos, fixes, flags, depth + 1)
        elif kind == _STRING_ARRAY and size:
            # UTF-16 strings, each ending in a NUL.
            items = v.decode("utf-16-le", errors="replace").split("\x00")[:-1]
            if "" in items:
                flags["empty_in_array"] = True
        pos += size


def evtx_typed_values(chunk: bytes) -> dict[int, tuple[dict[str, str], bool]]:
    """Record id -> (`fixes`, empty string in an array) for every record of
    one chunk. A record whose Binary XML is not read here keeps the library's
    form (no fix), never fails."""
    out: dict[int, tuple[dict[str, str], bool]] = {}
    end = min(len(chunk), struct.unpack_from("<I", chunk, 48)[0] if len(chunk) >= 52 else 0)
    pos = 512  # the chunk header and its string / template tables
    while pos + 28 <= end and chunk[pos:pos + 4] == _RECORD_MAGIC:
        size, record_id = struct.unpack_from("<IQ", chunk, pos + 4)
        if size < 28 or pos + size > len(chunk):
            break
        fixes: dict[str, str] = {}
        flags: dict[str, bool] = {}
        try:
            _binxml_values(chunk, pos + 24, fixes, flags)
        except (struct.error, IndexError, ValueError, OverflowError):
            pass
        out[record_id] = (fixes, flags.get("empty_in_array", False))
        pos += size
    return out


class _Tally:
    """Records returned per chunk, by record id (ids are unique in a file and
    each chunk holds a contiguous range of them)."""

    def __init__(self, chunks):
        self.chunks = sorted(chunks, key=lambda c: c[1])
        self.firsts = [c[1] for c in self.chunks]
        self.got = [0] * len(self.chunks)

    def add(self, record_id) -> int | None:
        """Count one record; its chunk's slot, or None outside every chunk."""
        if not isinstance(record_id, int):
            return None
        k = bisect.bisect_right(self.firsts, record_id) - 1
        if k < 0 or record_id > self.chunks[k][2]:
            return None
        self.got[k] += 1
        return self.chunks[k][0]

    def short(self) -> Iterator[tuple[int, int, int, int, bool]]:
        for (slot, first, last, cut), got in zip(self.chunks, self.got):
            if got < last - first + 1:
                yield slot, first, last, last - first + 1 - got, cut


def _without_bad_slots(path: Path, scratch: Path | None) -> Path:
    """A copy of the file header and every slot that starts with a chunk
    signature: the reader stops at the first slot without one ("Failed to
    parse chunk header"), which would lose every good chunk after it. Never
    written beside the evidence."""
    fd, name = tempfile.mkstemp(suffix=".evtx", dir=str(scratch) if scratch else None)
    with open(path, "rb") as src, os.fdopen(fd, "wb") as dst:
        dst.write(src.read(EVTX_HEADER))
        while block := src.read(EVTX_CHUNK):
            if block[:8] == EVTX_CHUNK_MAGIC:
                dst.write(block)
    return Path(name)


def iter_evtx(path: Path, progress=None, errors: list | None = None,
              scratch: Path | None = None) -> Iterator[EvtxRecord | Damage]:
    """Each record of a plain .evtx as event XML, in file order; then a
    Damage for every chunk whose header names records the reader did not
    return, and for every slot that is not a chunk. `progress(fraction)` by
    chunk; the reader's own error messages are appended to `errors`; a file
    with a damaged slot is read from a copy without it, made in `scratch`."""
    chunks, bad = evtx_chunks(path)
    tally = _Tally(chunks)
    slots = max(1, max([c[0] for c in chunks] + bad, default=0) + 1)
    n = 0
    source = _without_bad_slots(path, scratch) if bad else path
    try:
        with open(path, "rb") as fh:
            typed_slot, typed = None, {}
            for rec in _evtx_parser(str(source)).records():
                if isinstance(rec, Exception):
                    if errors is not None and len(errors) < 20:
                        errors.append(str(rec)[:300])
                    continue
                slot = tally.add(rec.get("event_record_id"))
                if slot is not None and slot != typed_slot:
                    # Records come in file order: one chunk read per chunk.
                    fh.seek(EVTX_HEADER + slot * EVTX_CHUNK)
                    typed_slot, typed = slot, evtx_typed_values(fh.read(EVTX_CHUNK))
                fixes, empty_in_array = (typed.get(rec.get("event_record_id"), ({}, False))
                                         if slot is not None else ({}, False))
                yield EvtxRecord(rec["data"], fixes, empty_in_array)
                n += 1
                if progress and slot is not None and n % 1000 == 0:
                    progress(slot / slots)
    except Exception as exc:  # noqa: BLE001 - the reader gave up; what is left is counted below
        if errors is not None:
            errors.append(f"reading stopped: {str(exc)[:300]}")
    finally:
        if source != path:
            source.unlink(missing_ok=True)
    for slot, first, last, missing, cut in tally.short():
        offset = EVTX_HEADER + slot * EVTX_CHUNK
        yield Damage(f"[unreadable EVTX records] chunk {slot} at byte {offset}: {missing} of "
                     f"records {first}-{last} not readable"
                     + (" - the file ends inside this chunk" if cut else ""), missing)
    for slot in bad:
        yield Damage(f"[unreadable EVTX chunk] chunk {slot} at byte {EVTX_HEADER + slot * EVTX_CHUNK}: "
                     "its chunk header is damaged - how many records it held cannot be known", 0)
    if progress:
        progress(1.0)


# --- Splunk classic WinEventLog text (W3) ----------------------------------

@dataclass
class SplunkRecord:
    """One record's text: the time line through the end of its message."""
    text: str


def is_splunk_text(head: str) -> bool:
    """A Splunk time line followed by `LogName=` within the first 50 lines (a
    few lines before it - a search's preamble - are kept as a row when read)."""
    lines = head.lstrip("﻿").splitlines()[:51]
    return any(_SPLUNK_TIME.match(a) and b.startswith("LogName=") for a, b in zip(lines, lines[1:]))


def splunk_channels(head: str) -> list[str]:
    return [c.strip() for c in re.findall(r"^LogName=(.*)$", head, re.M) if c.strip()]


def iter_splunk_records(path: Path, progress=None) -> Iterator[SplunkRecord | Damage]:
    """Each record of a Splunk WinEventLog text file, in order. A record
    starts at a time line followed by `LogName=`, so a message line that
    happens to hold a date does not cut it. Text before the first record is
    kept as a Damage row, never dropped."""
    report = parsers._reporter(path, progress)
    current: list[str] = []
    pending: str | None = None  # a time line, until the next line says whether it starts a record

    def flush():
        if not current:
            return None
        text = "\n".join(current).rstrip("\n")
        current.clear()
        if text.strip():
            return SplunkRecord(text) if _SPLUNK_TIME.match(text.split("\n", 1)[0]) else \
                Damage("[not a Splunk WinEventLog record] " + text, 1)
        return None

    with parsers.open_text(path) as fh:
        for n, raw in enumerate(fh, 1):
            line = raw.rstrip("\r\n")
            if pending is not None:
                if line.startswith("LogName="):
                    done = flush()
                    if done:
                        yield done
                current.append(pending)
                pending = None
            if _SPLUNK_TIME.match(line):
                pending = line
                continue
            current.append(line)
            if report and n % 2000 == 0:
                report(fh)
    if pending is not None:
        current.append(pending)
    done = flush()
    if done:
        yield done


@functools.cache
def _providers() -> dict[str, dict]:
    """Display name -> {"name", "events": {id: [templates, newest version first]}}
    from the exported provider metadata (Q45)."""
    out = {}
    for path in sorted(_TEMPLATE_DIR.glob("*.json")):
        meta = json.loads(path.read_text(encoding="utf-8"))
        events: dict[int, list] = {}
        for e in meta["events"]:
            events.setdefault(e["id"], []).append(e)
        for versions in events.values():
            versions.sort(key=lambda e: -e["version"])
        out[meta["display"]] = {"name": meta["provider"], "events": events}
    return out


_INSERT = re.compile(r"%(\d+)(?:![^!]*!)?")


@functools.cache
def _line_pattern(template_line: str) -> tuple[re.Pattern, tuple[int, ...]]:
    """One template line as a pattern over a rendered line: its words as
    written, any run of whitespace as any whitespace, each %n a value (the last
    one runs to the end of the line)."""
    parts = _INSERT.split(template_line)
    numbers = tuple(int(p) for p in parts[1::2])
    out = []
    for i, part in enumerate(parts):
        if i % 2:
            out.append("(.*)" if i == len(parts) - 2 else "(.*?)")
        else:
            out.append("".join(r"\s*" if t.isspace() else re.escape(t)
                               for t in re.split(r"(\s+)", part) if t))
    return re.compile(r"\s*" + "".join(out) + ("" if numbers else r"\s*") + "$"), numbers


# A "Label:<tab>" line at the margin or one tab in: a field of the message, never
# a value continuing. One left over means the template is another build's - the
# same version of 5156 has two more fields on Windows 11 than on older builds.
_LABELLED = re.compile(r"^\t?[A-Za-z][^\t:]*:\t")
_HEX = re.compile(r"^0x[0-9A-F]+$")


def _match_template(message: list[str], template: str, names: list[str],
                    hex_names: tuple[str, ...] = ()) -> dict[str, str] | None:
    """Align the rendered message with one template, line by line: a line
    without an insertion must read the same; a line with one gives its values;
    lines that fit no template line are the previous value continuing (4672's
    PrivilegeList) - unless they are a field's own line. None when they do not
    align."""
    tlines = template.split("\n")
    values: dict[str, str] = {}
    j = 0
    last = None  # the name of the value a continuation line belongs to

    def fits(t: str, line: str) -> bool:
        return bool(_line_pattern(t)[0].match(line)) if t.strip() else not line.strip()
    for t in tlines:
        while True:
            if j >= len(message):
                return None
            if fits(t, message[j]):
                break
            # A continuation of the previous value (blank lines too: 4662's
            # Properties); with no value open, the template does not fit.
            if last is None or _LABELLED.match(message[j]):
                return None
            values[last] += "\n" + message[j]
            j += 1
        pattern, numbers = _line_pattern(t)
        if numbers:
            m = pattern.match(message[j])
            for n, v in zip(numbers, m.groups()):
                if 0 < n <= len(names):
                    values[names[n - 1]] = v
            last = names[numbers[-1] - 1] if 0 < numbers[-1] <= len(names) else None
        elif t.strip():
            last = None  # a label line closes the value; a blank one may not (4662)
        j += 1
    # The last value may continue up to the blank line before the explanation.
    while j < len(message) and message[j].strip():
        if not last or _LABELLED.match(message[j]):
            return None
        values[last] += "\n" + message[j]
        j += 1
    # Blank lines a multi-line value ran over before the next label are layout;
    # a hex value is written as the event stores it.
    return {k: re.sub(r"(\n[ \t]*)+$", "", v) if "\n" in v
            else v.lower() if k in hex_names and _HEX.match(v) else v
            for k, v in values.items()}


def parse_splunk(text: str) -> dict | None:
    """One Splunk WinEventLog record as parse_event's dict, or None when it
    has no EventCode. Items named from the provider's message templates
    (newest version first); a message no template fits is kept whole as
    `Message` and the dict says so (`template_matched`)."""
    lines = text.split("\n")
    header: dict[str, str] = {}
    message: list[str] = []
    for i, line in enumerate(lines[1:], 1):
        if line.startswith("Message="):
            message = [line[len("Message="):]] + lines[i + 1:]
            break
        key, sep, value = line.partition("=")
        if sep:
            header[key.strip()] = value.strip()
    try:
        event_id = int(header.get("EventCode", ""))
    except ValueError:
        return None
    while message and not message[-1].strip():
        message.pop()
    display = header.get("SourceName")
    provider = _providers().get(display or "")
    data, matched = None, False
    if provider:
        for template in provider["events"].get(event_id, []):
            data = _match_template(message, template["message"], template["names"],
                                   tuple(template.get("hex", ())))
            if data is not None:
                matched = True
                break
    if data is None:
        data = {"Message": "\n".join(message)}
    # A character XML cannot hold, as Windows' event XML writes it (see .evtx).
    data = {k: _ILLEGAL.sub("_", v) for k, v in data.items()}
    return {
        "provider": provider["name"] if provider else display,
        "event_id": event_id,
        "time_created": lines[0].strip(),
        "record_id": header.get("RecordNumber"),
        "channel": header.get("LogName"),
        "computer": header.get("ComputerName"),
        "user_sid": None,
        "data": data,
        "template_matched": matched,
    }


# --- JSON: Winlogbeat / Elastic and NXLog (W4) -------------------------------

def _unwrap(rec: dict) -> dict:
    """An Elasticsearch export wraps each document in `_source`."""
    return rec["_source"] if isinstance(rec.get("_source"), dict) else rec


def json_shape(rec: dict) -> str | None:
    """"winlogbeat", "nxlog", "flat" (OTRF's later records: Windows' names at
    the top, no shipper named - observed, not read) or None."""
    if not isinstance(rec, dict) or "_raw" in rec:
        return None
    rec = _unwrap(rec)
    w = rec.get("winlog")
    if isinstance(w, dict) and "event_id" in w and ("channel" in w or "provider_name" in w):
        return "winlogbeat"
    if rec.get("SourceModuleType") == "im_msvistalog":
        return "nxlog"
    if {"EventID", "Channel", "Hostname", "SourceName", "TimeCreated"} <= set(rec):
        return "flat"
    return None


def _text(v) -> str:
    if v is None:
        return ""
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (dict, list)):
        return json.dumps(v, ensure_ascii=False)
    return str(v)


def _int(v) -> int | None:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _template_names(provider: str | None, event_id: int | None, version: int | None) -> set[str] | None:
    """The item names of one event version in the exported templates, or None
    when the provider, event or version is not among them."""
    for meta in _providers().values():
        if meta["name"] == provider:
            for t in meta["events"].get(event_id, []):
                if t["version"] == version:
                    return set(t["names"])
    return None


def _nxlog_event_data(xml: str) -> dict[str, str] | None:
    """NXLog's `EventData` field, when it carries one: the items as Windows wrote them."""
    try:
        root = ElementTree.fromstring(_ILLEGAL.sub("_", xml))
    except ElementTree.ParseError:
        return None
    data = {}
    for i, d in enumerate((el for el in root.iter() if _local(el.tag) == "Data"), 1):
        data[d.get("Name") or f"param{i}"] = d.text or ""
    return data


def parse_json_event(rec: dict) -> dict | None:
    """One Winlogbeat or NXLog record as parse_event's dict, or None when it
    is neither (or carries no event ID)."""
    shape = json_shape(rec)
    if shape not in ("winlogbeat", "nxlog"):
        return None
    rec = _unwrap(rec)
    if shape == "winlogbeat":
        w = rec["winlog"]
        data = {k: _text(v) for k, v in (w.get("event_data") or {}).items()}
        for k, v in (w.get("user_data") or {}).items():
            if isinstance(v, dict):  # an element inside UserData's own element
                data.update({kk: _text(vv) for kk, vv in v.items()})
            elif k != "xml_name":  # Winlogbeat's name for UserData's element, not an item
                data[k] = _text(v)
        ev = {"provider": w.get("provider_name"), "event_id": _int(w.get("event_id")),
              "time_created": rec.get("@timestamp"), "record_id": _text(w.get("record_id")) or None,
              "channel": w.get("channel"), "computer": w.get("computer_name"),
              "user_sid": (w.get("user") or {}).get("identifier") if isinstance(w.get("user"), dict) else None}
    else:
        data, outside = None, []
        if isinstance(rec.get("EventData"), str):
            data = _nxlog_event_data(rec["EventData"])
        if data is None:
            # An item Windows' template names stays an item even when NXLog has a
            # field of that name (4778's AccountName); a key the template does not
            # name is kept too, and counted (OTRF's pipeline adds ProcessId).
            named = _template_names(rec.get("SourceName"), _int(rec.get("EventID")), _int(rec.get("Version")))
            data = {k: _text(v) for k, v in rec.items()
                    if (k not in _NXLOG_FIELDS and k not in _LOGSTASH_FIELDS) or (named and k in named)}
            if named is not None:
                outside = sorted(k for k in data if k not in named)
        ev = {"provider": rec.get("SourceName"), "event_id": _int(rec.get("EventID")),
              "time_created": _text(rec.get("EventTime")) or None,
              "record_id": _text(rec.get("RecordNumber")) or None,
              "channel": rec.get("Channel"), "computer": rec.get("Hostname"),
              "user_sid": rec.get("UserID"), "outside_template": outside}
    if ev["event_id"] is None:
        return None
    if ev["channel"]:
        ev["channel"] = channel_name(ev["channel"])
    ev["data"] = {k: _ILLEGAL.sub("_", v) for k, v in data.items()}
    return ev


def iter_json_records(path: Path, progress=None, stats: dict | None = None) -> Iterator[dict]:
    """Each JSON record of the file as decoded - nested, empty values kept."""
    return parsers.iter_json(path, progress, stats, flat=False)
