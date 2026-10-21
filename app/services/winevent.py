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
containers (.evtx, Splunk text, JSON, Event Viewer CSV) feed the same
`event_rows()`.

Event types (layer A, D12) are named from each event's Microsoft page
(Security) and the event headings of the Sysmon page; an event not listed has
no type and is shown as "Windows event <id> (<provider>)" - never guessed.
Which Sysmon item names feed the canonical columns is **observed** in the
events themselves (their `Data Name` attributes): the Sysmon page lists the
events but not their fields.
"""

import json
import re
from collections.abc import Iterator
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

# Channel -> Sigma logsource (taxonomy v2.1.0). Any other channel is
# product windows with the channel named.
CHANNELS = {
    "Security": {"sigma": {"product": "windows", "service": "security"}},
    "Microsoft-Windows-Sysmon/Operational": {"sigma": {"product": "windows", "service": "sysmon"}},
    "System": {"sigma": {"product": "windows", "service": "system"}},
    "Application": {"sigma": {"product": "windows", "service": "application"}},
}

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
_USER = ("TargetUserName", "SubjectUserName", "User")
_SRCIP = ("IpAddress", "SourceIp")
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


def parse_event(text: str) -> dict | None:
    """One event's System values and items, or None when it does not parse."""
    try:
        root = ElementTree.fromstring(text)
    except ElementTree.ParseError:
        return None
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
        for i, d in enumerate(event_data.findall(_NS + "Data"), 1):
            # An unnamed item gets Winlogbeat's documented name, param<n>.
            data[d.get("Name") or f"param{i}"] = (d.text or "")
    user_data = root.find(_NS + "UserData")
    if user_data is not None:
        for holder in user_data:
            for child in holder:
                data[_local(child.tag)] = (child.text or "")
    try:
        event_id = int(sys("EventID") or "")
    except ValueError:
        event_id = None
    return {
        "provider": (system.find(_NS + "Provider").get("Name")
                     if system.find(_NS + "Provider") is not None else None),
        "event_id": event_id,
        "time_created": sys("TimeCreated", "SystemTime"),
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
    """SystemTime (UTC, `...Z`, up to 100 ns) -> naive GMT+7."""
    if not text:
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
        dt = dt.replace(tzinfo=timezone.utc)
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
    return {
        "ts": _when(ev["time_created"]),
        "ts_raw": ev["time_created"],
        "srcip": _first(d, _SRCIP),
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


def damaged_row(text: str) -> dict:
    """A piece of the file that is not a readable event: kept as text."""
    return {"ts": None, "ts_raw": None, "srcip": None, "dstip": None, "dstport": None,
            "username": None, "program": None, "hostname": None, "action": None, "verdict": None,
            "app": None, "risk": None, "bytes_sent": None, "category": None,
            "raw": ("[unreadable event XML] " + re.sub(r"\s+", " ", text))[:4000]}
