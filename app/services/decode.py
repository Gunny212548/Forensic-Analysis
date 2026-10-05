"""Decodes a parsed row into the canonical event schema (see db.py).

This is our stand-in for what a SIEM's decoders do: pull a real timestamp,
hostname, program, and semantic fields (srcip, user, action...) out of
unstructured text or arbitrary CSV/JSON columns.

Everything a rule might need is extracted into a typed column here, so the
raw source row never has to be carried any further - that keeps storage
proportional to the source file instead of several times larger.
"""

import re
from datetime import datetime, timedelta, timezone

from .. import config

# Every event time lands in the one fixed ingest zone - see config for why.
_EVENT_TZ = timezone(timedelta(hours=config.EVENT_TZ_OFFSET_HOURS))

_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

_ISO_TS_RE = re.compile(r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)\s+(?P<rest>.*)$")
_SYSLOG_TS_RE = re.compile(r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<rest>.*)$")

# Matches a "program[pid]:" or "program:" token, e.g. "sshd[49289]:"
_PROG_TOKEN_RE = re.compile(r"^(?P<prog>[\w.\-/]+?)(?:\[(?P<pid>\d+)\])?:$")

# FortiGate (and other Fortinet) logs are flat space-separated key=value
# lines with no leading timestamp at all - "devname=... date=... time=...
# ...srcip=1.2.3.4 ...". Neither _ISO_TS_RE nor _SYSLOG_TS_RE match that, so
# decode_line() used to fall all the way through to the bare _IP_RE scan,
# which happened to grab srcip= only because it's usually the first
# IP-shaped substring on the line - dstip/verdict/app/ts all stayed NULL for
# 621,924 real rows in one customer file. Detected by key, not position:
# other Fortinet subtypes (utm/event) share the same key=value style with a
# different key set, so this can't be a fixed field list.
_FORTIGATE_SIGNATURE_RE = re.compile(r"(?:^|\s)devname=")
_KV_RE = re.compile(r'(\w+)=("(?:[^"\\]|\\.)*"|\S+)')


def _is_fortigate_line(line: str) -> bool:
    # devname= alone is Fortinet-specific but cheap to check first; srcip=
    # confirms this is a traffic-shaped record worth decoding by key rather
    # than something else entirely that merely mentions a device name.
    return bool(_FORTIGATE_SIGNATURE_RE.search(line)) and "srcip=" in line


def _parse_kv(line: str) -> dict[str, str]:
    out = {}
    for key, val in _KV_RE.findall(line):
        if len(val) >= 2 and val[0] == '"' and val[-1] == '"':
            val = val[1:-1].replace('\\"', '"')
        out[key] = val
    return out


_TS_FORMATS = [
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M:%S",
    "%d/%m/%Y %H:%M:%S",
    "%d/%m/%Y %H:%M",
    "%Y/%m/%d %H:%M:%S",
    "%m/%d/%Y %H:%M:%S",
    "%b %d, %Y %I:%M:%S %p",  # Check Point: "Jun 23, 2026 10:03:02 PM"
    "%b %d, %Y %H:%M:%S",
]


def parse_ts(text: str | None) -> datetime | None:
    """Best-effort real timestamp, always returned as naive GMT+7 wall-clock
    time (config.EVENT_TZ_*). Returns None rather than guessing when the
    format carries no year (classic syslog "Aug 12 05:03:31") - the original
    string is always kept in ts_raw either way.

    An offset in the source is *converted*, not discarded: dropping the
    tzinfo from "03:12:00Z" used to store 03:12 and leave a UTC row sitting
    seven hours away from its +07:00 neighbours in the same timeline, while
    the SQL ingest path was normalising the other way, to UTC. The two paths
    disagreed on the same file."""
    if not text:
        return None
    s = str(text).strip()
    if not s:
        return None

    iso = s.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(iso)
        if dt.tzinfo:
            return dt.astimezone(_EVENT_TZ).replace(tzinfo=None)
        return dt
    except ValueError:
        pass

    for fmt in _TS_FORMATS:
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            continue
    return None


# sshd message patterns (same shape a Wazuh sshd decoder would match)
_SSHD_PATTERNS = [
    ("auth_failed", re.compile(
        r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+) port (?P<port>\d+)"
    )),
    ("auth_failed", re.compile(
        r"authentication failure;.*?rhost=(?P<ip>[\d.]+)(?:\s+user=(?P<user>\S+))?"
    )),
    ("auth_failed", re.compile(
        r"error: PAM: Authentication failure for (?:illegal user )?(?P<user>\S+) from (?P<ip>[\d.]+)"
    )),
    ("auth_success", re.compile(
        r"Accepted (?:password|publickey|keyboard-interactive\S*) for (?P<user>\S+) from (?P<ip>[\d.]+) port (?P<port>\d+)"
    )),
    ("connection", re.compile(r"Connection from (?P<ip>[\d.]+) port (?P<port>\d+)")),
    ("invalid_user", re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>[\d.]+)")),
]

_PAM_PATTERNS = [
    ("password_changed", re.compile(r"password changed for (?P<user>\S+)")),
]

# Column-name candidates for each canonical field, matched case-insensitively
# as substrings. Order matters: the first hit wins.
_FIELD_CANDIDATES = {
    # "High Res Timestamp" first: it's unambiguous ISO8601 with an offset,
    # unlike Palo Alto's "Receive Time" (DD/MM/YYYY, locale-ambiguous).
    "ts": ["high res timestamp", "receive time", "generate time", "timestamp",
           "@timestamp", "time", "date"],
    # "source"/"destination" (Check Point) come last so Palo Alto's more
    # specific "Source address" still wins when both could match.
    "srcip": ["source address", "src ip", "srcip", "source ip", "src_ip",
              "sourceip", "source", "ip address"],
    "dstip": ["destination address", "dst ip", "dstip", "destination ip",
              "dst_ip", "destinationip", "destination"],
    "dstport": ["destination port", "dst port", "dstport", "dport"],
    "username": ["source user", "destination user", "dst user", "user", "username", "account"],
    # "status" before "result": Azure AD sign-in exports carry both a
    # "Status" column (Success/Failure) and a "Multifactor authentication
    # result" column holding a paragraph of prose.
    "verdict": ["action", "status", "result", "verdict", "disposition"],
    # Sign-in/logon outcome, kept separate from "verdict" because it maps to
    # the semantic `action` column (auth_failed / auth_success) that the
    # R1xxx and R2000 rules key off. Only the auth vocabulary is accepted -
    # see normalize_auth_status() - so a firewall "Action" column full of
    # allow/deny can never be read as an authentication outcome.
    "auth_status": ["sign-in status", "signin status", "logon status",
                    "authentication result", "status", "result"],
    "app": ["application", "app", "service"],
    "risk": ["risk of app", "risk"],
    "bytes_sent": ["bytes sent", "bytessent", "bytes_sent"],
    "category": ["threat/content type", "category of app", "characteristic of app",
                 "threat name", "category"],
}

# Columns to ignore during the loose substring pass for a given field, so
# "Source User Name" can't be mistaken for a source IP when a file has no
# plain "Source" column.
_AVOID_SUBSTRINGS = {
    # "resource": Azure AD exports have a "Resource" column, and the loose
    # pass for "source" matches the "source" inside "re-source" - which is
    # how an Azure sign-in export ended up with resource names as its source
    # IPs. "destination"/"source" cross-guards keep "Destination IP address"
    # out of srcip and vice versa now that "ip address" is a candidate.
    "srcip": ("user", "name", "zone", "country", "interface", "port",
              "resource", "destination", "dest"),
    "dstip": ("user", "name", "zone", "country", "interface", "port",
              "resource", "source", "src"),
    # "log action" holds "Log Forwarding ALL" in Palo Alto exports; the exact
    # pass already prefers the real "Action" column, this stops the loose
    # pass from picking it up when a file has no exact match at all.
    # "statuscode" keeps Azure's "Token Protection - Sign In Session
    # StatusCode" out of both.
    "verdict": ("log action", "statuscode"),
    "auth_status": ("statuscode",),
    # "user" as a loose substring matches "User agent" and "User type" as
    # readily as a real account column, and a non-NULL username is the guard
    # that lets an auth_status column become an auth finding at all (gotcha
    # #11) - so a browser version or "Member"/"Guest" landing here would
    # carry failed-login findings under an account that is not one.
    # Deliberately just these two. "User ID" was in an earlier draft and
    # taken out: a user id *is* an account identifier, so blocking it would
    # risk losing the username - and with it every auth finding - on a file
    # whose only account column is that. Surveyed against the corpus first:
    # every real file here (Palo Alto "Source User", Azure "Username"/"User",
    # Check Point "Source User Name") resolves before the loose pass matters.
    "username": ("agent", "type"),
}

# Firewall vendors spell the same verdict differently; rules are written
# against the canonical spellings.
_VERDICT_ALIASES = {
    "accept": "allow",
    "permit": "allow",
    "allowed": "allow",
    "denied": "deny",
    "dropped": "drop",
    "rejected": "reject",
}


def normalize_verdict(value: str | None) -> str | None:
    if not value:
        return None
    v = str(value).strip().lower()
    return _VERDICT_ALIASES.get(v, v) or None


# Sign-in outcome vocabulary -> the semantic action the rules match on.
# Deliberately narrow: "Interrupted" (Azure's MFA/keep-me-signed-in prompt)
# is not a failed authentication and maps to nothing, and firewall verdicts
# (allow/deny/drop) are absent, so a firewall Action column can never be
# misread as an auth outcome.
_AUTH_STATUS = {
    "success": "auth_success",
    "succeeded": "auth_success",
    "failure": "auth_failed",
    "failed": "auth_failed",
    "fail": "auth_failed",
}


def normalize_auth_status(value: str | None) -> str | None:
    if not value:
        return None
    return _AUTH_STATUS.get(str(value).strip().lower())


def extract_ip(value: str | None) -> str | None:
    """Check Point writes address fields as "object-name (1.2.3.4)"; Palo
    Alto writes a bare IP. Pull the IP when there is one, otherwise keep the
    original text so named entities still show up in the graph."""
    if not value:
        return None
    m = _IP_RE.search(str(value))
    return m.group(0) if m else str(value).strip() or None


def _find_field(row: dict, field: str) -> str | None:
    """Exact column-name matches win over substring matches. Without that,
    Palo Alto's "Log Action" column (value: "Log Forwarding ALL") shadows
    the real "Action" column (allow/deny), and every firewall rule silently
    stops matching."""
    lower_keys = {k.lower().strip(): k for k in row.keys()}
    candidates = _FIELD_CANDIDATES.get(field, [])
    avoid = _AVOID_SUBSTRINGS.get(field, ())

    for cand in candidates:
        orig_k = lower_keys.get(cand)
        if orig_k is not None:
            val = row.get(orig_k)
            if val not in (None, ""):
                return str(val)

    for cand in candidates:
        for lk, orig_k in lower_keys.items():
            if cand in lk and not any(bad in lk for bad in avoid):
                val = row.get(orig_k)
                if val not in (None, ""):
                    return str(val)
    return None


def match_column(header: list[str], field: str) -> str | None:
    """Same precedence as _find_field(), but resolved once against a CSV
    header instead of per row - used to build the SQL ingest for CSV files
    so DuckDB can do the whole decode itself."""
    lower_keys = {h.lower().strip(): h for h in header if h}
    candidates = _FIELD_CANDIDATES.get(field, [])
    avoid = _AVOID_SUBSTRINGS.get(field, ())

    for cand in candidates:
        if cand in lower_keys:
            return lower_keys[cand]

    for cand in candidates:
        for lk, orig in lower_keys.items():
            if cand in lk and not any(bad in lk for bad in avoid):
                return orig
    return None


def _to_int(val: str | None) -> int | None:
    if val is None:
        return None
    try:
        return int(str(val).strip())
    except (TypeError, ValueError):
        return None


def _split_host_prog(rest: str) -> tuple[str | None, str | None, str]:
    """After the timestamp a line is either "program[pid]: message" (no
    hostname - e.g. ESXi's own logs) or "hostname program[pid]: message".
    Checked token-by-token because a single greedy regex can't tell which
    token is the program when both look tokenish."""
    parts = rest.split(" ", 2)
    if not parts:
        return None, None, rest

    m = _PROG_TOKEN_RE.match(parts[0])
    if m:
        return None, m.group("prog"), rest[len(parts[0]):].lstrip()

    if len(parts) >= 2:
        m = _PROG_TOKEN_RE.match(parts[1])
        if m:
            msg = rest[len(parts[0]) + 1 + len(parts[1]):].lstrip()
            return parts[0], m.group("prog"), msg

    return None, None, rest


def _blank_event() -> dict:
    return {
        "ts": None, "ts_raw": None, "srcip": None, "dstip": None, "dstport": None,
        "username": None, "program": None, "hostname": None, "action": None,
        "verdict": None, "app": None, "risk": None, "bytes_sent": None,
        "category": None, "raw": "",
    }


def _decode_fortigate(line: str) -> dict:
    event = _blank_event()
    event["raw"] = line[:2000]
    kv = _parse_kv(line)

    date, time_ = kv.get("date"), kv.get("time")
    if date and time_:
        tz = kv.get("tz", "")
        ts_raw = f"{date}T{time_}{tz}" if tz else f"{date}T{time_}"
        event["ts_raw"] = ts_raw
        event["ts"] = parse_ts(ts_raw)

    event["hostname"] = kv.get("devname")
    event["srcip"] = extract_ip(kv.get("srcip"))
    event["dstip"] = extract_ip(kv.get("dstip"))
    event["dstport"] = kv.get("dstport")
    event["verdict"] = normalize_verdict(kv.get("action"))
    # service= is on effectively every traffic row; app= only appears on a
    # minority (application-control-inspected sessions) but is the more
    # specific signal when present.
    event["app"] = kv.get("app") or kv.get("service")
    event["category"] = kv.get("appcat")
    event["bytes_sent"] = _to_int(kv.get("sentbyte"))
    # user= is an FSSO/identity-aware-firewall field, not an authentication
    # outcome - FortiGate traffic logs have no success/failure vocabulary, so
    # this is never routed through normalize_auth_status()/`action` (gotcha
    # #11): there is nothing here that could turn a traffic row into a bogus
    # auth finding.
    event["username"] = kv.get("user")
    return event


def decode_line(line: str) -> dict:
    if _is_fortigate_line(line):
        return _decode_fortigate(line)

    event = _blank_event()
    event["raw"] = line[:2000]

    m = _ISO_TS_RE.match(line) or _SYSLOG_TS_RE.match(line)
    if m:
        event["ts_raw"] = m.group("ts")
        event["ts"] = parse_ts(m.group("ts"))
        hostname, program, msg = _split_host_prog(m.group("rest"))
        event["hostname"] = hostname
        event["program"] = program
    else:
        msg = line

    patterns = []
    if event["program"] == "sshd":
        patterns = _SSHD_PATTERNS
    elif event["program"] in ("passwd", "pam", "sudo"):
        patterns = _PAM_PATTERNS

    for action, pattern in patterns:
        pm = pattern.search(msg)
        if pm:
            gd = pm.groupdict()
            event["action"] = action
            event["srcip"] = gd.get("ip")
            event["username"] = gd.get("user")
            # NOTE: the "port" captured here is the remote client's ephemeral
            # SOURCE port, not a destination port being probed - deliberately
            # not stored as dstport, or the port-scan rule would false-positive
            # on any host that simply reconnects a lot.
            break

    if not event["srcip"]:
        ip_m = _IP_RE.search(msg)
        if ip_m:
            event["srcip"] = ip_m.group(0)

    return event


def decode_row(row: dict, kind: str) -> dict:
    if kind == "json" and set(row.keys()) == {"_raw"}:
        return decode_line(row["_raw"])

    event = _blank_event()
    ts_raw = _find_field(row, "ts")
    event["ts_raw"] = ts_raw
    event["ts"] = parse_ts(ts_raw)
    event["srcip"] = extract_ip(_find_field(row, "srcip"))
    event["dstip"] = extract_ip(_find_field(row, "dstip"))
    event["dstport"] = _find_field(row, "dstport")
    event["username"] = _find_field(row, "username")
    # Only an event with an account attached can be an authentication
    # outcome - see the guard in pipeline._ingest_csv_sql for what happens
    # without this (mail delivery "Failed" read as a failed login).
    event["action"] = (
        normalize_auth_status(_find_field(row, "auth_status"))
        if event["username"] else None
    )
    event["verdict"] = normalize_verdict(_find_field(row, "verdict"))
    event["app"] = _find_field(row, "app")
    event["risk"] = _to_int(_find_field(row, "risk"))
    event["bytes_sent"] = _to_int(_find_field(row, "bytes_sent"))
    event["category"] = _find_field(row, "category")
    event["raw"] = ", ".join(
        f"{k}={v}" for k, v in list(row.items())[:14] if v not in (None, "")
    )[:2000]
    return event


def decode(row: dict, kind: str) -> dict:
    if kind == "log":
        return decode_line(row["line"])
    return decode_row(row, kind)
