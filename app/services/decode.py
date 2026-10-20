"""Decodes a parsed row into the canonical event schema (see db.py).

This is our stand-in for what a SIEM's decoders do: pull a real timestamp,
hostname, program, and semantic fields (srcip, user, action...) out of
unstructured text or arbitrary CSV/JSON columns.

Everything a rule might need is extracted into a typed column here, so the
raw source row never has to be carried any further - that keeps storage
proportional to the source file instead of several times larger.
"""

import contextvars
import re
from datetime import datetime, timedelta, timezone

from .. import config

# Every event time lands in the one fixed ingest zone - see config for why.
_EVENT_TZ = timezone(timedelta(hours=config.EVENT_TZ_OFFSET_HOURS))

_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# ISO 8601 / RFC 3339 at the start of a line - with an offset too: rsyslog's
# RSYSLOG_FileFormat writes "2026-01-10T13:13:32.123456+07:00 host prog:",
# which the first version (Z or nothing) did not match, so such a file lost
# its whole syslog header (IAI-34).
_ISO_TS_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+(?P<rest>.*)$")
# RFC 3164 "Mmm dd hh:mm:ss" - no year, no zone.
_SYSLOG_TS_RE = re.compile(r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<rest>.*)$")
_RFC3164_TS = re.compile(r"^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}$")

# Syslog over the network (and many collectors' files) start with the
# priority: "<134>". RFC 5424 sec. 6.2.1 / RFC 3164 sec. 4.1.1:
# facility = PRI // 8, severity = PRI % 8.
_PRI_RE = re.compile(r"^<(?P<pri>\d{1,3})>")
# RFC 5424 sec. 6: "1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID SD MSG", every
# header field "-" when absent.
_RFC5424_RE = re.compile(
    r"^(?P<ver>[1-9]\d{0,2}) (?P<ts>\S+) (?P<host>\S+) (?P<app>\S+) (?P<procid>\S+) (?P<msgid>\S+) (?P<rest>.*)$")

# Matches a "program[pid]:" or "program:" token, e.g. "sshd[49289]:" - and
# old Red Hat's "sshd(pam_unix)[19939]:", the module in brackets.
_PROG_TOKEN_RE = re.compile(r"^(?P<prog>[\w.\-/]+?(?:\([\w.\-]+\))?)(?:\[(?P<pid>\d+)\])?:$")

# The year an RFC 3164 timestamp is placed in (IAI-34): the case's upload
# time, set by the pipeline around decoding a file. Unset -> no year is
# guessed and ts stays NULL, as before.
REFERENCE_TIME: contextvars.ContextVar[datetime | None] = contextvars.ContextVar(
    "REFERENCE_TIME", default=None)


def infer_year(ts_text: str) -> datetime | None:
    """An RFC 3164 timestamp placed in the reference time's year - or the year
    before, when that would put it more than a day after the reference (a
    December line in a file uploaded in January). The common receiver
    practice (rsyslog, Logstash), and a guess: the case flags it
    (`year-inferred`, db._confidence) rather than presenting it as read."""
    ref = REFERENCE_TIME.get()
    if ref is None or not _RFC3164_TS.match(ts_text or ""):
        return None
    try:
        dt = datetime.strptime(f"{ref.year} {' '.join(ts_text.split())}", "%Y %b %d %H:%M:%S")
    except ValueError:
        return None  # Feb 29 in a non-leap year, a bad month name
    if dt > ref + timedelta(days=1):
        try:
            dt = dt.replace(year=ref.year - 1)
        except ValueError:
            return None
    return dt


def _sd_end(text: str) -> int:
    """Where RFC 5424 STRUCTURED-DATA ends: "-" or one or more "[...]"
    elements, in which \\] and \\" are escapes (sec. 6.3.5)."""
    if text.startswith("-"):
        return 1
    i = 0
    while i < len(text) and text[i] == "[":
        i += 1
        while i < len(text) and text[i] != "]":
            i += 2 if text[i] == "\\" else 1
        i += 1
    return i

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


# sshd message patterns: the messages OpenSSH's auth_log() (auth.c) writes,
# cited in logsources.LINE_PROFILES["openssh-sshd"].
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
    # Pre-authentication probes (IAI-29): a client that connects and never
    # speaks SSH (a port scanner), or speaks something else at the SSH port
    # ("GET / HTTP/1.1"). OpenSSH kex.c / sshd.c.
    ("ssh_probe", re.compile(r"Did not receive identification string from (?P<ip>[\d.]+)")),
    ("ssh_probe", re.compile(r"Bad protocol version identification .* from (?P<ip>[\d.]+)")),
    # session.c - a file-transfer channel on an authenticated session.
    ("sftp_session", re.compile(r"subsystem request for sftp by user (?P<user>\S+)")),
    # Recognised, but no security meaning on their own (packet.c,
    # serverloop.c): an action of None keeps them out of every rule.
    (None, re.compile(r"Connection closed by (?P<ip>[\d.]+)")),
    (None, re.compile(r"Timeout, client not responding")),
]

_PAM_PATTERNS = [
    ("password_changed", re.compile(r"password changed for (?P<user>\S+)")),
]

# pam_unix's session messages (pam_unix_sess.c), which sshd writes under its
# own name: "pam_unix(system-auth-generic:session): session opened for user
# root by (uid=0)".
_PAM_SESSION_PATTERNS = [
    ("session_open", re.compile(r"pam_unix\([^)]*:session\): session opened for user (?P<user>\S+)")),
    ("session_close", re.compile(r"pam_unix\([^)]*:session\): session closed for user (?P<user>\S+)")),
]

# VMware ESXi's own auth.log lines, documented in Broadcom KB 321910
# ("Auditing ESXi Shell logins and commands"): an ESXi Shell session over
# SSH, and a login at the console (DCUI / tty).
_ESXI_PATTERNS = [
    ("shell_session_open", re.compile(r"Session opened for '(?P<user>[^']+)' on")),
    ("shell_session_close", re.compile(r"Session closed for '(?P<user>[^']+)'")),
    ("console_login", re.compile(r"^(?P<user>\S+) login on '(?P<tty>[^']+)'")),
]

# ESXi's shell.log (IAI-34): the ESXi Shell's command history and the
# switching on and off of the shell and of SSH - Broadcom KB 321910 (command
# history, "Interactive shell session started") and KB 306962 (shell.log:
# "ESXi Shell usage, including enable/disable"). Real files prefix each
# command with the account ("[root]: cd /var/log"); KB 321910's example has
# none, so the prefix is optional.
_ESXI_SHELL_PATTERNS = [
    ("shell_session_start", re.compile(r"^Interactive shell session started")),
    ("shell_command", re.compile(r"^(?:\[(?P<user>[^\]]+)\]: )?(?P<cmd>\S.*)$")),
]
_ESXI_SERVICE_PATTERNS = [
    # Turning SSH or the ESXi Shell on is a common step before hands-on
    # activity on a host - the SUMMIT host enabled both minutes before the
    # encryptor ran.
    ("ssh_enabled", re.compile(r"^SSH login enabled")),
    ("ssh_disabled", re.compile(r"^SSH login disabled")),
    ("esxi_shell_enabled", re.compile(r"^ESXi shell login enabled", re.I)),
    ("esxi_shell_disabled", re.compile(r"^ESXi shell login disabled", re.I)),
    (None, re.compile(r"^ESXi Shell (?:available|unavailable)", re.I)),
]

# ESXi lines seen in real auth.logs whose format VMware/Broadcom does not
# publish - kept apart so the case says "observed", never "documented"
# (logsources.LINE_PROFILES). `User 'root' running command '...'` is a
# command sent over SSH (`ssh host <cmd>`): on the SUMMIT ransomware host it
# is the only trace of `/tmp/esxi_encryptor` and `rm -rf /.ash_history`.
_ESXI_OBSERVED_PATTERNS = [
    ("command_exec", re.compile(r"User '(?P<user>[^']+)' running command '")),
    # ESXi's PAM per-user mapping - plumbing, no security meaning.
    (None, re.compile(r"pam_per_user: create_subrequest_handle\(\)")),
]

# Which patterns are tried for a program, in order, and the line profile
# (logsources.LINE_PROFILES) each set cites. Per pattern set, not per
# program: sshd writes pam_unix's and ESXi's messages under its own name.
_PROGRAM_PATTERNS = {
    "sshd": [(_SSHD_PATTERNS, "openssh-sshd"), (_PAM_SESSION_PATTERNS, "linux-pam"),
             (_ESXI_PATTERNS, "vmware-esxi"), (_ESXI_OBSERVED_PATTERNS, "vmware-esxi-observed")],
    "passwd": [(_PAM_PATTERNS, "linux-pam")],
    "pam": [(_PAM_PATTERNS, "linux-pam")],
    "sudo": [(_PAM_PATTERNS, "linux-pam")],
    "login": [(_ESXI_PATTERNS, "vmware-esxi")],
    "shell": [(_ESXI_SHELL_PATTERNS, "vmware-esxi")],
    "ESXShell": [(_ESXI_SERVICE_PATTERNS, "vmware-esxi")],
    "SSH": [(_ESXI_SERVICE_PATTERNS, "vmware-esxi")],
}

# Firewall log sources spell the same verdict differently; rules are written
# against the canonical spellings.
VERDICT_ALIASES = {
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
    return VERDICT_ALIASES.get(v, v) or None


# Sign-in outcome vocabulary -> the semantic action the rules match on.
# Deliberately narrow: "Interrupted" (Azure's MFA/keep-me-signed-in prompt)
# is not a failed authentication and maps to nothing, and firewall verdicts
# (allow/deny/drop) are absent, so a firewall Action column can never be
# misread as an auth outcome.
AUTH_STATUS = {
    "success": "auth_success",
    "succeeded": "auth_success",
    "failure": "auth_failed",
    "failed": "auth_failed",
    "fail": "auth_failed",
}


def normalize_auth_status(value: str | None) -> str | None:
    if not value:
        return None
    return AUTH_STATUS.get(str(value).strip().lower())


def extract_ip(value: str | None) -> str | None:
    """Check Point writes address fields as "object-name (1.2.3.4)"; Palo
    Alto writes a bare IP. Pull the IP when there is one, otherwise keep the
    original text so named entities still show up in the graph."""
    if not value:
        return None
    m = _IP_RE.search(str(value))
    return m.group(0) if m else str(value).strip() or None


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
        # Which documented line format read this event (logsources.LINE_PROFILES),
        # or None. Not stored per row - counted for the manifest.
        "profile": None,
    }


# FortiGate traffic-log `action` values (FortiOS Log Message Reference,
# traffic log fields). Session-end values of an allowed session are an
# allow; anything not listed keeps its own spelling (normalize_verdict).
_FORTI_ALLOW = {"accept", "close", "timeout", "client-rst", "server-rst", "start"}


def _forti_verdict(action: str | None) -> str | None:
    v = (action or "").strip().lower()
    if v in _FORTI_ALLOW:
        return "allow"
    return normalize_verdict(action)


def _decode_fortigate(line: str) -> dict:
    event = _blank_event()
    event["raw"] = line[:2000]
    event["profile"] = "fortigate-traffic"
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
    event["verdict"] = _forti_verdict(kv.get("action"))
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

    # The syslog header (IAI-34): an optional <PRI>, then either an RFC 5424
    # header or a timestamp (RFC 3164 or ISO / RFC 3339) and "host prog[pid]:".
    # `envelope` / `syslog_pri` / `year_inferred` are counted per file by the
    # pipeline; they are not raw_events columns.
    body = line
    pm = _PRI_RE.match(body)
    if pm:
        event["syslog_pri"] = int(pm.group("pri"))
        body = body[pm.end():]
    m5 = _RFC5424_RE.match(body) if pm else None  # RFC 5424 always has a PRI
    if m5 and m5.group("ver") == "1":
        event["envelope"] = "rfc5424"
        nil = lambda v: None if v == "-" else v  # noqa: E731
        event["ts_raw"] = nil(m5.group("ts"))
        event["ts"] = parse_ts(event["ts_raw"])
        event["hostname"] = nil(m5.group("host"))
        event["program"] = nil(m5.group("app"))
        rest = m5.group("rest")
        msg = rest[_sd_end(rest):].lstrip().lstrip("﻿")  # MSG may start with a BOM
    else:
        m = _ISO_TS_RE.match(body) or _SYSLOG_TS_RE.match(body)
        if m:
            event["envelope"] = "rfc3164" if _RFC3164_TS.match(m.group("ts")) else "iso"
            event["ts_raw"] = m.group("ts")
            event["ts"] = parse_ts(m.group("ts"))
            if event["ts"] is None:
                event["ts"] = infer_year(m.group("ts"))
                event["year_inferred"] = event["ts"] is not None
            hostname, program, msg = _split_host_prog(m.group("rest"))
            event["hostname"] = hostname
            event["program"] = program
        else:
            msg = body

    matched = False
    # "sshd(pam_unix)" is sshd's PAM module - its messages are sshd's.
    base = (event["program"] or "").split("(", 1)[0]
    for patterns, profile in _PROGRAM_PATTERNS.get(base, ()):
        for action, pattern in patterns:
            pm = pattern.search(msg)
            if pm:
                gd = pm.groupdict()
                event["action"] = action
                event["profile"] = profile
                event["srcip"] = gd.get("ip")
                event["username"] = gd.get("user")
                # NOTE: the "port" captured here is the remote client's ephemeral
                # SOURCE port, not a destination port being probed - deliberately
                # not stored as dstport, or the port-scan rule would false-positive
                # on any host that simply reconnects a lot.
                matched = True
                break
        if matched:
            break

    if not event["srcip"]:
        ip_m = _IP_RE.search(msg)
        if ip_m:
            event["srcip"] = ip_m.group(0)

    return event


def decode_row(row: dict, kind: str, mapping=None) -> dict:
    """`mapping` (logsources.Mapping), resolved once from the documented
    profile, reads each field from its mapped column(s), so this path and the
    SQL fast path decode a file identically. Without one nothing is read -
    no column is guessed (IAI-92)."""
    if kind == "json" and set(row.keys()) == {"_raw"}:
        return decode_line(row["_raw"])

    profile = mapping.profile if mapping else None

    def get(field: str) -> str | None:
        if mapping is None:
            return None
        for col in mapping.columns.get(field, ()):
            val = row.get(col)
            bad = profile.null_values.get(col, ()) if profile else ()
            if val not in (None, "") and not any(str(val).startswith(b) for b in bad):
                return val
        return None

    event = _blank_event()
    ts_raw = get("ts")
    event["ts_raw"] = ts_raw
    event["ts"] = parse_ts(ts_raw)
    event["srcip"] = extract_ip(get("srcip"))
    event["dstip"] = extract_ip(get("dstip"))
    event["dstport"] = get("dstport")
    event["username"] = get("username")
    # Only an event with an account attached can be an authentication
    # outcome - see the guard in pipeline._ingest_csv_sql for what happens
    # without this (mail delivery "Failed" read as a failed login).
    status = get("auth_status")
    if not event["username"] or not status:
        event["action"] = None
    elif profile and profile.auth_values:
        event["action"] = profile.auth_values.get(str(status).strip().lower())
    else:
        event["action"] = normalize_auth_status(status)
    verdict = get("verdict")
    if verdict and profile and profile.verdict_values:
        v = str(verdict).strip().lower()
        event["verdict"] = profile.verdict_values.get(v, v) or None
    else:
        event["verdict"] = normalize_verdict(verdict)
    event["app"] = get("app")
    event["risk"] = _to_int(get("risk"))
    event["bytes_sent"] = _to_int(get("bytes_sent"))
    event["category"] = get("category")
    event["raw"] = ", ".join(
        f"{k}={v}" for k, v in list(row.items())[:14] if v not in (None, "")
    )[:2000]
    return event


def decode(row: dict, kind: str, mapping=None) -> dict:
    if kind == "log":
        return decode_line(row["line"])
    return decode_row(row, kind, mapping)
