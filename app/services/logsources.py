"""Log source profiles: column mappings taken from each log source's own
format documentation.

A *log source* is the product that wrote the log - a PAN-OS firewall's
traffic log, Microsoft Entra ID's sign-in log, OpenSSH's sshd - in the sense
of the Sigma specification's `logsource` (product / service). Not the
company that made it: one company ships several log sources with unrelated
formats, and the format is what a profile describes.

A CSV or JSON file is read only through a profile below (IAI-92, the
user's rule since 2026-10-20: nothing is guessed). Every canonical field is
read from the column the log source's documentation defines for it, and its
values are translated with the vocabulary that documentation lists. Each
profile cites the page it was built from, so any mapping can be checked
against the source instead of taken on trust. A file no profile matches is
not read at all - identify.py keeps it as evidence and the case says so - and
a column the documentation names but an export left out stays empty and is
listed as missing. (Until IAI-92 a name-guessing fallback, decode.match_column,
read such files and columns; gotchas #2, #12 and #22 were its failures.)

Line logs are not column-mapped; their decoders match documented message
formats (`LINE_PROFILES`), and the manifest counts which one read each line.

What a profile fixed, measured against the guesswork it replaced:
- Palo Alto `category` came from `Threat/Content Type` - the log *subtype*,
  whose values are start/end/drop/deny - because it was first in the
  candidate list. PAN-OS documents `Category` as the URL category, which is
  what R3002's malware/command-and-control match is written for.
- Entra ID `username` came from `User`, the display name, because an exact
  match on "user" won. Microsoft documents `Username` as the user principal
  name - the account identifier.
- Entra ID `verdict` came from `Status` (Success/Failure), a sign-in outcome
  read as a firewall verdict. A sign-in has no firewall verdict; the profile
  leaves it empty.
"""

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Profile:
    id: str
    name: str
    docs: tuple[tuple[str, str], ...]  # (title, url)
    # Header columns that must all be present (case- and space-insensitive)
    # for the file to be read with this profile.
    signature: tuple[str, ...]
    # Canonical field -> documented column(s), in preference order. Several
    # columns are only given where the documentation defines more than one
    # (e.g. PAN-OS's three timestamps); the first non-empty value wins.
    fields: dict[str, tuple[str, ...]]
    # Documented values -> canonical spelling. A value the documentation does
    # not list is kept as written (lower-cased) for verdict, and dropped for
    # auth, exactly as the heuristic path does.
    verdict_values: dict[str, str] = field(default_factory=dict)
    auth_values: dict[str, str] = field(default_factory=dict)
    # Field-level notes shown to the analyst, e.g. why something is unmapped.
    notes: tuple[str, ...] = ()
    # Values the documentation defines as "no data" for a column.
    null_values: dict[str, tuple[str, ...]] = field(default_factory=dict)


PROFILES: tuple[Profile, ...] = (
    Profile(
        id="paloalto-traffic",
        name="Palo Alto Networks PAN-OS traffic log",
        docs=(
            ("PAN-OS 11.0 Administrator's Guide - Traffic Log Fields",
             "https://docs.paloaltonetworks.com/pan-os/11-0/pan-os-admin/monitoring/"
             "use-syslog-for-monitoring/syslog-field-descriptions/traffic-log-fields"),
        ),
        signature=("Receive Time", "Type", "Threat/Content Type", "Source address",
                   "Destination address", "Action", "Application"),
        fields={
            # High Resolution Timestamp is the only one documented with an
            # explicit zone offset and milliseconds; Generate/Receive Time are
            # the documented fallbacks (PAN-OS 9.1 and earlier write a 1969
            # placeholder into the high-res field - see null_values).
            "ts": ("High Res Timestamp", "Generate Time", "Receive Time"),
            "srcip": ("Source address",),
            "dstip": ("Destination address",),
            "dstport": ("Destination Port",),
            "username": ("Source User",),
            "verdict": ("Action",),
            "app": ("Application",),
            "risk": ("Risk of app",),
            "bytes_sent": ("Bytes Sent",),
            # "URL category associated with the session" - not
            # Threat/Content Type, which is the log subtype.
            "category": ("Category",),
        },
        verdict_values={
            "allow": "allow", "deny": "deny", "drop": "drop", "drop icmp": "drop",
            "reset both": "reset-both", "reset client": "reset-client",
            "reset server": "reset-server",
        },
        null_values={"High Res Timestamp": ("1969-12-31",)},
        notes=("A traffic log carries no authentication outcome, so no auth "
               "finding can come from it.",),
    ),
    Profile(
        id="entra-signin",
        name="Microsoft Entra ID sign-in log",
        docs=(
            ("Microsoft Learn - Customize and filter activity logs in Microsoft Entra ID "
             "(Status: Success, Failure, Interrupted)",
             "https://learn.microsoft.com/en-us/entra/identity/monitoring-health/"
             "howto-customize-filter-logs"),
            ("Microsoft Learn - Sign-in log activity details (User, Username, IP address)",
             "https://learn.microsoft.com/en-us/entra/identity/monitoring-health/"
             "concept-sign-in-log-activity-details"),
        ),
        signature=("Date (UTC)", "Request ID", "Correlation ID", "Username",
                   "IP address", "Status"),
        fields={
            "ts": ("Date (UTC)",),
            "srcip": ("IP address",),
            # The user principal name - the account. "User" is the display
            # name, which two different accounts can share.
            "username": ("Username",),
            "auth_status": ("Status",),
            "app": ("Application",),
        },
        # "Interrupted" is a documented third outcome (an MFA or
        # keep-me-signed-in prompt), not a failed authentication.
        auth_values={"success": "auth_success", "failure": "auth_failed"},
        notes=("Status 'Interrupted' is not counted as a failed sign-in.",
               "A sign-in has no firewall verdict; none is mapped."),
    ),
    # The same sign-in, as Azure Monitor diagnostic settings export it (to a
    # storage account / event hub, one JSON record per line): an envelope
    # (time, category, resultType, callerIpAddress) around `properties`, which
    # is the Microsoft Graph signIn object. Keys are flattened by
    # parsers.flatten. Tested on Splunk attack_data's two Entra password-spray
    # captures (T1110.003, Apache-2.0) - see CLAUDE.md gotcha #39.
    Profile(
        id="entra-signin-azure-monitor",
        name="Microsoft Entra ID sign-in log (Azure Monitor JSON export)",
        docs=(
            ("Microsoft Graph - signIn resource type (createdDateTime, ipAddress, "
             "userPrincipalName, status)",
             "https://learn.microsoft.com/en-us/graph/api/resources/signin?view=graph-rest-1.0"),
            ("Microsoft Graph - signInStatus resource type (errorCode)",
             "https://learn.microsoft.com/en-us/graph/api/resources/signinstatus?view=graph-rest-1.0"),
            ("Microsoft Entra authentication & authorization error codes (AADSTS)",
             "https://learn.microsoft.com/en-us/entra/identity-platform/reference-error-codes"),
            ("Microsoft Learn - Monitoring and health activity log schemas (Azure Monitor "
             "vs Graph)",
             "https://learn.microsoft.com/en-us/entra/identity/monitoring-health/"
             "concept-activity-log-schemas"),
        ),
        signature=("time", "category", "resultType", "callerIpAddress",
                   "properties.userPrincipalName", "properties.status.errorCode"),
        fields={
            # Graph: "Date and time (UTC) the sign-in was initiated". The
            # envelope's `time` is the record's and can differ (by 28 minutes
            # in the Splunk capture), so it is only the fallback.
            "ts": ("properties.createdDateTime", "time"),
            # Graph: "IP address of the client used to sign in".
            "srcip": ("properties.ipAddress", "callerIpAddress"),
            # The account. userDisplayName is a display name - the same trap
            # as the CSV's User vs Username (gotcha #27).
            "username": ("properties.userPrincipalName",),
            "auth_status": ("properties.status.errorCode",),
            "app": ("properties.appDisplayName",),
        },
        auth_values={
            "0": "auth_success",
            # Credential-validation failures, by Microsoft's AADSTS names:
            # InvalidUserNameOrPassword, UserAccountNotFound, IdsLocked,
            # invalid or null password, CredentialAuthenticationError.
            "50126": "auth_failed", "50034": "auth_failed", "50053": "auth_failed",
            "50056": "auth_failed", "50064": "auth_failed",
        },
        notes=("Sign-in outcome from status.errorCode: 0 is a success; only codes "
               "Microsoft names as credential failures (50126, 50034, 50053, 50056, "
               "50064) count as failed. Interrupts such as 50140 KmsiInterrupt or "
               "50074 MFA required, and any other code, are not counted - like "
               "'Interrupted' in the CSV export.",
               "A sign-in has no firewall verdict; none is mapped."),
    ),
    # IAI-31. A SmartConsole / SmartView "Export" of the Logs view: columns
    # are the display names sk144192 gives each log field. Tested on the
    # real export of CLAUDE.md's Real-world benchmark (D:/logtest, 45,209
    # rows), whose figures the human SOC report also reproduced.
    Profile(
        id="checkpoint-smartconsole",
        name="Check Point SmartConsole / SmartView log export",
        docs=(
            ("Check Point sk144192 - Description of Fields in Check Point Logs "
             "(field name -> display name)",
             "https://support.checkpoint.com/results/sk/sk144192"),
        ),
        signature=("Time", "Blade", "Action", "Origin", "Source", "Destination", "Service"),
        fields={
            # sk144192: time "Timestamp when the log was created".
            "ts": ("Time",),
            # src "Client source IP address"; the export writes the object
            # name with the address in brackets - decode.extract_ip.
            "srcip": ("Source",),
            "dstip": ("Destination",),
            "username": ("Source User Name", "User"),
            # rule_action, display name "Action".
            "verdict": ("Action",),
            # The service *name* (http, FW1_ica_services); the export has no
            # numeric port, so R2002 cannot fire and R2003 counts these
            # instead (gotcha #8).
            "app": ("Service",),
        },
        verdict_values={
            "accept": "allow", "drop": "drop", "reject": "reject",
            # IPS blocked it.
            "prevent": "prevent",
            # IPS saw it and let it pass.
            "detect": "detect",
            # A VPN key exchange (IKE), not a decision on traffic - the SOC
            # report on this very export makes the same reading.
            "key install": "",
        },
        notes=("The Time column carries no time zone: SmartConsole writes the "
               "time in the zone of the computer that exported the log, which the "
               "file does not record. It is read as GMT+7 and flagged "
               "timezone-unconfirmed.",
               "'Key Install' is a VPN key exchange, not a firewall verdict; none is mapped.",
               "No numeric destination port is exported - Service is a name."),
    ),
    Profile(
        id="exchange-message-trace",
        name="Exchange Online message trace",
        docs=(
            ("Microsoft Learn - Get-MessageTrace (Exchange PowerShell)",
             "https://learn.microsoft.com/powershell/module/exchange/Get-MessageTrace"),
        ),
        signature=("MessageId", "Received", "SenderAddress", "RecipientAddress",
                   "Status", "MessageTraceId"),
        fields={
            "ts": ("Received",),
            "srcip": ("FromIP",),
            "dstip": ("ToIP",),
        },
        notes=("Status is a mail delivery status, not an authentication or "
               "firewall outcome, and is deliberately not mapped (gotcha #11).",),
    ),
)

# Line-log decoders and the documented message formats they match. Keys are
# what decode.decode_line() records as an event's profile.
LINE_PROFILES: dict[str, dict] = {
    "openssh-sshd": {
        "name": "OpenSSH sshd authentication messages",
        "docs": [("OpenSSH portable - auth.c, auth_log()",
                  "https://github.com/openssh/openssh-portable/blob/master/auth.c"),
                 # IAI-29: pre-auth probes, sftp, closed / timed-out sessions.
                 ("OpenSSH portable - kex.c (identification string exchange)",
                  "https://github.com/openssh/openssh-portable/blob/master/kex.c"),
                 ("OpenSSH portable - session.c (subsystem request)",
                  "https://github.com/openssh/openssh-portable/blob/master/session.c"),
                 ("OpenSSH portable - packet.c (connection closed)",
                  "https://github.com/openssh/openssh-portable/blob/master/packet.c")],
    },
    "linux-pam": {
        "name": "Linux-PAM pam_unix password change and session messages",
        "docs": [("Linux-PAM - modules/pam_unix/pam_unix_passwd.c",
                  "https://github.com/linux-pam/linux-pam/blob/master/modules/pam_unix/"
                  "pam_unix_passwd.c"),
                 ("Linux-PAM - modules/pam_unix/pam_unix_sess.c",
                  "https://github.com/linux-pam/linux-pam/blob/master/modules/pam_unix/"
                  "pam_unix_sess.c")],
    },
    # IAI-29. ESXi writes its shell-session and console-login lines into
    # auth.log; Broadcom documents them.
    "vmware-esxi": {
        "name": "VMware ESXi shell sessions, shell command history, console login, SSH / ESXi Shell on-off",
        "docs": [("Broadcom KB 321910 - Auditing ESXi Shell logins and commands",
                  "https://knowledge.broadcom.com/external/article/321910/"
                  "auditing-esxi-shell-logins-and-commands.html"),
                 # IAI-34: shell.log - command history, enable/disable events.
                 ("Broadcom KB 306962 - Location and Contents of ESXi log files",
                  "https://knowledge.broadcom.com/external/article/306962")],
    },
    # Lines a real ESXi auth.log carries whose format VMware does not
    # publish ("User 'root' running command '...'", pam_per_user). Read,
    # because the command line is evidence, but never called documented:
    # no docs, and the case page says the format was observed.
    "vmware-esxi-observed": {
        "name": "VMware ESXi remote command and PAM per-user lines",
        "docs": [],
        "observed": True,
    },
    "fortigate-traffic": {
        "name": "FortiGate FortiOS traffic log (key=value)",
        "docs": [("FortiOS Log Message Reference",
                  "https://docs.fortinet.com/document/fortigate/7.2.4/"
                  "fortios-log-message-reference/949981")],
    },
}

# What each documented format is in the Sigma logsource taxonomy
# (sigma-appendix-taxonomy.md v2.1.0, read 2026-10-20 - docs/standards/SOURCES.md).
# `sigma` holds only values the taxonomy defines; where it has no product for
# the log source (no firewall vendor, no ESXi), `custom` names it and the case
# says the value is not the taxonomy's (identify.py, IAI-92).
LOGSOURCE: dict[str, dict] = {
    "paloalto-traffic": {"sigma": {"category": "firewall"}, "custom": "paloalto_panos"},
    "checkpoint-smartconsole": {"sigma": {"category": "firewall"}, "custom": "checkpoint_smartconsole"},
    "fortigate-traffic": {"sigma": {"category": "firewall"}, "custom": "fortinet_fortigate"},
    "entra-signin": {"sigma": {"product": "azure", "service": "signinlogs"}},
    "entra-signin-azure-monitor": {"sigma": {"product": "azure", "service": "signinlogs"}},
    "exchange-message-trace": {"sigma": {"product": "m365", "service": "exchange"}},
    "openssh-sshd": {"sigma": {"product": "linux", "service": "sshd"}},
    "linux-pam": {"sigma": {"product": "linux", "service": "auth"}},
    "vmware-esxi": {"sigma": {}, "custom": "vmware_esxi"},
    "vmware-esxi-observed": {"sigma": {}, "custom": "vmware_esxi"},
}

# The syslog header itself (IAI-34) - read before any message format above.
SYSLOG_DOCS = [
    {"title": "RFC 5424 - The Syslog Protocol", "url": "https://www.rfc-editor.org/rfc/rfc5424"},
    {"title": "RFC 3164 - The BSD syslog Protocol", "url": "https://www.rfc-editor.org/rfc/rfc3164"},
]

CSV_FIELDS = ("ts", "srcip", "dstip", "dstport", "username", "verdict", "app",
              "risk", "bytes_sent", "category", "auth_status")


def _norm(name: str) -> str:
    return " ".join(name.lower().split())


@dataclass
class Mapping:
    """How one CSV file's columns were read."""
    profile: Profile | None
    columns: dict[str, tuple[str, ...]]   # field -> source column(s), () if unmapped
    source: dict[str, str | None]          # field -> "documented" | None

    def describe(self) -> dict:
        """The manifest/API form: what the analyst sees."""
        out = {
            "method": "documented" if self.profile else "unrecognised",
            "profile": self.profile.id if self.profile else None,
            "name": self.profile.name if self.profile else None,
            "docs": [{"title": t, "url": u} for t, u in self.profile.docs] if self.profile else [],
            "notes": list(self.profile.notes) if self.profile else [],
            "fields": {
                f: {"columns": list(cols), "source": self.source[f]}
                for f, cols in self.columns.items() if cols
            },
        }
        # Nothing is guessed any more (IAI-92); kept so older manifests and
        # this one read alike.
        out["heuristic_fields"] = []
        out["missing_fields"] = sorted(
            f for f in (self.profile.fields if self.profile else ()) if not self.columns.get(f))
        return out


def match_profile(header: list[str]) -> Profile | None:
    present = {_norm(h) for h in header if h}
    for p in PROFILES:
        if all(_norm(c) in present for c in p.signature):
            return p
    return None


def resolve(header: list[str]) -> Mapping:
    """Map a CSV header - or a JSON file's keys (flattened, dotted) - by its
    documented profile, and only by it (IAI-92): a column the documentation
    names but the export dropped stays empty and is listed as missing, a field
    the profile does not list is deliberately unmapped, and a header no profile
    matches maps nothing. There is no guessing fallback any more; identify.py
    decides before ingest whether a file is read at all."""
    by_norm = {_norm(h): h for h in header if h}
    profile = match_profile(header)
    columns: dict[str, tuple[str, ...]] = {}
    source: dict[str, str | None] = {}
    for f in CSV_FIELDS:
        cols: tuple[str, ...] = ()
        if profile and f in profile.fields:
            cols = tuple(by_norm[_norm(c)] for c in profile.fields[f] if _norm(c) in by_norm)
        columns[f] = cols
        source[f] = "documented" if cols else None
    return Mapping(profile, columns, source)


def line_mapping(counts: dict[str | None, int]) -> dict:
    """The manifest form for a line log: lines read by each documented
    message format, and how many no decoder recognised. A file where no
    line matched is "unrecognised", not "heuristic": nothing was guessed -
    only each line's timestamp and first IP address were pulled out, and no
    rule can fire on it (an ESXi hostd.log, say)."""
    used = {k: v for k, v in counts.items() if k}
    documented = any(not LINE_PROFILES[k].get("observed") for k in used)
    return {
        # "observed" only if every line read was of an unpublished format.
        "method": "documented" if documented else ("observed" if used else "unrecognised"),
        "line_profiles": [
            {"profile": k, "lines": n, "name": LINE_PROFILES[k]["name"],
             "docs": [{"title": t, "url": u} for t, u in LINE_PROFILES[k]["docs"]],
             # Format seen in real logs, not published by the log source.
             "observed": bool(LINE_PROFILES[k].get("observed"))}
            for k, n in sorted(used.items(), key=lambda kv: -kv[1])
        ],
        "unrecognised_lines": counts.get(None, 0),
        "syslog_docs": SYSLOG_DOCS,
    }
