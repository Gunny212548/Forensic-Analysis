"""Vendor profiles: column mappings taken from each vendor's own documentation.

The decoder has two ways to read a CSV:

- **documented** - the header matches a profile below. Every canonical field
  is read from the column the vendor's documentation defines for it, and its
  values are translated with the vocabulary that documentation lists. Each
  profile cites the page it was built from, so any mapping can be checked
  against the source instead of taken on trust.
- **heuristic** - no profile matches (a vendor we have no profile for, or a
  file whose columns were renamed). The original name-guessing in
  `decode.match_column()` still runs, because refusing an unknown file would
  leave the analyst with nothing; but the case is marked as such, and the UI
  tells the analyst to verify the mapping.

A documented profile can still fall back field by field: if an export left
out a column the profile names, that field is guessed and marked `heuristic`
on its own, rather than silently left empty.

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
                  "https://github.com/openssh/openssh-portable/blob/master/auth.c")],
    },
    "linux-pam": {
        "name": "Linux-PAM pam_unix password change",
        "docs": [("Linux-PAM - modules/pam_unix/pam_unix_passwd.c",
                  "https://github.com/linux-pam/linux-pam/blob/master/modules/pam_unix/"
                  "pam_unix_passwd.c")],
    },
    "fortigate-traffic": {
        "name": "FortiGate FortiOS traffic log (key=value)",
        "docs": [("FortiOS Log Message Reference",
                  "https://docs.fortinet.com/document/fortigate/7.2.4/"
                  "fortios-log-message-reference/949981")],
    },
}

CSV_FIELDS = ("ts", "srcip", "dstip", "dstport", "username", "verdict", "app",
              "risk", "bytes_sent", "category", "auth_status")


def _norm(name: str) -> str:
    return " ".join(name.lower().split())


@dataclass
class Mapping:
    """How one CSV file's columns were read."""
    profile: Profile | None
    columns: dict[str, tuple[str, ...]]   # field -> source column(s), () if unmapped
    source: dict[str, str | None]          # field -> "documented" | "heuristic" | None

    def describe(self) -> dict:
        """The manifest/API form: what the analyst sees."""
        out = {
            "method": "documented" if self.profile else "heuristic",
            "profile": self.profile.id if self.profile else None,
            "name": self.profile.name if self.profile else None,
            "docs": [{"title": t, "url": u} for t, u in self.profile.docs] if self.profile else [],
            "notes": list(self.profile.notes) if self.profile else [],
            "fields": {
                f: {"columns": list(cols), "source": self.source[f]}
                for f, cols in self.columns.items() if cols
            },
        }
        out["heuristic_fields"] = sorted(f for f, s in self.source.items() if s == "heuristic")
        return out


def match_profile(header: list[str]) -> Profile | None:
    present = {_norm(h) for h in header if h}
    for p in PROFILES:
        if all(_norm(c) in present for c in p.signature):
            return p
    return None


def resolve(header: list[str], heuristic) -> Mapping:
    """Map a CSV header. `heuristic(header, field)` is the guessing fallback
    (decode.match_column), passed in so this module has no import cycle."""
    by_norm = {_norm(h): h for h in header if h}
    profile = match_profile(header)
    columns: dict[str, tuple[str, ...]] = {}
    source: dict[str, str | None] = {}
    for f in CSV_FIELDS:
        cols: tuple[str, ...] = ()
        src = None
        if profile:
            if f in profile.fields:
                cols = tuple(by_norm[_norm(c)] for c in profile.fields[f] if _norm(c) in by_norm)
                src = "documented" if cols else None
                if not cols:
                    # The export dropped a column the profile names: guess
                    # it, and say so for this field.
                    guess = heuristic(header, f)
                    cols, src = ((guess,), "heuristic") if guess else ((), None)
            # A field the profile does not list is deliberately unmapped -
            # the documentation gives it no meaning in this log type.
        else:
            guess = heuristic(header, f)
            if guess:
                cols, src = (guess,), "heuristic"
        columns[f] = cols
        source[f] = src
    return Mapping(profile, columns, source)


def line_mapping(counts: dict[str | None, int]) -> dict:
    """The manifest form for a line log: lines read by each documented
    message format, and how many no decoder recognised. A file where no
    line matched is "unrecognised", not "heuristic": nothing was guessed -
    only each line's timestamp and first IP address were pulled out, and no
    rule can fire on it (an ESXi hostd.log, say)."""
    used = {k: v for k, v in counts.items() if k}
    return {
        "method": "documented" if used else "unrecognised",
        "line_profiles": [
            {"profile": k, "lines": n, "name": LINE_PROFILES[k]["name"],
             "docs": [{"title": t, "url": u} for t, u in LINE_PROFILES[k]["docs"]]}
            for k, n in sorted(used.items(), key=lambda kv: -kv[1])
        ],
        "unrecognised_lines": counts.get(None, 0),
    }
