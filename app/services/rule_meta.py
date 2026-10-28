"""Rule metadata: every detection rule described by two published standards.

**Sigma rules specification v2.1.0** gives the metadata fields - `id`
(UUID v4), `title`, `status`, `description`, `author`, `date`, `modified`,
`references`, `logsource`, `falsepositives`, `level`, `tags`. The detection
logic itself stays SQL in rules.py: it runs on this tool's canonical schema,
which no Sigma backend targets, so a `detection:` block written from it
would look portable and not be. That is why this is metadata, not an export.

**Palantir's Alerting and Detection Strategy (ADS) framework** gives the
documentation each rule must carry: Goal, Categorization, Strategy Abstract,
Technical Context, Blind Spots and Assumptions, False Positives, Validation,
Priority, Response. Categorization is the ATT&CK `tags`, Priority is the
Sigma `level`, False Positives is Sigma's `falsepositives`; the rest is
written per rule below.

`status` follows the Sigma definitions, and the criterion is evidence:

  stable        "may be used in production" - not given to any rule yet.
                Every rule here has been validated on one customer's data
                plus synthetic ground truth; Sigma's bar is proven use, and
                one environment does not meet it.
  test          "mostly stable ... could require slight adjustments depending
                on the environment" - fired correctly on real data, with its
                false positives examined (the gotcha cited in `validation` -
                a pointer kept in the source, stripped from what the UI shows).
  experimental  "could lead to false positives results or be noisy" - never
                validated on real data: synthetic hits only, or none.

`date` is 2026-09-15 for every rule: the repository's first commit, the
earliest date the history can show (the rules predate it). `modified` is
the last change to a rule's logic or level.
"""

import re

from .rules import RULE_LABELS, RULE_LEVEL

AUTHOR = "forensic-analyzer"
CREATED = "2026-09-15"
LEVELS_MODIFIED = "2026-10-12"  # Sigma levels replaced the 0-15 scale (gotcha #26)

_ATTACK = "https://attack.mitre.org/techniques/"

# ATT&CK technique -> tactic tag(s), as Sigma's tag namespace spells them.
TACTICS = {
    "t1110": ["credential_access"],
    "t1087": ["discovery"],
    "t1595": ["reconnaissance"],
    "t1046": ["discovery"],
    "t1133": ["initial_access", "persistence"],
    "t1078": ["defense_evasion", "persistence", "privilege_escalation", "initial_access"],
    "t1071": ["command_and_control"],
    "t1041": ["exfiltration"],
    "t1105": ["command_and_control"],
    "t1190": ["initial_access"],
    # Windows story 5b - each technique page's Tactic field (content v20.0, read 2026-10-26).
    "t1021": ["lateral_movement"],
    "t1569": ["execution"],
    "t1550": ["lateral_movement"],
    "t1558": ["credential_access"],
    "t1003": ["credential_access"],
    # Story 5f - T1685's Tactic field (content v20.0, read 2026-10-28).
    "t1685": ["defense_impairment"],
}

# The Enterprise tactics in the order ATT&CK lists them (attack.mitre.org/tactics/enterprise,
# content v20.0, read 2026-10-22): the stages of the Attack timeline. v20 has 15 - Defense Evasion
# became Stealth (TA0005) and Defense Impairment (TA0112); TACTICS above still says
# defense_evasion for T1078, which is shown at TA0005's place.
TACTIC_ORDER: list[tuple[str, str, str]] = [
    ("reconnaissance", "TA0043", "Reconnaissance"),
    ("resource_development", "TA0042", "Resource Development"),
    ("initial_access", "TA0001", "Initial Access"),
    ("execution", "TA0002", "Execution"),
    ("persistence", "TA0003", "Persistence"),
    ("privilege_escalation", "TA0004", "Privilege Escalation"),
    ("defense_evasion", "TA0005", "Stealth (Defense Evasion)"),
    ("defense_impairment", "TA0112", "Defense Impairment"),
    ("credential_access", "TA0006", "Credential Access"),
    ("discovery", "TA0007", "Discovery"),
    ("lateral_movement", "TA0008", "Lateral Movement"),
    ("collection", "TA0009", "Collection"),
    ("command_and_control", "TA0011", "Command and Control"),
    ("exfiltration", "TA0010", "Exfiltration"),
    ("impact", "TA0040", "Impact"),
]
_TACTIC_RANK = {t: i for i, (t, _, _) in enumerate(TACTIC_ORDER)}


def tactics_of(techniques: list[str] | None) -> list[str]:
    """The ATT&CK tactics of a finding's techniques, in ATT&CK's order."""
    found = {t for tech in techniques or [] for t in TACTICS.get(tech.lower().split(".")[0], [])}
    return sorted(found, key=lambda t: _TACTIC_RANK.get(t, len(TACTIC_ORDER)))


AUTH_SOURCES = ["openssh-sshd", "entra-signin"]
FIREWALL_SOURCES = ["paloalto-traffic", "checkpoint-smartconsole", "fortigate-traffic"]
PALOALTO_SOURCES = ["paloalto-traffic"]
CHECKPOINT_SOURCES = ["checkpoint-log-exporter", "checkpoint-smartconsole"]

RULE_META: dict[str, dict] = {
    "R1000": {
        "id": "d8e0240f-a400-4d41-a280-0216641e2277",
        "title": "Authentication failure",
        "status": "deprecated",
        "techniques": ["T1110.001"],
        "category": "authentication", "log_sources": AUTH_SOURCES,
        "falsepositives": ["A user mistyping their own password"],
        "ads": {
            "goal": "Record every failed authentication so the correlation rules can count them.",
            "strategy": "One finding per row whose decoded action is auth_failed.",
            "technical_context": "sshd 'Failed password' / PAM failure lines; Entra ID Status=Failure. "
                                 "Needs an account on the row (gotcha #11).",
            "blind_spots": "Log sources with no auth outcome (firewall traffic) can never produce it.",
            "validation": "ESXi auth.log and the Entra ID export in the corpus; nightfall-auth.log "
                          "expects 8 (tests/README.md).",
            "response": "Deprecated 2026-10-20 - no longer a finding; now an event type (layer A): every failed sign-in is shown on the event; R2000, R2005 and R2009 count them "
                        "(specs/rules_review.md).",
        },
    },
    "R1001": {
        "id": "f22d1320-bb96-40e9-840b-d8877663c116",
        "title": "Successful authentication",
        "status": "deprecated",
        "techniques": [],
        "category": "authentication", "log_sources": AUTH_SOURCES,
        "falsepositives": ["Ordinary logins - this rule exists for context, not as an alert"],
        "ads": {
            "goal": "Give the attack-path patterns the successes to pair with failures.",
            "strategy": "One finding per auth_success row. Untagged: one login is not a technique.",
            "technical_context": "sshd 'Accepted password/publickey'; Entra ID Status=Success.",
            "blind_spots": "Cannot tell an owner from an attacker holding the password - that is "
                           "what credential-compromise (severity.py) and R2006 are for.",
            "validation": "ESXi and Entra ID corpus files; nightfall-auth.log expects 3.",
            "response": "Deprecated 2026-10-20 - no longer a finding; now an event type (layer A); the login after an attack is R2008 "
                        "(specs/rules_review.md).",
        },
    },
    "R1002": {
        "id": "5015bccb-5e4d-47ae-a4db-08d914d52ec9",
        "title": "Login attempt for a non-existent account",
        "status": "deprecated",
        "techniques": ["T1110.003", "T1087"],
        "category": "authentication", "log_sources": ["openssh-sshd"],
        "falsepositives": ["Misconfigured automation using a removed account name"],
        "ads": {
            "goal": "Spot account-name guessing.",
            "strategy": "One finding per sshd 'Invalid user' line.",
            "technical_context": "OpenSSH only; Entra ID reports unknown users as an error code, "
                                 "which no profile maps yet.",
            "blind_spots": "Every log source except sshd.",
            "validation": "Synthetic only (nightfall-auth.log expects 3); no hit in the real corpus.",
            "response": "Deprecated 2026-10-20 - no longer a finding; now an event type (layer A); R2009 counts non-existent accounts as part of a spray "
                        "(specs/rules_review.md).",
        },
    },
    "R1003": {
        "id": "b3166831-2475-49c7-9ec8-330cb9478027",
        "title": "SSH connection opened",
        "status": "deprecated",
        "techniques": [],
        "category": "authentication", "log_sources": ["openssh-sshd"],
        "falsepositives": ["Every legitimate SSH session"],
        "ads": {
            "goal": "Context: who reached the SSH service at all.",
            "strategy": "One finding per sshd 'Connection from' line.",
            "technical_context": "The captured port is the client's source port and is deliberately "
                                 "not stored as a destination port (gotcha #4).",
            "blind_spots": "sshd only.",
            "validation": "ESXi auth.log; nightfall-auth.log expects 4.",
            "response": "Deprecated 2026-10-20 - no longer a finding; now an event type (layer A) "
                        "(specs/rules_review.md).",
        },
    },
    "R1004": {
        "id": "0c639136-db9e-48ff-8ecc-7e49c88b2465",
        "title": "Account password changed",
        "status": "deprecated",
        "techniques": [],
        "category": "authentication", "log_sources": ["linux-pam"],
        "falsepositives": ["Scheduled or self-service password rotation",
                           "Service accounts rotated by tooling (vpxuser on ESXi)"],
        "ads": {
            "goal": "Surface password changes, which can be persistence after a compromise.",
            "strategy": "One finding per pam_unix 'password changed for' line.",
            "technical_context": "Untagged on purpose: T1098 only applies when the change was "
                                 "not the owner's, which one line cannot show.",
            "blind_spots": "No log source other than PAM; changes made in a directory service.",
            "validation": "ESXi auth.log: 138 rows, every one the vpxuser service account's "
                          "rotation; nightfall-auth.log expects 1.",
            "response": "Deprecated 2026-10-20 - no longer a finding; now an event type (layer A) "
                        "(specs/rules_review.md).",
        },
    },
    "R2000": {
        "id": "55d6987b-8b32-4286-8212-eb1b34261917",
        "title": "Brute force from one source",
        "status": "test",
        "techniques": ["T1110.001"],
        "category": "authentication", "log_sources": AUTH_SOURCES,
        "falsepositives": ["A user or script retrying a wrong password three or more times"],
        "ads": {
            "goal": "Detect password guessing from a single source.",
            "strategy": "Sources with >=3 auth failures; every failure row of that source is flagged.",
            "technical_context": "Counts per source across all accounts.",
            "blind_spots": "Low-and-slow guessing spread across sources - R2005 covers that axis "
                           "(gotcha #14). No time window: three failures months apart still count.",
            "validation": "ESXi auth.log; nightfall-auth.log expects 8.",
            "response": "Look for a later success from the same source - R2008 flags it and "
                        "severity.py raises the path to high (credential-compromise).",
        },
    },
    "R2001": {
        "id": "0fba7271-1c22-4e20-9779-d1c5c60a081f",
        "title": "Repeated blocked connections from one source",
        "status": "deprecated",
        "techniques": ["T1595"],
        "category": "firewall", "log_sources": FIREWALL_SOURCES,
        "falsepositives": ["Internet background scanning of any public address",
                           "A misconfigured internal client retrying a blocked service"],
        "ads": {
            "goal": "Show sources the perimeter keeps refusing.",
            "strategy": "Sources with >=5 denied rows; only the denied rows are flagged.",
            "technical_context": "Needs a verdict column. Tagged T1595, not T1110 - the original "
                                 "brute-force tag made the narrative misread port-scan denies.",
            "blind_spots": "Sources the firewall allowed.",
            "validation": "Palo Alto corpus; nightfall-firewall.csv expects 15.",
            "response": "Deprecated 2026-10-20 - no longer a finding; now a context fact (layer C): the events table shows how often a source was refused "
                        "(specs/rules_review.md).",
        },
    },
    "R2002": {
        "id": "20ff3d92-b26c-4c06-a8d3-6fd137e35f74",
        "title": "Port scan (refused)",
        "status": "test",
        "techniques": ["T1046"],
        "category": "firewall", "log_sources": FIREWALL_SOURCES,
        "falsepositives": ["Vulnerability scanners run by the customer",
                           "Monitoring systems probing many ports"],
        "ads": {
            "goal": "Detect a source probing many destination ports.",
            "strategy": ">=10 distinct destination ports among a source's denied rows; only the "
                        "denied rows are flagged (gotcha #23).",
            "technical_context": "Needs a destination-port column - Check Point has none, see R2003.",
            "blind_spots": "Scans the firewall allowed; slow scans under 10 ports; log sources "
                           "without a port column (gotcha #8).",
            "validation": "Tuned over 13,666 corpus sources: deny-dominated sources top out at 1 "
                          "port (gotcha #23). nightfall-firewall.csv expects 15.",
            "response": "Low unless the same source was later allowed in (R2004).",
        },
    },
    "R2003": {
        "id": "88be6974-1f75-4174-8711-8077a3186b47",
        "title": "Service sweep (refused)",
        "status": "test",
        "techniques": ["T1046"],
        "category": "firewall", "log_sources": FIREWALL_SOURCES,
        "falsepositives": ["Customer-run scanners"],
        "ads": {
            "goal": "R2002's signal for log sources that name services instead of ports.",
            "strategy": ">=20 distinct services among a source's denied rows.",
            "technical_context": "Reads the app/service column (Check Point 'Service').",
            "blind_spots": "Same as R2002; double-counts with it where both columns exist, which "
                           "is why confidence counts rule families, not ids (gotcha #20).",
            "validation": "Check Point export: 900 distinct services among denied rows "
                          "(gotcha #23). That file is no longer in the store.",
            "response": "As R2002.",
        },
    },
    "R2004": {
        "id": "328ae7d5-8acd-46f2-a0d6-57e83dca8ae4",
        "title": "Traffic allowed from a mostly-blocked source",
        "status": "test",
        "techniques": [],
        "category": "firewall", "log_sources": FIREWALL_SOURCES,
        "falsepositives": ["A user who hits a few blocked sites among normal browsing "
                           "(excluded by the >=20 denies and 3x guard)"],
        "ads": {
            "goal": "Find a policy gap: a source the firewall overwhelmingly refuses that still "
                    "got some traffic through.",
            "strategy": ">=20 denies, >=1 allow, denies >= 3x allows; only the allowed rows are flagged.",
            "technical_context": "Needs both allowed and denied rows of the same source in one file "
                                 "- an action-filtered export silences it (gotcha #9).",
            "blind_spots": "Exports filtered to one verdict.",
            "validation": "Check Point benchmark: flagged exactly the 2,978 accepted rows the human "
                          "SOC report identified as the Implied Rule bypass.",
            "response": "High: find the firewall rule that allowed those sessions.",
        },
    },
    "R2005": {
        "id": "ac38c2b7-cdc7-4edb-9890-f7ad338a2bba",
        "title": "Distributed password guessing against one account",
        "status": "test",
        "techniques": ["T1110.001"],
        "category": "authentication", "log_sources": AUTH_SOURCES,
        "falsepositives": ["A roaming user failing once from each of several networks"],
        "ads": {
            "goal": "Catch guessing spread across sources, which per-source counting misses.",
            "strategy": "Accounts with failures from >=5 distinct sources.",
            "technical_context": "Pairs with R2000 on the other axis (gotcha #14). Named a password "
                                 "spray until 2026-10-20; ATT&CK's spraying (T1110.003) is many "
                                 "accounts, which is R2009 - one account is guessing (T1110.001).",
            "blind_spots": "Sprays under 5 sources; no time window.",
            "validation": "Entra ID export (14 sources, one account) and ESXi root (6 sources).",
            "response": "Check every source that later succeeded on the account.",
        },
    },
    "R2006": {
        "id": "f4277f02-e5d2-4add-88ab-e837cbb4db30",
        "title": "Successful logins from many sources within an hour",
        "status": "test",
        "techniques": ["T1078"],
        "category": "authentication", "log_sources": AUTH_SOURCES,
        "falsepositives": ["Corporate proxies or VPN pools presenting many egress addresses"],
        "ads": {
            "goal": "Detect one account being used from many places at once.",
            "strategy": ">=4 distinct sources succeeding for one account in the same clock hour.",
            "technical_context": "Hour buckets, not a sliding window: a burst across a boundary splits.",
            "blind_spots": "Bursts straddling the hour; slower credential sharing.",
            "validation": "Entra ID export: 16 sources in 89.251.0.0/24 within minutes - the case's "
                          "real finding (gotcha #14).",
            "response": "High: confirm with the account owner; check the sources' ownership.",
        },
    },
    "R2007": {
        "id": "cd794bee-8701-4d13-a1c3-d1d81826fd87",
        "title": "Beaconing to a public address",
        "status": "test",
        "techniques": ["T1071"],
        "category": "firewall", "log_sources": FIREWALL_SOURCES,
        "falsepositives": ["Update checks, telemetry and keep-alives to public services"],
        "ads": {
            "goal": "Find command-and-control by its regularity, which no threshold can express.",
            "strategy": ">=30 intervals, mean 30-3600 s, jitter (stddev/mean) < 0.6, public IPv4 "
                        "destination only.",
            "technical_context": "Needs parsed timestamps; non-public and broadcast destinations are "
                                 "excluded (gotcha #15).",
            "blind_spots": "Internal C2 and lateral beaconing (excluded on purpose); jittered "
                           "beacons above 0.6.",
            "validation": "Calibrated on the customer's compromised host: beacons 0.43-0.55, "
                          "browsing 0.89-0.94; the egress filter removed 16,599 false positives.",
            "response": "High: identify the destination - the rule localises, the analyst decides.",
        },
    },
    "R2008": {
        "id": "8dbc6e85-be17-4f98-a13b-63d93edf1342",
        "title": "Login succeeded after brute force",
        "status": "test",
        "techniques": ["T1078"],
        "category": "authentication", "log_sources": AUTH_SOURCES,
        "falsepositives": ["The owner mistyping a password three times and then getting it right "
                           "from the same address"],
        "ads": {
            "goal": "Flag the login that followed an attack - the moment the attacker got in.",
            "strategy": "A success for an account from a source R2000 counts as brute-forcing, "
                        "after that source's first failure on the same account; the success rows "
                        "are flagged.",
            "technical_context": "Shares R2000's source condition (rules.BRUTE_FORCE_SOURCES). Was "
                                 "severity.py raising an R1001 login finding until R1001 became an "
                                 "event type (2026-10-20).",
            "blind_spots": "A login from a different address than the attack; no time window yet - "
                           "a success months after the failures still counts.",
            "validation": "Same condition credential-compromise used on the ESXi auth.log and the "
                          "Entra ID export; nightfall-auth.log expects 1.",
            "response": "High: treat the account as compromised until the owner confirms the login.",
        },
    },
    "R2009": {
        "id": "0fad7436-42f6-4dd8-bae2-fd5bf1a35815",
        "title": "Password spray from one source",
        "status": "experimental",
        "techniques": ["T1110.003"],
        "category": "authentication", "log_sources": AUTH_SOURCES,
        "falsepositives": ["A shared jump host or NAT address where several users mistype passwords"],
        "ads": {
            "goal": "Detect one source trying many accounts - ATT&CK's password spraying.",
            "strategy": "Sources whose failed sign-ins and non-existent-account attempts name >=3 "
                        "distinct accounts (case-insensitive); those rows are flagged.",
            "technical_context": "Threshold measured 2026-10-20: 71 sources in the customers' own "
                                 "logs each failed on exactly 1 account; recorded attacks reached "
                                 "4 and 31 (rules.SPRAY_MIN_ACCOUNTS).",
            "blind_spots": "A spray spread across many sources, each trying few accounts; no time "
                           "window yet.",
            "validation": "Splunk attack_data Entra spray capture (31 accounts from one source); "
                          "nightfall-auth.log expects 11. Small real sample - experimental.",
            "response": "Medium: list the accounts tried and check each for a later success (R2008).",
        },
    },
    "R3000": {
        "id": "6b3736f8-3d98-420e-9c6d-ec5d076724c1",
        "title": "High-risk application allowed",
        "status": "deprecated",
        "techniques": ["T1071"],
        "category": "firewall", "log_sources": ["paloalto-traffic"],
        "falsepositives": ["Sanctioned use of applications App-ID rates risk 4-5"],
        "ads": {
            "goal": "Show allowed sessions of applications the firewall itself rates risky.",
            "strategy": "Allowed rows with an application risk >= 4.",
            "technical_context": "Needs PAN-OS 'Risk of app' (1-5).",
            "blind_spots": "Log sources without an application risk rating.",
            "validation": "Palo Alto corpus; fires alone on ordinary hosts, which is why it is "
                          "medium (gotcha #24). nightfall-firewall.csv expects 6.",
            "response": "Deprecated 2026-10-20 - no longer a finding; now a context fact (layer C): the events table shows the vendor's application risk "
                        "(specs/rules_review.md).",
        },
    },
    "R3001": {
        "id": "c76ce65f-59dd-466a-8bf1-98f296d7a13e",
        "title": "Large outbound transfer",
        "status": "test",
        "techniques": ["T1041"],
        "category": "firewall", "log_sources": ["paloalto-traffic", "fortigate-traffic"],
        "falsepositives": ["Backups and cloud sync uploads"],
        "ads": {
            "goal": "Spot sessions that sent more than 50 MB.",
            "strategy": "Rows with bytes sent > 50,000,000.",
            "technical_context": "Needs a client-to-server byte count.",
            "blind_spots": "Exfiltration split into many small sessions.",
            "validation": "Palo Alto corpus (8 on the beaconing host); nightfall-firewall.csv expects 2.",
            "response": "Medium alone; critical when the same host also shows another "
                        "post-intrusion behaviour (compromised-host).",
        },
    },
    "R3002": {
        "id": "e23154d0-0ee7-4604-8d9f-5666122f184a",
        "title": "Traffic in a malware or C2 category",
        "status": "experimental",
        "techniques": ["T1105"],
        "category": "firewall", "log_sources": ["paloalto-traffic", "fortigate-traffic"],
        "falsepositives": ["Category databases misclassifying a site"],
        "ads": {
            "goal": "Trust the firewall's own malware/C2 categorisation.",
            "strategy": "Rows whose category matches malware, virus, spyware, botnet, "
                        "command-and-control or c2.",
            "technical_context": "PAN-OS documents 'Category' as the URL category (gotcha #27).",
            "blind_spots": "Uncategorised infrastructure.",
            "validation": "Synthetic only (nightfall-firewall.csv expects 1). Its real-corpus hits "
                          "were a decoding bug (gotcha #22).",
            "response": "High: isolate the host pending review.",
        },
    },
    "R3003": {
        "id": "09a166b6-d43c-4b67-9d58-8ba943414561",
        "title": "Traffic allowed to a known-bad address",
        "status": "experimental",
        "techniques": ["T1071"],
        "category": "firewall", "log_sources": FIREWALL_SOURCES,
        "falsepositives": ["Shared hosting or CDN addresses listed in a feed",
                           "Stale indicators"],
        "ads": {
            "goal": "Match traffic against offline threat-intel feeds (gotcha #17).",
            "strategy": "Destination in the ioc table and not denied.",
            "technical_context": "Only as good as the feed snapshot in DATA_DIR/intel.",
            "blind_spots": "Infrastructure no feed lists yet.",
            "validation": "Every real hit so far was on denied traffic - now R3005 - so the allowed "
                          "case has not been seen on real data.",
            "response": "High: check the feed entry quoted in the finding, then the host.",
        },
    },
    "R3004": {
        "id": "3c80687a-2296-442e-b2db-3fe1926bba44",
        "title": "Traffic allowed from a known-bad address",
        "status": "test",
        "techniques": ["T1595"],
        "category": "firewall", "log_sources": FIREWALL_SOURCES,
        "falsepositives": ["Scanner lists (blocklist.de) name any host that ever probed anyone"],
        "ads": {
            "goal": "Show inbound sessions the firewall let in from listed addresses.",
            "strategy": "Source in the ioc table and not denied.",
            "technical_context": "Needs the intel feeds loaded.",
            "blind_spots": "Unlisted attackers.",
            "validation": "2,480 hits on log_22_.csv, all inbound scanners (gotcha #17).",
            "response": "Medium: check what the allowed sessions reached.",
        },
    },
    "R3005": {
        "id": "79b9201a-3d55-440b-bde7-36608b684ebb",
        "title": "Blocked attempt to reach a known-bad address",
        "status": "test",
        "techniques": ["T1071"],
        "category": "firewall", "log_sources": FIREWALL_SOURCES,
        "falsepositives": ["DNS/NetBIOS leakage to listed addresses", "Stale configuration"],
        "ads": {
            "goal": "Find hosts trying to reach malware infrastructure even when it was stopped.",
            "strategy": "Destination in the ioc table and denied.",
            "technical_context": "Split from R3003 by verdict.",
            "blind_spots": "As R3003.",
            "validation": "FortiGate corpus: 24 hits, all denied (e.g. NetBIOS to 207.90.244.13).",
            "response": "Medium: the attempt is the lead - find what on the host made it.",
        },
    },
    "R3006": {
        "id": "5f0c3b68-50c0-4e51-9d35-0e55dcc1e7a0",
        "title": "Blocked inbound traffic from a known-bad address",
        "status": "deprecated",
        "techniques": ["T1595"],
        "category": "firewall", "log_sources": FIREWALL_SOURCES,
        "falsepositives": ["All of it, usually - the perimeter doing its job"],
        "ads": {
            "goal": "Keep the perimeter's refusal rate of listed sources visible.",
            "strategy": "Source in the ioc table and denied.",
            "technical_context": "Informational by design.",
            "blind_spots": "None that matter for an alert.",
            "validation": "Not separately measured on the current corpus.",
            "response": "Deprecated 2026-10-20 - no longer a finding; now a context fact (layer C): the events table shows the threat-intel listing "
                        "(specs/rules_review.md).",
        },
    },
    # ---- Palo Alto (rules_paloalto.py, specs/per_product_rules.md story 2) ----
    "PAN-SCAN-2": {
        "id": "6016da59-0b4f-45e0-89bd-f4242047308d",
        "title": "Palo Alto: horizontal scan (TRW)",
        "status": "experimental",
        "techniques": ["T1046", "T1595.001"],
        "category": "firewall", "log_sources": PALOALTO_SOURCES,
        "falsepositives": ["Vulnerability scanners and monitoring run by the customer",
                           "Web crawlers and proxies reaching many hosts"],
        "ads": {
            "goal": "Detect one source probing many hosts, most of which refuse it (behaviour S2, "
                    "detection-behaviours.md; ATT&CK DET0817 AN1949, DET0376 AN1057).",
            "strategy": "Threshold Random Walk (Jung, Paxson, Berger & Balakrishnan 2004, §4): the "
                        "first attempt to each new destination host is a success (allow) or a failure "
                        "(refused); Wald's sequential test with success 0.8 benign / 0.2 scanner, "
                        "alpha 0.01, beta 0.99 decides scanner after 4 failures in a row. The source's "
                        "refused rows are flagged. T1046 from an internal source, T1595.001 from outside.",
            "technical_context": "A firewall refusal is read as the paper's failure (an attempt to an "
                                 "inactive host or service) - an adaptation. Needs source, destination, "
                                 "Action and time (PAN-OS Traffic Log Fields).",
            "blind_spots": "Vertical scans of one host (PAN-SCAN-1); distributed scans from many "
                           "sources; a scanner mixing in connections to known servers (paper §6).",
            "validation": "Customer Traffic exports (424,948 rows): 0 scanners, 167 benign, 1,106 "
                          "pending; benign first contacts succeeded 99.6%. Synthetic: tests/check_firewall_rules.py.",
            "response": "Low: reconnaissance. Look for an allow from the same source afterwards.",
        },
    },
    "PAN-SCAN-1": {
        "id": "49e5995a-97d8-47c5-8c30-a36928cb5cb9",
        "title": "Palo Alto: vertical scan",
        "status": "experimental",
        "techniques": ["T1046", "T1595"],
        "category": "firewall", "log_sources": PALOALTO_SOURCES,
        "falsepositives": ["Customer-run scanners", "Clients retrying several services of one server"],
        "ads": {
            "goal": "Detect one source probing many ports of one host (behaviour S1; ATT&CK DET0376 "
                    "AN1057 / AN1058, DET0830).",
            "strategy": "Distinct refused destination ports per source -> host within any hour. The line "
                        "is measured on the evidence (lines.py, D16): above 2 x the 99th percentile of "
                        "the (source, host) pairs of TRW-benign sources, and at least 2 ports; under 20 "
                        "such pairs, no line - every pair with 2 or more goes to the analyst (Q67, Q70).",
            "technical_context": "Needs Destination Port and Action (PAN-OS Traffic Log Fields).",
            "blind_spots": "Scans the firewall allowed; scans slower than 2 ports an hour; scans spread "
                           "over many sources.",
            "validation": "Customer Traffic exports: refused rows are 24 sources x 9 hosts x 5 ports, at "
                          "most 2 ports to a host in an hour - no scan. Synthetic: tests/check_firewall_rules.py.",
            "response": "Low unless the same source is later allowed (PAN-SCAN-3).",
        },
    },
    "PAN-SCAN-3": {
        "id": "7d2b75fa-f551-4c35-8d13-bb1087cf9154",
        "title": "Palo Alto: allowed after refusals",
        "status": "experimental",
        "techniques": [],
        "category": "firewall", "log_sources": PALOALTO_SOURCES,
        "falsepositives": ["A client refused on several services of a host and allowed on another"],
        "ads": {
            "goal": "Detect a source let through to a host it probed shortly before - a gap in the "
                    "policy found by probing (behaviour S5).",
            "strategy": "An allowed connection after refusals of the same source -> host on several "
                        "distinct services in the hour before. Line as PAN-SCAN-1 on the distinct "
                        "services refused before an allow, at least 2 (Q71: one refusal was a retry).",
            "technical_context": "No ATT&CK analytic names it: an internal method (the SOC benchmark's "
                                 "implied-rule bypass), stated as one.",
            "blind_spots": "A probe and its success more than an hour apart; a different target host.",
            "validation": "Customer Traffic exports: 1 pair (one refused service before: 2 more pairs, "
                          "dropped by Q71). Synthetic: tests/check_firewall_rules.py.",
            "response": "High: something got through. Read the allowed session and the rule it matched.",
        },
    },
    "PAN-MAL-1": {
        "id": "8158add6-94a0-4849-891f-33d752466053",
        "title": "Palo Alto: beaconing to a public address",
        "status": "test",
        "techniques": ["T1071"],
        "category": "firewall", "log_sources": PALOALTO_SOURCES,
        "falsepositives": ["Update checks, telemetry and monitoring agents with fixed timers"],
        "ads": {
            "goal": "Detect an implant checking in at regular intervals (behaviour M1; ATT&CK DET0444 "
                    "AN1226 'beacon-like intervals').",
            "strategy": "R2007's measured method on Palo Alto rows only: >=30 intervals, mean 30-3600 s, "
                        "jitter < 0.6, public destination.",
            "technical_context": "The SQL is R2007's own until story 4 retires the generic rule.",
            "blind_spots": "As R2007.",
            "validation": "As R2007 (calibrated on the customer's compromised host).",
            "response": "High: find the process on the host.",
        },
    },
    "PAN-MAL-2": {
        "id": "a1538b29-09f8-43e1-a1b1-f667c8bf0165",
        "title": "Palo Alto: malicious PAN-DB category",
        "status": "experimental",
        "techniques": ["T1071.001"],
        "category": "firewall", "log_sources": PALOALTO_SOURCES,
        "falsepositives": ["A category assigned wrongly by PAN-DB"],
        "ads": {
            "goal": "Report traffic to destinations Palo Alto's own URL database classifies as "
                    "malicious (behaviour M5).",
            "strategy": "Category is malware, command-and-control, ransomware, compromised-website or "
                        "phishing - the categories PAN-DB's 'URL Categories' page defines as malicious "
                        "content or C2. Grayware ('does not pose a direct security threat') is not.",
            "technical_context": "The Traffic log's Category is the URL category of the session; the "
                                 "customer's exports carry 'any' / 'not-resolved' almost everywhere.",
            "blind_spots": "Uncategorised destinations; Threat logs are not read.",
            "validation": "Customer exports: 31 rows with a real category, none of these. Synthetic: "
                          "nightfall-firewall.csv (1).",
            "response": "High when allowed; a refused one is capped at medium.",
        },
    },
    "PAN-INTEL-1": {
        "id": "981933e7-d750-437e-9257-3cfc2d4b4813",
        "title": "Palo Alto: known-bad destination (allowed)",
        "status": "test",
        "techniques": ["T1071"],
        "category": "firewall", "log_sources": PALOALTO_SOURCES,
        "falsepositives": ["Feed entries for shared or reassigned addresses"],
        "ads": {
            "goal": "Traffic allowed to an address a feed lists (behaviour T1; NIST SP 800-150 §2.1).",
            "strategy": "R3003's feed match on Palo Alto rows only.",
            "technical_context": "Offline feeds (gotcha #17); the match is evidence, not a verdict (SP "
                                 "800-150 §4.3).",
            "blind_spots": "The indicator's validity at the event's time is not checked yet (T4).",
            "validation": "As R3003.",
            "response": "High: confirm the indicator was valid when the event happened.",
        },
    },
    "PAN-INTEL-2": {
        "id": "0a129f2e-4aeb-4502-97c7-f625d27e3439",
        "title": "Palo Alto: known-bad source (allowed)",
        "status": "test",
        "techniques": ["T1595"],
        "category": "firewall", "log_sources": PALOALTO_SOURCES,
        "falsepositives": ["Feed entries for shared or reassigned addresses"],
        "ads": {
            "goal": "Traffic allowed from an address a feed lists (behaviour T2).",
            "strategy": "R3004's feed match on Palo Alto rows only.",
            "technical_context": "As PAN-INTEL-1.",
            "blind_spots": "As PAN-INTEL-1.",
            "validation": "As R3004.",
            "response": "Medium: what did the source reach?",
        },
    },
    "PAN-INTEL-3": {
        "id": "fe4a315c-080e-4aaa-8348-e644db1ace52",
        "title": "Palo Alto: known-bad destination (blocked)",
        "status": "test",
        "techniques": ["T1071"],
        "category": "firewall", "log_sources": PALOALTO_SOURCES,
        "falsepositives": ["Feed entries for shared or reassigned addresses"],
        "ads": {
            "goal": "An attempt to reach a listed address that the firewall refused (behaviour T3).",
            "strategy": "R3005's feed match on Palo Alto rows only.",
            "technical_context": "As PAN-INTEL-1.",
            "blind_spots": "As PAN-INTEL-1.",
            "validation": "As R3005.",
            "response": "Medium: the defence worked; which host tried, and why?",
        },
    },
}


# Check Point (rules_checkpoint.py, story 3): the shared firewall rules
# (rules_firewall.py) - the same method as their Palo Alto twins, on Check Point
# rows, with a destination service being the port or, in a SmartConsole export,
# the service name. Measured on the customer's Log Exporter export (20,000
# records, 2026-10-21 10:18-10:23).
_CHECKPOINT = {
    "SCAN-2": ("3ac9f3f5-0f66-46ad-8818-504a66982bb0",
               "Customer export: TRW decided 7 scanners, 41 benign, 315 pending; benign first contacts "
               "succeeded 99.4%. All 7 external, each dropped on one service across 4-5 public "
               "addresses (ICMP echo, 3389, 9443, 264, 1114)."),
    "SCAN-1": ("b80451f9-72ba-4552-9ff9-efa5ddd6a1f3",
               "Customer export: line above 2 services (p99 1 over 1,138 benign pairs); 3 external "
               "pairs, e.g. 8 consecutive ports 25376-25383 of one public address."),
    "SCAN-3": ("6308d47b-aaf6-429e-a9d2-60593187a9fc",
               "Customer export: none. One refusal before an accept was 9 internal clients' HTTPS to a "
               "CDN - why two distinct services are required (Q71)."),
    "MAL-1": ("6b43eb82-43c2-4173-98ed-712f67ba8be9", "Customer export: none (5 minutes of records)."),
    "INTEL-1": ("d228ddcc-c5cd-4fa4-bcd0-a60decba39b5", "As R3003."),
    "INTEL-2": ("fbd2238e-db87-4a0b-8bf7-1fbffcfc9833", "As R3004."),
    "INTEL-3": ("720132b7-34f8-4d41-8386-a59b2ad50999", "As R3005."),
}
for _suffix, (_uuid, _validation) in _CHECKPOINT.items():
    _pan = RULE_META[f"PAN-{_suffix}"]
    RULE_META[f"CP-{_suffix}"] = {
        **_pan, "id": _uuid, "title": _pan["title"].replace("Palo Alto", "Check Point"),
        "status": "experimental" if _suffix.startswith("SCAN") else _pan["status"],
        "log_sources": CHECKPOINT_SOURCES,
        "ads": {**_pan["ads"], "validation": _validation,
                "technical_context": _pan["ads"]["technical_context"] + " Check Point: a service is the "
                "Log Exporter `service` port, or the SmartConsole Service name (gotcha #8); Detect is "
                "neither a refusal nor an accept."},
    }

RULE_META["CP-MAL-2"] = {
    "id": "c8f26b0c-c3df-42c0-8ddc-bc63bd0f37cb",
    "title": "Check Point: Threat Prevention verdict",
    "status": "experimental",
    "techniques": ["T1071", "T1190"],
    "category": "firewall", "log_sources": ["checkpoint-log-exporter"],
    "falsepositives": ["A protection matching benign traffic (ThreatCloud confidence below High)"],
    "ads": {
        "goal": "Report what Check Point's own Threat Prevention blades decided: IPS, Anti-Bot, "
                "Anti-Virus or Threat Emulation prevented or detected a connection (behaviour M5).",
        "strategy": "Log Exporter record whose product (Blade) is one of those four and whose action is "
                    "Prevent or Detect (sk144192). Anti-Bot verdicts are T1071 (C&C, DET0444); IPS verdicts on "
                    "traffic from outside are T1190 (Initial Access, DET0080); Anti-Virus / Threat Emulation "
                    "carry no technique until T1105 is read.",
        "technical_context": "The blade, protection name, malware action and ThreatCloud severity are read "
                             "from the record kept in raw - no canonical column holds them. A Detect of the "
                             "URL Filtering / HTTPS inspection blade (certificate notes) is not a threat blade "
                             "and is not read.",
        "blind_spots": "SmartConsole exports (their Blade column is not read yet); blades in Bypass.",
        "validation": "Customer export: no Threat Prevention record. Synthetic Check Point quarter "
                      "(tests/gen_checkpoint_quarter.py): IPS Log4Shell / CVE-2024-24919, Anti-Bot QakBot "
                      "and the I2 beacon. tests/check_firewall_rules.py.",
        "response": "High when Detect (it passed); a Prevent is capped at medium - read what else the "
                    "source did.",
    },
}

# Windows (specs/windows_rules.md, story 5a): sign-ins from the Security log, one attempt however
# many events record it (rules_windows.py).
WINDOWS_SOURCES = ["windows-event-xml", "windows-evtx", "windows-splunk-text", "windows-winlogbeat-json",
                   "windows-nxlog-json"]
_WIN_ATTEMPT = ("Failures: 4625 SubStatus / Status 0xC000006A or 0xC0000064, 4771 Failure Code 0x18 or "
                "0x6, 4776 Error Code 0xC000006A or 0xC0000064, 4768 Result Code 0x6 (Microsoft's event "
                "pages; 4768 0x12 / 0x17 are refusals, not counted); a DC's 4771 / "
                "4776 within a second of a host's 4625 for the same account is the same attempt and counts "
                "once. The source is the address (::ffff: read as IPv4), else a 4776's Source Workstation "
                "name, else the host's console.")
_WIN_VALIDATION = ("Synthetic Windows quarter (tests/gen_windows_domain.py, ground truth): {found}; no "
                   "plain or look-alike event flagged. Real: attack_data purplesharp spray (XML and Splunk "
                   "text) - 50 attempts logged as 4625 + 4776 on the DC, merged. tests/check_windows_rules.py.")
RULE_META.update({
    "WIN-BRUTE-1": {
        "id": "5fdc5aef-7088-4d76-8353-3d0a7d41e4d8",
        "title": "Windows: password guessing",
        "status": "experimental",
        "techniques": ["T1110.001"],
        "category": "authentication", "log_sources": WINDOWS_SOURCES,
        "falsepositives": ["A service or scheduled task still using an old password",
                           "A user retrying a forgotten password many times within an hour"],
        "ads": {
            "goal": "Detect a series of failed sign-ins against one account from one source (behaviour B1; "
                    "T1110.001 DET0551 AN1521-AN1523).",
            "strategy": "Failed attempts of one (account, source) within any hour. The line is measured on "
                        "the evidence (lines.py, D16, Q66): above 2 x the 99th percentile of the sign-in "
                        "episodes that ended in a success (failures in the hour before it), and at least 2; "
                        "under 20 such episodes, no line.",
            "technical_context": _WIN_ATTEMPT,
            "blind_spots": "Guessing slower than the line per hour (B5, low-and-slow - WIN-BRUTE-4); guessing "
                           "spread over sources (WIN-BRUTE-3); failures with other codes (locked, disabled).",
            "validation": _WIN_VALIDATION.format(found="W2 RDP brute force (800) and W6 NTLM guessing "
                                                       "(280 attempts, 560 events)"),
            "response": "Read whether it ended in a success (WIN-AUTH-1) and what the source did next.",
        },
    },
    "WIN-BRUTE-2": {
        "id": "5149dab3-38c0-4676-9d78-feda3b013e3c",
        "title": "Windows: password spray",
        "status": "experimental",
        "techniques": ["T1110.003"],
        "category": "authentication", "log_sources": WINDOWS_SOURCES,
        "falsepositives": ["A shared terminal or jump host where many users mistype on their first sign-in"],
        "ads": {
            "goal": "Detect one source failing across many accounts (behaviour B2; T1110.003 DET0487 AN1336 / "
                    "AN1339).",
            "strategy": "TRW over accounts (Jung et al. 2004 §4, adapted from hosts to accounts): each "
                        "source's first attempt at each account is a success or a failure; the paper's "
                        "parameters decide sprayer / benign / pending, with no time window.",
            "technical_context": _WIN_ATTEMPT,
            "blind_spots": "A spray from many sources, a few accounts each; a source that also signs in "
                           "successfully to most accounts it tries.",
            "validation": _WIN_VALIDATION.format(found="W1 Kerberos spray (4771 on the DC, 71 accounts)"),
            "response": "Read whether any sprayed account then signed in from the source (WIN-AUTH-1).",
        },
    },
    "WIN-BRUTE-3": {
        "id": "a892a19e-0134-45a4-9bf6-66f78c06b8af",
        "title": "Windows: one account failing from many sources",
        "status": "experimental",
        "techniques": ["T1110.001"],
        "category": "authentication", "log_sources": WINDOWS_SOURCES,
        "falsepositives": ["A user moving between machines while the password is wrong",
                           "Several devices of one user holding an old password"],
        "ads": {
            "goal": "Detect guessing of one account spread over several sources (behaviour B3; AN1521 "
                    "\"from one or more remote IPs\").",
            "strategy": "Distinct failing sources of one account within any hour; computer accounts (names "
                        "ending in $, Microsoft 4769) left out. Line on the accounts' own failures that were "
                        "followed by a success from the same source within the hour, at least 2 sources.",
            "technical_context": _WIN_ATTEMPT,
            "blind_spots": "Distributed guessing slower than one source an hour per account.",
            "validation": _WIN_VALIDATION.format(found="W9 distributed guessing (30 internet addresses)"),
            "response": "Read where the sources come from and whether the account then signed in.",
        },
    },
    "WIN-BRUTE-4": {
        "id": "12c8c0fc-93d8-4b8c-94f2-aa81c28d80bd",
        "title": "Windows: low-and-slow guessing during a site-wide rise in failures",
        "status": "experimental",
        "techniques": ["T1110.001"],
        "category": "authentication", "log_sources": WINDOWS_SOURCES,
        "falsepositives": ["A source that never signs in in the evidence but is someone's (a home router "
                           "mistyping during an outage) caught in an epoch",
                           "Evidence too short to model the normal failure rate"],
        "ads": {
            "goal": "Detect guessing spread so thin over sources and days that no source, account or hour "
                    "shows it (behaviour B5; Javed & Paxson 2013).",
            "strategy": "The case's attempts left after WIN-BRUTE-1..3 (the paper filters pointwise "
                        "brute-forcers first) in time order, cut into events of 100; Y = failures per event. "
                        "Normal from the evidence (§5): sources that never succeed, sources failing >= 95% "
                        "of >= 20 attempts and automations (Zhang's chi-squared test, 3-day windows of >= 50 "
                        "attempts, two-sided at 0.001) left out, a beta-binomial fitted by moments. CUSUM "
                        "(§4.1) with k = delta / 2 (delta = 1 failure per 100 attempts, Q88) on a 1/4-failure "
                        "lattice; H the smallest whose in-control ARL is the paper's 3,720 events; epochs "
                        "stepped back by the out-of-control ARL; an epoch that no longer alarms without its "
                        "top-failing source is a singleton and dropped. Flagged: the epoch's failures whose "
                        "(source, account) never signs in, nor the source as an account one letter away "
                        "(§4.2).",
            "technical_context": _WIN_ATTEMPT + " The case keeps the fit, k, H and both ARLs (manifest lines).",
            "blind_spots": "Guessing between alarms: an epoch ends at the first event at or below the normal "
                           "mean, and a late run with no coordination left (singleton) is dropped - measured, "
                           "W3's last month; under 20 events of ordinary attempts (2,000) the rule does not "
                           "run; a guesser whose pair also signs in (stolen password).",
            "validation": _WIN_VALIDATION.format(found="W3, 3 a day from rotating internet addresses for three "
                                                       "months: 156 of 246 failures, Jul 2 - Aug 27"),
            "response": "The paper decides participation by hand: read the sources and accounts the finding "
                        "lists - shared targets, similar counts, timing.",
        },
    },
    "WIN-AUTH-1": {
        "id": "c92b388f-b4d1-4542-93e8-1bfb906bcd9e",
        "title": "Windows: sign-in after flagged failures",
        "status": "experimental",
        "techniques": ["T1078"],
        "category": "authentication", "log_sources": WINDOWS_SOURCES,
        "falsepositives": ["The owner signing in after mistyping (said so when the pair signed in before "
                           "the failures began)"],
        "ads": {
            "goal": "Detect the success that follows guessing or spraying (behaviour B4; T1110 DET0463 "
                    "AN1275 / AN1276, AN1522, AN1524).",
            "strategy": "A success (4624 interactive / network / unlock / RDP / cached, 4768 or 4776 status "
                        "0x0) from a source WIN-BRUTE-1..3 flagged, after its first flagged failure: for the "
                        "same account, or for any account but a computer account (...$) when the source was a "
                        "sprayer - its own machine account signs in from it all day (W-D10). A pair that signed "
                        "in before the failures began is named likely the owner (Javed & Paxson §4.2).",
            "technical_context": _WIN_ATTEMPT,
            "blind_spots": "A success from another source than the failures; failures the BRUTE rules did "
                           "not flag; a sprayed computer account that then signs in (left out on purpose).",
            "validation": _WIN_VALIDATION.format(found="W1 (the sprayed account's TGT), W6 (adm.backup), W7 "
                                                       "(adm.backup reused on RDP)"),
            "response": "High: the account is likely in the attacker's hands - read what it did next.",
        },
    },
})

# Story 5b: sequences on one host, joined by the logon session (TargetLogonId -> SubjectLogonId /
# Sysmon LogonId) or the Sysmon process GUID - no window, no number (W-D2).
_WIN_SESSION = ("Joined by the session: a 4624's TargetLogonId is the SubjectLogonId of the 4688 / 4697 / "
                "4698 it causes on that host and Sysmon 1's LogonId; an event belongs to the latest 4624 "
                "of that id on that host before it.")
_WIN_5B = ("Synthetic Windows quarter (tests/gen_windows_domain.py, ground truth): {found}; no plain or "
           "look-alike event flagged. tests/check_windows_rules.py.")
RULE_META.update({
    "WIN-LAT-1": {
        "id": "319f4e3a-3548-4f75-900f-f4cf01631855",
        "title": "Windows: uncommon RDP, then commands",
        "status": "experimental",
        "techniques": ["T1021.001"],
        "category": "process_creation", "log_sources": WINDOWS_SOURCES,
        "falsepositives": ["An administrator connecting to a server for the first and only time in the "
                           "evidence", "Evidence of one day: every pair is seen on one day"],
        "ads": {
            "goal": "Detect an RDP logon followed by process execution, from a source / account / host "
                    "combination that is not a habit (T1021.001 DET0327 AN0931, its HostAccessPatterns: "
                    "\"first-time source/destination pairs\").",
            "strategy": "4624 LogonType 10 with a source address, or a reconnect to an existing session "
                        "(4778, SessionName RDP-Tcp#N, its ClientAddress; story 5d), then 4688 / Sysmon 1 in "
                        "that session after it; flagged when the (source, account, host) shows RDP on one day "
                        "of the evidence only (the user's choice, 2026-10-26). The finding lists what ran.",
            "technical_context": _WIN_SESSION + " A 4778's LogonID is the session's own; the reconnect's "
                                                "4624 type 7 have new ids that run nothing.",
            "blind_spots": "An attacker returning on several days; a session whose start (4624 or 4778) is "
                           "outside the evidence; reconnects without Other Logon/Logoff auditing (no 4778).",
            "validation": _WIN_5B.format(found="W7, RDP from a user workstation as adm.backup, then "
                                               "discovery and procdump; W10, an admin's session taken over by "
                                               "a reconnect from outside; admins' recurring RDP and "
                                               "reconnects not flagged") +
                          " Real: OTRF RDP capture - the reconnect from 1.2.3.4 and Task Manager in it.",
            "response": "Read the commands; ask whether the account's owner made the connection.",
        },
    },
    "WIN-LAT-2": {
        "id": "71f1f03c-2637-4231-b293-d8272558835f",
        "title": "Windows: remote service or task in a network logon",
        "status": "experimental",
        "techniques": ["T1021.002", "T1569.002"],
        "category": "process_creation", "log_sources": WINDOWS_SOURCES,
        "falsepositives": ["Software deployment tools (SCCM, monitoring agents) installing a service remotely",
                           "Administrators using PsExec"],
        "ads": {
            "goal": "Detect a service or scheduled task created through a network logon - PsExec's shape "
                    "(T1021.002 DET0530 AN1468; T1569.002 DET0421 AN1185).",
            "strategy": "4624 LogonType 3, then 4697 (service installed) or 4698 (task created) in that "
                        "session on that host; ADMIN$ / C$ opened in the session before it (5140) is named "
                        "and kept on the finding. A service carries T1569.002 too.",
            "technical_context": _WIN_SESSION + " System 7045 is not typed - no Microsoft page for it was "
                                                "found; a host that logs a service only there is not read.",
            "blind_spots": "Services created over WMI or with no 4697 audit; tasks on another host than the "
                           "logon's.",
            "validation": _WIN_5B.format(found="W8 PSEXESVC in the pass-the-hash session; the Zabbix rollout "
                                               "found and labelled a benign true positive"),
            "response": "Read the service's file and what it ran; a deployment tool is closed as benign.",
        },
    },
    "WIN-LAT-4": {
        "id": "ff261617-38f6-45f8-ae24-c2f8b380e0bc",
        "title": "Windows: file copied to an admin share, then run",
        "status": "experimental",
        "techniques": ["T1021.002", "T1569.002"],
        "category": "file_event", "log_sources": WINDOWS_SOURCES,
        "falsepositives": ["Software deployment that copies an installer through ADMIN$ / C$ and runs it",
                           "Administrators using PsExec"],
        "ads": {
            "goal": "Detect a file written into ADMIN$ or C$ over the network and then run on that host - "
                    "PsExec copies PSEXESVC.exe to ADMIN$ and installs it (T1021.002 DET0530 AN1468).",
            "strategy": "5145 on ADMIN$ / C$ with WriteData (AccessMask 0x2), the file = ShareLocalPath + "
                        "RelativeTargetName; then on the same host a 4697 whose ServiceFileName names it "
                        "(%SystemRoot% read as C:\\Windows) or a 4688 / Sysmon 1 of that image. Joined by the "
                        "path, no window. A service carries T1569.002 too.",
            "technical_context": "Needs Detailed File Share auditing (5145), which many sites leave off; a "
                                 "host without it shows nothing here (Microsoft 5145).",
            "blind_spots": "A copy through another share or protocol; the source host's side (which session "
                           "started it - a time window, left out); a file renamed after the copy.",
            "validation": _WIN_5B.format(found="W8, PSEXESVC.exe copied to SQL01's ADMIN$ and run; the "
                                               "patch copied through C$ found and labelled a benign true "
                                               "positive"),
            "response": "Read the file and its service; a deployment tool is closed as benign.",
        },
    },
    "WIN-LAT-3": {
        "id": "7499c1dc-23c3-42f3-b982-05ef8e188ba8",
        "title": "Windows: NTLM network logon without Kerberos",
        "status": "experimental",
        "techniques": ["T1550.002"],
        "category": "authentication", "log_sources": WINDOWS_SOURCES,
        "falsepositives": ["A user reaching a host from a computer outside the domain (NLA from home)",
                           "Access by address instead of name, which falls back to NTLM"],
        "ads": {
            "goal": "Detect NTLM network logons \"with no accompanying domain logon events\" (T1550.002 "
                    "DET0409 AN1144) - a sign of pass-the-hash.",
            "strategy": "4624 LogonType 3, AuthenticationPackageName NTLM, from an address, for an account "
                        "that has Kerberos tickets (4768 / 4769 status 0x0) in the evidence but never from "
                        "that address. Computer accounts and ANONYMOUS LOGON left out.",
            "technical_context": "Needs the domain controller's 4768 / 4769 in the same case; an account with "
                                 "no Kerberos at all (a scanner on a share) is not anomalous by this test.",
            "blind_spots": "Pass-the-hash from a host the victim also used legitimately; a case without the "
                           "DC's log.",
            "validation": _WIN_5B.format(found="W8, adm.it from WS023 to FS01 / SQL01 / DC01; the scanner's "
                                               "NTLM-only account not flagged") +
                          " Real: OTRF RDP capture - the NLA logon from the outside client (1.2.3.4).",
            "response": "High: read where the account's hash could have been taken (WIN-HOST-2).",
        },
    },
    "WIN-HOST-1": {
        "id": "f4335dd9-1620-4ed5-8697-104a179688be",
        "title": "Windows: Kerberoasting",
        "status": "experimental",
        "techniques": ["T1558.003"],
        "category": "authentication", "log_sources": WINDOWS_SOURCES,
        "falsepositives": ["A legacy application whose service accounts only support RC4, used by one "
                           "account for many services"],
        "ads": {
            "goal": "Detect one account asking for weak-encryption service tickets for several services in "
                    "a short time (T1558.003 DET0157 AN0444).",
            "strategy": "4769 status 0x0 with a Ticket Encryption Type other than 0x11 / 0x12 (Microsoft "
                        "4769), services of people only (no ...$, no krbtgt); distinct services per account "
                        "within any hour. Line on the accounts' AES-only requests (lines.py), at least 2.",
            "technical_context": "Needs the domain controller's 4769.",
            "blind_spots": "Roasting slowly (one service an hour); AES roasting; AS-REP roasting (4768).",
            "validation": _WIN_5B.format(found="W5, 14 RC4 tickets in 90 s; the finance users' daily RC4 "
                                               "ticket to one legacy service not flagged"),
            "response": "High: the service accounts' passwords should be changed.",
        },
    },
    "WIN-HOST-2": {
        "id": "61e80a22-14db-42cd-b13a-8602b8ea190b",
        "title": "Windows: LSASS read, then a file written",
        "status": "experimental",
        "techniques": ["T1003.001"],
        "category": "process_access", "log_sources": WINDOWS_SOURCES,
        "falsepositives": ["Security products that read lsass and write their own files"],
        "ads": {
            "goal": "Detect a process that opens lsass.exe and then writes a file - a memory dump "
                    "(T1003.001 DET0363 AN1030).",
            "strategy": "Sysmon 10 with TargetImage lsass.exe, then Sysmon 11 by the same process "
                        "(SourceProcessGUID = ProcessGuid) on the same host. Registry writes are left out.",
            "technical_context": "Needs Sysmon with process access (10) and file creation (11) logged.",
            "blind_spots": "A Sysmon configuration that does not log the access (measured: the OTRF Task "
                           "Manager dump has the lsass.DMP file but no Sysmon 10 for it); dumps written by "
                           "another process.",
            "validation": _WIN_5B.format(found="W7, procdump on RDS01; Defender's daily lsass read with no "
                                               "file not flagged"),
            "response": "High: every account signed in on that host should be treated as exposed.",
        },
    },
})

# Story 5c: Sysmon's network connections (event 3) and the sign-in attempts against the feeds.
RULE_META.update({
    "WIN-MAL-1": {
        "id": "590df77b-1287-4a00-949e-2bbc4b457af0",
        "title": "Windows: beaconing from a process",
        "status": "experimental",
        "techniques": ["T1071"],
        "category": "network_connection", "log_sources": WINDOWS_SOURCES,
        "falsepositives": ["Update checks, telemetry and keep-alives on a timer under an hour"],
        "ads": {
            "goal": "Detect one process connecting to one public address at regular intervals (behaviour "
                    "M1; T1071 DET0444).",
            "strategy": "R2007's measured method on Sysmon 3, keyed on (host, process, destination): at least "
                        "30 intervals, mean 30 s - 1 h, jitter (CV) under 0.6. A silence longer than an hour is "
                        "not an interval (the host off, the channel asleep) and is left out of the statistics. "
                        "A (process, destination) beaconing on more than half of the hosts with Sysmon network "
                        "events is the fleet's timer, not a rare destination (AN0076, AN0761), and is left out, "
                        "named on the line record (W-D11) - only from 20 such hosts up: under that there is no "
                        "fleet to call a destination common in, and every beacon is flagged (Q105).",
            "technical_context": "Needs Sysmon network connection logging (event 3); public IPv4 destinations "
                                 "only, as R2007.",
            "blind_spots": "Beacons slower than an hour; jitter above 0.6; destinations by name only (Sysmon "
                           "22) or behind a proxy; Sysmon configurations that leave the process out; one implant "
                           "on more than half of the machines calling one address (on the line record, not "
                           "flagged).",
            "validation": "Synthetic Windows quarter (tests/gen_windows_domain.py): W4's 5-minute beacon, "
                          "working hours only, Aug 3 - Sep 20 (R2007 missed it: nights and weekends lifted the "
                          "jitter); OneDrive's two-hourly sync not flagged. The user's blind quarter: K7 and K15 "
                          "found, ESET's timer on 40 of 43 hosts left out (after its answer key was read - a "
                          "measurement of the fix). tests/check_windows_rules.py.",
            "response": "High: read what the process is, where it came from (Sysmon 1, 11) and the destination.",
        },
    },
    "WIN-INTEL-1": {
        "id": "5fb6c871-2e45-4f6b-a109-e5fb12931073",
        "title": "Windows: connection to a known-bad address",
        "status": "test",
        "techniques": ["T1071"],
        "category": "network_connection", "log_sources": WINDOWS_SOURCES,
        "falsepositives": ["A feed listing shared hosting or a CDN address"],
        "ads": {
            "goal": "Report a process's connection to an address a threat-intel feed lists (behaviour T1; "
                    "R3003's feed match on Sysmon 3).",
            "strategy": "Sysmon 3 destination equal to an IP indicator of the case's feeds (intel.py).",
            "technical_context": "Offline feeds (gotcha #17); Windows logs no refused connection, so there is "
                                 "no blocked twin (R3005).",
            "blind_spots": "Indicators that are names, URLs or hashes; feeds not loaded.",
            "validation": "tests/check_windows_rules.py (a listed public address).",
            "response": "High: the feed's note says what the address is; read the process.",
        },
    },
    "WIN-INTEL-2": {
        "id": "c04e2250-f6b4-433a-b897-4e2bb583523d",
        "title": "Windows: sign-in from a known-bad address",
        "status": "test",
        "techniques": ["T1078", "T1110"],
        "category": "authentication", "log_sources": WINDOWS_SOURCES,
        "falsepositives": ["A feed listing a shared VPN or proxy exit the staff also use"],
        "ads": {
            "goal": "Report a sign-in attempt from an address a threat-intel feed lists (behaviour T2; "
                    "R3004's feed match on the sign-in attempts).",
            "strategy": "A sign-in attempt (rules_windows.py: one attempt per 4625 / 4771 / 4776 / 4624 / "
                        "4768) whose source address is an IP indicator. A success is T1078, a failure T1110.",
            "technical_context": _WIN_ATTEMPT,
            "blind_spots": "Attempts sourced by a workstation name (a lone 4776); feeds not loaded.",
            "validation": "Synthetic Windows quarter with a test feed: W2's internet brute force. "
                          "tests/check_windows_rules.py.",
            "response": "Medium; high if the attempt succeeded - read what the account did next.",
        },
    },
})

# Story 5f (specs/windows_defender_rules.md): Microsoft Defender Antivirus's own events.
_DEFENDER_SOURCES = ["windows-event-xml", "windows-evtx", "windows-nxlog-json"]
_DEFENDER_FORMS = ("Read from Defender's EventData item names, which differ by event (the provider's "
                   "templates): 1006 / 1015 Path Found and Domain + User, 1007 / 1008 Cleaning Action, "
                   "1116-1119 Path, Action Name and Detection User. Checked on event XML and .evtx "
                   "exported from a Windows 11 PC and on NXLog JSON; Winlogbeat JSON and Splunk text not "
                   "checked on a Defender event.")
RULE_META.update({
    "WIN-MAL-2": {
        "id": "13b945bd-7574-4c4b-9df7-df0739e50e38",
        "title": "Windows: Microsoft Defender detection",
        "status": "experimental",
        "techniques": [],
        "category": "antivirus", "log_sources": _DEFENDER_SOURCES,
        "falsepositives": ["A tool the organisation uses that Defender classes as HackTool or PUA",
                           "A test file (EICAR)"],
        "ads": {
            "goal": "Report what Microsoft Defender Antivirus itself detected on a host, and whether it "
                    "remediated it (W-D12: the product's own verdict, as CP-MAL-2 reads Check Point's).",
            "strategy": "Defender 1006 / 1015 / 1116 (detected), 1007 / 1117 (action taken) and 1008 / 1118 / "
                        "1119 (action failed) grouped into one detection by host and Detection ID, else host, "
                        "threat ID and path. A 1011 (deleted from quarantine) whose threat has no detection event "
                        "on that host in the evidence is reported too - it had been quarantined (Q116).",
            "technical_context": _DEFENDER_FORMS + " Detection ID is observed in the events, not named in "
                                 "Microsoft's field lists. No technique: a detection names what Defender found, "
                                 "not what the attacker did (SigmaHQ 57b649ef's T1059 would put adware in "
                                 "Execution).",
            "blind_spots": "Defender turned off, excluded paths, other antivirus products; ASR (1121 / 1122) and "
                           "network protection (1125 / 1126) - not on Microsoft's page as read; Defender for "
                           "Endpoint alerts (not a local event log).",
            "validation": "WinEvents.log (Meterpreter via AMSI, quarantined; Glupteba deleted from quarantine); "
                          "Defender events exported from a PC; tests/check_windows_rules.py.",
            "response": "High when not remediated - no action event, Allow / No action / None (\"don't remediate "
                        "detected threats\"), or the action failed (1118 / 1119: \"The endpoint might not be "
                        "protected\"). Medium when quarantined, removed, cleaned or blocked: read how it got "
                        "there and what the account did around it.",
        },
    },
    "WIN-HOST-3": {
        "id": "2a336334-15fc-4d19-948b-ebec0d10dbc1",
        "title": "Windows: Microsoft Defender turned off or tampered with",
        "status": "experimental",
        "techniques": ["T1685"],
        "category": "antivirus", "log_sources": _DEFENDER_SOURCES,
        "falsepositives": ["Administrator actions (should be investigated) - SigmaHQ b28e58e4",
                           "Seen being triggered occasionally during Defender updates - SigmaHQ b28e58e4",
                           "A software deployment adding its own exclusion"],
        "ads": {
            "goal": "Detect Microsoft Defender Antivirus being turned off or its exclusions changed "
                    "(T1685 Disable or Modify Tools, DET0497 AN1369: \"tampering with exclusion lists\").",
            "strategy": "Defender 5001 (real-time protection disabled), 5010 / 5012 (scanning disabled), 5013 "
                        "(tamper protection blocked a change) and 5007 whose New Value is under "
                        "Windows Defender\\Exclusions\\ (Q117 - the key path is observed). Shown with it, no "
                        "window (Q118): when it was turned back on (5000 / 5009 / 5011) and the nearest Defender "
                        "update event (2000 / 2001 / 2002) on either side.",
            "technical_context": _DEFENDER_FORMS + " AN1369's own log sources (7045, Sysmon 5, 13 / 14) are "
                                 "not read here; 5004's Configuration has no documented values - Timeline only.",
            "blind_spots": "Defender's service stopped or its process killed (a sequence, not read); changes "
                           "made while the log was off; Group Policy settings applied with no 5007.",
            "validation": "WinEvents.log (5001 on ACC01, turned back on two minutes later); "
                          "tests/check_windows_rules.py.",
            "response": "High: find who did it - the sign-ins on that host just before - and what ran while "
                        "it was off. Medium when tamper protection blocked the change.",
        },
    },
})



def tags(rid: str) -> list[str]:
    """Sigma tags: tactic(s) first, then the techniques, lower-case."""
    out: list[str] = []
    for t in RULE_META[rid]["techniques"]:
        for tactic in TACTICS.get(t.lower().split(".")[0], []):
            tag = f"attack.{tactic}"
            if tag not in out:
                out.append(tag)
    out += [f"attack.{t.lower()}" for t in RULE_META[rid]["techniques"]]
    return out


_DEV_REF = re.compile(r"\s*\(gotcha #\d+\)")


def _plain(text: str) -> str:
    """Analyst-facing text: drop the "(gotcha #N)" pointers into CLAUDE.md.
    They stay in the source so a developer can trace each claim; to an
    analyst reading a rule card they are noise."""
    return _DEV_REF.sub("", text)


def describe(rid: str) -> dict:
    """One rule in Sigma field names, plus its ADS documentation."""
    m = RULE_META[rid]
    m = {**m, "falsepositives": [_plain(f) for f in m["falsepositives"]],
         "ads": {k: _plain(v) for k, v in m["ads"].items()}}
    techniques = m["techniques"]
    return {
        "rid": rid,
        "label": RULE_LABELS.get(rid, rid),
        "id": m["id"],
        "title": m["title"],
        "status": m["status"],
        "description": m["ads"]["goal"],
        "author": AUTHOR,
        "date": CREATED,
        "modified": LEVELS_MODIFIED,
        "references": [f"{_ATTACK}{t.replace('.', '/')}/" for t in techniques],
        "logsource": {"category": m["category"]},
        "log_sources": m["log_sources"],
        "level": RULE_LEVEL.get(rid),
        "tags": tags(rid),
        "falsepositives": m["falsepositives"],
        "ads": {
            "goal": m["ads"]["goal"],
            "categorization": tags(rid) or ["(no ATT&CK technique - context only)"],
            "strategy_abstract": m["ads"]["strategy"],
            "technical_context": m["ads"]["technical_context"],
            "blind_spots_and_assumptions": m["ads"]["blind_spots"],
            "false_positives": m["falsepositives"],
            "validation": m["ads"]["validation"],
            "priority": RULE_LEVEL.get(rid),
            "response": m["ads"]["response"],
        },
    }


def problems() -> list[str]:
    """Consistency of the metadata with the rules themselves - run by
    tests/check_rule_meta.py. A rule without metadata, or whose documented
    techniques differ from the ATT&CK ids its SQL writes into findings, is a
    documentation bug the UI would otherwise show as fact."""
    from .rules import RULES

    out = []
    ids = set()
    for rid, sql in RULES:
        if rid not in RULE_META:
            out.append(f"{rid}: no metadata")
            continue
        m = RULE_META[rid]
        sql_mitre = re.findall(r"'(T\d{4}(?:\.\d{3})?)'", sql)
        if sorted(sql_mitre) != sorted(m["techniques"]):
            out.append(f"{rid}: techniques {m['techniques']} but its SQL writes {sql_mitre}")
        if m["status"] not in ("stable", "test", "experimental", "deprecated", "unsupported"):
            out.append(f"{rid}: status {m['status']!r} is not a Sigma status")
        if m["id"] in ids:
            out.append(f"{rid}: duplicate id")
        ids.add(m["id"])
        for t in m["techniques"]:
            if t.lower().split(".")[0] not in TACTICS:
                out.append(f"{rid}: no tactic mapping for {t}")
        if rid not in RULE_LEVEL:
            out.append(f"{rid}: no Sigma level in RULE_LEVEL")
    # A rule taken out of rules.py keeps its metadata as `deprecated`, so a
    # case processed before still explains its findings; anything else left
    # behind is a stale entry.
    running = {rid for rid, _ in RULES}
    extra = {rid for rid in set(RULE_META) - running
             if RULE_META[rid]["status"] != "deprecated"}
    out += [f"{rid}: metadata for a rule that does not exist" for rid in sorted(extra)]
    out += [f"{rid}: deprecated but still in rules.py" for rid in sorted(running)
            if RULE_META.get(rid, {}).get("status") == "deprecated"]
    return out
