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
}

AUTH_SOURCES = ["openssh-sshd", "entra-signin"]
FIREWALL_SOURCES = ["paloalto-traffic", "checkpoint-smartconsole", "fortigate-traffic"]
PALOALTO_SOURCES = ["paloalto-traffic"]

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
                          "pending; benign first contacts succeeded 99.6%. Synthetic: tests/check_paloalto.py.",
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
                          "most 2 ports to a host in an hour - no scan. Synthetic: tests/check_paloalto.py.",
            "response": "Low unless the same source is later allowed (PAN-SCAN-3).",
        },
    },
    "PAN-SCAN-3": {
        "id": "7d2b75fa-f551-4c35-8d13-bb1087cf9154",
        "title": "Palo Alto: allowed after refusals",
        "status": "experimental",
        "techniques": [],
        "category": "firewall", "log_sources": PALOALTO_SOURCES,
        "falsepositives": ["A client refused on one service and allowed on another of the same host"],
        "ads": {
            "goal": "Detect a source let through to a host it was refused by shortly before - a gap "
                    "in the policy found by probing (behaviour S5).",
            "strategy": "An allowed connection with refusals of the same source -> host in the hour "
                        "before. Line as PAN-SCAN-1 on the refusals before an allow, at least 1.",
            "technical_context": "No ATT&CK analytic names it: an internal method (the SOC benchmark's "
                                 "implied-rule bypass), stated as one.",
            "blind_spots": "A probe and its success more than an hour apart; a different target host.",
            "validation": "Customer Traffic exports: 3 such pairs. Synthetic: tests/check_paloalto.py.",
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
