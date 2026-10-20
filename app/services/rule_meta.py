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

RULE_META: dict[str, dict] = {
    "R1000": {
        "id": "d8e0240f-a400-4d41-a280-0216641e2277",
        "title": "Authentication failure",
        "status": "test",
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
            "response": "Low on its own - read it through R2000/R2005 on the same source or account.",
        },
    },
    "R1001": {
        "id": "f22d1320-bb96-40e9-840b-d8877663c116",
        "title": "Successful authentication",
        "status": "test",
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
            "response": "None alone. Raised to high by credential-compromise when it follows a "
                        "brute force from the same source.",
        },
    },
    "R1002": {
        "id": "5015bccb-5e4d-47ae-a4db-08d914d52ec9",
        "title": "Login attempt for a non-existent account",
        "status": "experimental",
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
            "response": "Check whether the same source also brute-forced (R2000).",
        },
    },
    "R1003": {
        "id": "b3166831-2475-49c7-9ec8-330cb9478027",
        "title": "SSH connection opened",
        "status": "test",
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
            "response": "None - informational.",
        },
    },
    "R1004": {
        "id": "0c639136-db9e-48ff-8ecc-7e49c88b2465",
        "title": "Account password changed",
        "status": "test",
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
            "response": "Check it against the timeline of any compromised account on the host.",
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
            "response": "Look for a later success from the same source - severity.py raises that "
                        "path to high (credential-compromise).",
        },
    },
    "R2001": {
        "id": "0fba7271-1c22-4e20-9779-d1c5c60a081f",
        "title": "Repeated blocked connections from one source",
        "status": "test",
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
            "response": "Low: confirm nothing from the same source was allowed (R2004).",
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
        "techniques": ["T1133"],
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
        "title": "Password spray against one account",
        "status": "test",
        "techniques": ["T1110.003"],
        "category": "authentication", "log_sources": AUTH_SOURCES,
        "falsepositives": ["A roaming user failing once from each of several networks"],
        "ads": {
            "goal": "Catch guessing spread across sources, which per-source counting misses.",
            "strategy": "Accounts with failures from >=5 distinct sources.",
            "technical_context": "Pairs with R2000 on the other axis (gotcha #14).",
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
    "R3000": {
        "id": "6b3736f8-3d98-420e-9c6d-ec5d076724c1",
        "title": "High-risk application allowed",
        "status": "test",
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
            "response": "Medium: decide whether the application is sanctioned.",
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
        "status": "experimental",
        "techniques": ["T1595"],
        "category": "firewall", "log_sources": FIREWALL_SOURCES,
        "falsepositives": ["All of it, usually - the perimeter doing its job"],
        "ads": {
            "goal": "Keep the perimeter's refusal rate of listed sources visible.",
            "strategy": "Source in the ioc table and denied.",
            "technical_context": "Informational by design.",
            "blind_spots": "None that matter for an alert.",
            "validation": "Not separately measured on the current corpus.",
            "response": "None.",
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
    extra = set(RULE_META) - {rid for rid, _ in RULES}
    out += [f"{rid}: metadata for a rule that does not exist" for rid in sorted(extra)]
    return out
