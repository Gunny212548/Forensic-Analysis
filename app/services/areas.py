"""Detection areas: the six cards of the Overview.

An area groups rules by the behaviour they detect, so "where is the trouble"
can be read at a glance. It is an internal grouping - the nearest framework is
the ATT&CK tactic, but a tactic list is dominated by two entries on real data
(C2, Reconnaissance; CLAUDE.md, *Decisions*) and cannot say "authentication".

Every rule belongs to exactly one area. `tests/check_workflow.py` fails when a
rule is added to rules.py without being placed here, because an unplaced rule
would be counted nowhere on the Overview.
"""

AREAS: list[dict] = [
    {"id": "authentication", "name": "Authentication",
     "about": "Logins that failed or succeeded, invalid users, new connections, password changes",
     "rids": ("R1000", "R1001", "R1002", "R1003", "R1004")},
    {"id": "account-attacks", "name": "Brute force & spraying",
     "about": "Repeated failures from one source, one account failing from many sources, "
              "one account succeeding from many sources",
     "rids": ("R2000", "R2005", "R2006")},
    {"id": "scanning-policy", "name": "Scanning & policy",
     "about": "Repeated blocks, port scans, service sweeps, traffic allowed despite many blocks",
     "rids": ("R2001", "R2002", "R2003", "R2004")},
    {"id": "malware-c2", "name": "Malware & C2",
     "about": "Malware-category traffic and regular beaconing to external addresses",
     "rids": ("R2007", "R3002")},
    {"id": "data-apps", "name": "Data & applications",
     "about": "Large outbound transfers and high-risk applications that were allowed",
     "rids": ("R3000", "R3001")},
    {"id": "threat-intel", "name": "Threat intelligence",
     "about": "Traffic to or from addresses on the threat-intel feeds",
     "rids": ("R3003", "R3004", "R3005", "R3006")},
]

AREA_OF: dict[str, str] = {rid: a["id"] for a in AREAS for rid in a["rids"]}
AREA_IDS: tuple[str, ...] = tuple(a["id"] for a in AREAS)

# The four chips on a card. A Sigma level has five; informational folds into low.
CHIPS = ("critical", "high", "medium", "low")


def chip(level: str | None) -> str:
    return level if level in ("critical", "high", "medium") else "low"
