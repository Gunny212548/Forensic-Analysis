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
     "about": "Logins that succeeded after an attack, one account logging in from many sources",
     "rids": ("R2008", "R2006")},
    {"id": "account-attacks", "name": "Brute force & spraying",
     "about": "Repeated failures from one source, one source failing against many accounts, "
              "one account failing from many sources",
     "rids": ("R2000", "R2009", "R2005")},
    {"id": "scanning-policy", "name": "Scanning & policy",
     "about": "Port scans, service sweeps, traffic allowed despite many blocks",
     "rids": ("R2002", "R2003", "R2004", "PAN-SCAN-1", "PAN-SCAN-2", "PAN-SCAN-3")},
    {"id": "malware-c2", "name": "Malware & C2",
     "about": "Malware-category traffic and regular beaconing to external addresses",
     "rids": ("R2007", "R3002", "PAN-MAL-1", "PAN-MAL-2")},
    {"id": "data-apps", "name": "Data transfer",
     "about": "Large outbound transfers",
     "rids": ("R3001",)},
    {"id": "threat-intel", "name": "Threat intelligence",
     "about": "Traffic to or from addresses on the threat-intel feeds",
     "rids": ("R3003", "R3004", "R3005", "PAN-INTEL-1", "PAN-INTEL-2", "PAN-INTEL-3")},
]

AREA_OF: dict[str, str] = {rid: a["id"] for a in AREAS for rid in a["rids"]}
AREA_IDS: tuple[str, ...] = tuple(a["id"] for a in AREAS)

# The four chips on a card. A Sigma level has five; informational folds into low.
CHIPS = ("critical", "high", "medium", "low")


def chip(level: str | None) -> str:
    return level if level in ("critical", "high", "medium") else "low"
