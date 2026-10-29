"""SigmaHQ's high / critical Windows rules as product rules (specs/sigma_windows.md S-D4).

The same interface as rules_windows.py, so rules.apply_rules runs them and everything that
follows a finding - review, the AI's explanation, FD ids, the attack timeline and graph -
needs nothing new. The rules themselves are SigmaHQ's, converted at image build (sigma.py);
their level is the rule's own, their family one for all of them (confidence counts a
SigmaHQ match as one kind of evidence, however many of its rules agree), and every one names
its entity: the host and account of the event (S-D5).
"""
from . import sigma

PRODUCT = "windows"
_SUGGEST = [r for r in sigma.bundle()["rules"] if sigma.suggests(r)]

RULES: list[tuple[str, str]] = [(r["rid"], sigma.finding_sql(r)) for r in _SUGGEST]
FROM_GENERIC: list = []
PREPARE: dict = {}
ENTITY = tuple(r["rid"] for r in _SUGGEST)
LEVEL = {r["rid"]: r["level"] for r in _SUGGEST}
LABELS = {r["rid"]: r["title"] for r in _SUGGEST}
FAMILY = {r["rid"]: "SG" for r in _SUGGEST}
EQUIVALENT: dict = {}
SUPERSEDES: tuple = ()

# S-D6 (Q129): the area of a SigmaHQ rule is its first ATT&CK tactic's.
TACTIC_AREA = {
    "lateral-movement": "lateral-movement", "lateral_movement": "lateral-movement",
    "command-and-control": "malware-c2", "command_and_control": "malware-c2",
}


def area_of(r: dict) -> str:
    for t in r.get("tactics") or []:
        return TACTIC_AREA.get(t, "host-activity")
    return "host-activity"


AREAS = {r["rid"]: area_of(r) for r in _SUGGEST}
