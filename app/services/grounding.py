"""Keep the narrative inside the evidence it was given.

Two halves, both computed per call from the same facts:

- **What the model may say.** `facts()` collects, from what the prompt
  actually carries, every technique id, ATT&CK stage, timestamp, Sigma level,
  address and entity. `narrative_schema()` / `map_schema()` turn that into a
  JSON schema whose enums are those values, and Ollama's structured outputs
  enforce it while decoding: a technique id or a stage with no evidence
  behind it cannot be generated at all. Asking in the prompt was measured not
  to be enough - qwen3.5:9b invented T1076 / T1552.004 / T1059 in 3 runs while
  the prompt told it to "infer from context" (CLAUDE.md gotcha #37).
- **What the model did say.** Free text (summary, descriptions, events,
  recommendations) cannot be enumerated, so `check()` reads it back and lists
  every IP, technique id, e-mail address or ISO date in it that the prompt
  never contained. A warning, not a refusal - the analyst decides.

Stages come from the ATT&CK tactics of the tagged techniques (rule_meta's
TACTICS, the same map the Sigma tags use) plus the attack-path escalations,
never from the model. A rule without a technique tag (R1001, R1003, R1004)
therefore cannot put a stage on the chain: the narrative says less, and
everything it does say has a rule behind it.
"""

import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass, field

from .rule_meta import TACTICS
from .severity import LEVELS

# The prompt states these same numbers; the schema is what enforces them.
CHAIN_CAP = 4
TIMELINE_CAP = 6
RECS_CAP = 3
NOTABLE_CAP = 4

# Free-text ceilings. Generous - the prompt asks for far less - they exist
# because a constrained string has no natural end: in testing a "target"
# field ran to a paragraph of speculation.
SUMMARY_MAX = 700
DESCRIPTION_MAX = 240
EVENT_MAX = 160
RECOMMENDATION_MAX = 160
TIMESTAMP_RANGE_MAX = 64
CHUNK_NOTE_MAX = 400

# ATT&CK Enterprise tactic order, so the allowed stages read like a kill chain.
STAGE_ORDER = [
    "Reconnaissance", "Resource Development", "Initial Access", "Execution",
    "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
    "Discovery", "Lateral Movement", "Collection", "Command and Control",
    "Exfiltration", "Impact",
]

# What an attack-path pattern (severity.py) establishes, in ATT&CK terms.
# A brute force followed by a login from the same source on the same account
# is the use of a valid account to get in: T1078, at the Initial Access
# stage - ODNI's Engagement -> Presence crossing, which is why the pattern
# escalates at all. Only that one tactic of T1078's four is evidenced by the
# pattern. compromised-host adds nothing: the behaviours that make it up are
# rules with their own techniques already.
ESCALATION_FACTS = {
    "credential-compromise": (["T1078"], ["Initial Access"]),
}

_IPV4 = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?:/(\d{1,2}))?(?![\d.])")
_TECH = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
_EMAIL = re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b")
_DATE = re.compile(r"\b\d{4}-\d{2}-\d{2}\b")


def stage_name(tag: str) -> str:
    """Sigma's tactic tag spelling -> ATT&CK's display name."""
    return " ".join(w if w == "and" else w.capitalize() for w in tag.split("_"))


def tactics_of(technique: str) -> list[str]:
    return [stage_name(t) for t in TACTICS.get(technique.lower().split(".")[0], [])]


@dataclass
class Facts:
    techniques: dict[str, set] = field(default_factory=dict)   # id -> {stages}
    rules_of: dict[str, set] = field(default_factory=dict)     # id -> {rids}
    timestamps: set = field(default_factory=set)
    levels: set = field(default_factory=set)
    ips: set = field(default_factory=set)
    entities: set = field(default_factory=set)

    def add_technique(self, tid: str, stages: list[str], rid: str | None = None) -> None:
        self.techniques.setdefault(tid, set()).update(stages)
        if rid:
            self.rules_of.setdefault(tid, set()).add(rid)

    @property
    def stages(self) -> list[str]:
        found = set().union(*self.techniques.values()) if self.techniques else set()
        return [s for s in STAGE_ORDER if s in found]


def _ips_in(text) -> list[str]:
    return [m.group(1) for m in _IPV4.finditer(str(text or ""))]


def facts(
    events: list[dict],
    technique_events: list[dict] | None = None,
    digests: list[dict] | None = None,
    risk: dict | None = None,
    profiles: list[dict] | None = None,
    escalations: list[dict] | None = None,
) -> Facts:
    """Everything the model is allowed to cite.

    `events` are the rows quoted in the prompt. `technique_events` is the
    wider set whose techniques the prompt lists (a map-reduce reduce call
    quotes one batch but summarises the whole pool); it defaults to `events`.
    """
    f = Facts()
    for e in technique_events if technique_events is not None else events:
        for tid in e.get("mitre") or []:
            f.add_technique(tid, tactics_of(tid), e.get("rid"))
    for e in events:
        for ts in (e.get("ts_first"), e.get("ts_last")):
            if ts:
                f.timestamps.add(str(ts))
        if e.get("level"):
            f.levels.add(e["level"])
        if e.get("srcip"):
            f.ips.add(e["srcip"])
            f.entities.add(e["srcip"])
        if e.get("username"):
            f.entities.add(e["username"])
        for ip in _ips_in(e.get("descr")):
            f.ips.add(ip)
            f.entities.add(ip)
    for d in digests or []:
        for ev in d.get("notable_events") or []:
            if not isinstance(ev, dict):
                continue
            if ev.get("ts"):
                f.timestamps.add(str(ev["ts"]))
            if ev.get("sev"):
                f.levels.add(ev["sev"])
            for key in ("src", "target"):
                if ev.get(key):
                    f.entities.add(str(ev[key]))
                    f.ips.update(_ips_in(ev[key]))
    for items in (risk or {}).values():
        for i in items[:5]:
            f.entities.add(str(i["entity"]))
            f.ips.update(_ips_in(i["entity"]))
    for p in profiles or []:
        if p.get("srcip"):
            f.ips.add(p["srcip"])
            f.entities.add(p["srcip"])
    for x in escalations or []:
        techs, stages = ESCALATION_FACTS.get(x.get("pattern"), ([], []))
        for tid in techs:
            f.add_technique(tid, stages, x.get("pattern"))
        for key in ("srcip", "username"):
            if x.get(key):
                f.entities.add(x[key])
        if x.get("srcip"):
            f.ips.add(x["srcip"])
    f.levels &= set(LEVELS)
    return f


def techniques_block(f: Facts) -> str:
    """The prompt's statement of which ids exist, one line each, so the ids
    the schema allows are also ids the model was shown with their meaning."""
    lines = []
    for tid in sorted(f.techniques):
        stages = ", ".join(s for s in STAGE_ORDER if s in f.techniques[tid])
        rules = ", ".join(sorted(f.rules_of.get(tid, [])))
        lines.append(f"  {tid} - {stages} (from {rules})")
    return "\n".join(lines)


def escalations_block(escalations: list[dict] | None) -> str:
    lines = []
    for x in escalations or []:
        who = x.get("srcip") or "?"
        if x.get("username"):
            who += f" on account {x['username']}"
        techs, stages = ESCALATION_FACTS.get(x.get("pattern"), ([], []))
        meaning = f" - {', '.join(techs)} {', '.join(stages)}" if techs else ""
        lines.append(f"  {x['pattern']}: {who} (rules {'+'.join(x.get('rules') or [])}){meaning}")
    return "\n".join(lines)


# ------------------------------------------------------------------ schemas

def _enum(values, nullable: bool = False) -> dict:
    vals = sorted(str(v) for v in values)
    if nullable:
        return {"enum": vals + [None]}
    return {"enum": vals} if vals else {"type": "string", "maxLength": 0}


def _ids(f: Facts) -> dict:
    if not f.techniques:
        return {"type": "array", "maxItems": 0}
    return {"type": "array", "items": _enum(f.techniques)}


def _timestamp(f: Facts) -> dict:
    # A case whose timestamps never parsed has nothing to enumerate; a short
    # free string then, and check() still reads it.
    return _enum(f.timestamps) if f.timestamps else {"type": "string", "maxLength": 40}


def _level(f: Facts) -> dict:
    return _enum(f.levels) if f.levels else _enum(LEVELS)


def narrative_schema(f: Facts) -> dict:
    """The final narrative object. Property order is generation order, and it
    is the old schema's priority order (gotcha #5) - don't reorder."""
    stages = f.stages
    chain_item = {
        "type": "object",
        "properties": {
            "stage": _enum(stages),
            "description": {"type": "string", "maxLength": DESCRIPTION_MAX},
            "timestamp_range": {"type": "string", "maxLength": TIMESTAMP_RANGE_MAX},
            "confidence": {"enum": ["low", "medium", "high"]},
            "mitre": _ids(f),
        },
        "required": ["stage", "description", "timestamp_range", "confidence", "mitre"],
    }
    timeline_item = {
        "type": "object",
        "properties": {
            "timestamp": _timestamp(f),
            "event": {"type": "string", "maxLength": EVENT_MAX},
            "severity": _level(f),
            "source_ip": _enum(f.ips, nullable=True),
            "target": _enum(f.entities, nullable=True),
            "mitre": _ids(f),
        },
        "required": ["timestamp", "event", "severity", "source_ip", "target", "mitre"],
    }
    return {
        "type": "object",
        "properties": {
            "summary": {"type": "string", "maxLength": SUMMARY_MAX},
            "attack_chain": {"type": "array", "maxItems": CHAIN_CAP if stages else 0,
                             "items": chain_item},
            "recommendations": {"type": "array", "maxItems": RECS_CAP,
                                "items": {"type": "string", "maxLength": RECOMMENDATION_MAX}},
            "timeline": {"type": "array", "maxItems": TIMELINE_CAP, "items": timeline_item},
        },
        "required": ["summary", "attack_chain", "recommendations", "timeline"],
    }


def map_schema(f: Facts) -> dict:
    """One batch's digest (MAP_SYSTEM_PROMPT), chunk_note first."""
    return {
        "type": "object",
        "properties": {
            "chunk_note": {"type": "string", "maxLength": CHUNK_NOTE_MAX},
            "notable_events": {
                "type": "array",
                "maxItems": NOTABLE_CAP,
                "items": {
                    "type": "object",
                    "properties": {
                        "ts": _timestamp(f),
                        "event": {"type": "string", "maxLength": EVENT_MAX},
                        "sev": _level(f),
                        "src": _enum(f.ips, nullable=True),
                        "target": _enum(f.entities, nullable=True),
                        "mitre": _ids(f),
                    },
                    "required": ["ts", "event", "sev", "src", "target", "mitre"],
                },
            },
        },
        "required": ["chunk_note", "notable_events"],
    }


def digest(*parts) -> str:
    """SHA-256 of what was sent, recorded so a narrative can be tied to its
    exact prompt and schema later (NIST AI RMF MEASURE)."""
    h = hashlib.sha256()
    for p in parts:
        text = p if isinstance(p, str) else json.dumps(p, sort_keys=True, default=str)
        h.update(text.encode("utf-8"))
        h.update(b"\x00")
    return h.hexdigest()


# -------------------------------------------------------------------- check

def _strings(value, path: str):
    if isinstance(value, str):
        yield path, value
    elif isinstance(value, list):
        for i, v in enumerate(value):
            yield from _strings(v, f"{path}[{i}]")
    elif isinstance(value, dict):
        for k, v in value.items():
            yield from _strings(v, f"{path}.{k}")


def check(result: dict, prompt: str) -> dict:
    """Every address, technique id, e-mail and ISO date the narrative states
    must appear in the prompt it was written from. Schema-enforced fields are
    read too: the Groq path has no schema, and a check that skips fields can
    only miss things."""
    known_ips = set(_ips_in(prompt))
    known_nets = [ipaddress.ip_address(ip) for ip in known_ips if _valid(ip)]
    known_techs = set(_TECH.findall(prompt))
    known_parents = {t.split(".")[0] for t in known_techs}
    lowered = prompt.lower()
    unsupported, checked = [], 0
    for key in ("summary", "attack_chain", "recommendations", "timeline"):
        for path, text in _strings(result.get(key), key):
            for m in _IPV4.finditer(text):
                checked += 1
                ip, prefix = m.group(1), m.group(2)
                if prefix and _valid(ip):
                    try:
                        net = ipaddress.ip_network(f"{ip}/{prefix}", strict=False)
                    except ValueError:
                        net = None
                    if net and any(a in net for a in known_nets):
                        continue
                elif ip in known_ips:
                    continue
                unsupported.append({"path": path, "kind": "ip", "value": m.group(0)})
            for t in _TECH.findall(text):
                checked += 1
                # A parent id of a supplied sub-technique (T1110 for
                # T1110.001) is the same claim, less specific - not invented.
                if t not in known_techs and t not in known_parents:
                    unsupported.append({"path": path, "kind": "technique", "value": t})
            for kind, rx in (("email", _EMAIL), ("date", _DATE)):
                for v in rx.findall(text):
                    checked += 1
                    if v.lower() not in lowered:
                        unsupported.append({"path": path, "kind": kind, "value": v})
            # The schema keeps a stage the prompt never named off the chain,
            # but prose can still claim one: "...used stolen credentials for
            # lateral movement" on a case with no lateral-movement evidence.
            for stage, rx in _STAGE_RX.items():
                if rx.search(text):
                    checked += 1
                    if not rx.search(prompt):
                        unsupported.append({"path": path, "kind": "stage", "value": stage})
    return {"ok": not unsupported, "checked": checked, "unsupported": unsupported}


# Execution, Discovery, Collection and Impact are left out: as ordinary
# English ("reduce the impact") they would be flagged in every narrative.
_STAGE_RX = {
    s: re.compile(r"\b" + r"[\s-]+".join(map(re.escape, s.lower().split())) + r"\b", re.I)
    for s in STAGE_ORDER
    if s not in ("Execution", "Discovery", "Collection", "Impact")
}


def _valid(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False
