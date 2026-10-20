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
never from the model. A rule without a technique tag (R2004)
therefore cannot put a stage on the chain: the narrative says less, and
everything it does say has a rule behind it.

**Citations.** Every quoted finding carries a short `ref` (`F7`, its rank in
the case's pool - `assign_refs()`), and every attack-chain stage and timeline
entry must cite one or more of them in `refs`, plus a `basis`: `fact` when it
restates what the cited findings say, `inference` when it concludes beyond
them. The schema allows only refs the prompt carries; `resolve()` turns them
back into finding keys (`rid|srcip|username`, the unit the analyst reviews),
and `check()` flags an entry that names an address - as its `source_ip` or in
its text - that none of its citations states: a wrong relation between two
real entities, which no enum can catch.
"""

import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass, field

from .db import finding_key
from .rule_meta import TACTICS
from .severity import LEVELS

# The prompt states these same numbers; the schema is what enforces them.
CHAIN_CAP = 4
TIMELINE_CAP = 6
RECS_CAP = 3
NOTABLE_CAP = 4
REFS_CAP = 5        # citations per stage / timeline entry
NOTABLE_REFS_CAP = 3
BASES = ["fact", "inference"]

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

# The lookahead refuses a following digit or ".digit" (a longer dotted
# number), not a bare "." - it used to, and so never matched an address that
# ends a sentence ("...gained shell access to 10.10.1.5."), which check()
# then never read.
_IPV4 = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?:/(\d{1,2}))?(?!\d|\.\d)")
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
    # ref -> the finding it names: {"key", "rid", "srcip", "username", "ips"}. Only
    # refs the prompt actually shows (quoted, or cited by a batch digest).
    refs: dict[str, dict] = field(default_factory=dict)

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


def assign_refs(rows: list[dict]) -> list[dict]:
    """Give each finding its citation id, `F1`.. in the order given (the
    pool's severity rank, which is deterministic - gotcha #37). Rows that
    already carry one keep it, so a map-reduce pool numbered once stays
    numbered the same in every batch and in the reduce call."""
    for i, row in enumerate(rows, start=1):
        row.setdefault("ref", f"F{i}")
    return rows


def ref_order(ref: str) -> tuple:
    return (int(ref[1:]) if ref[1:].isdigit() else 0, ref)


def _ref_entry(e: dict) -> dict:
    return {
        "key": finding_key(e.get("rid"), e.get("srcip"), e.get("username")),
        "rid": e.get("rid"),
        "srcip": e.get("srcip"),
        "username": e.get("username"),
        # Every address the finding itself states: its source, and the ones
        # its description names (the destination of a transfer, say).
        "ips": sorted({*_ips_in(e.get("descr")), *([e["srcip"]] if e.get("srcip") else [])}),
    }


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
    pool = technique_events if technique_events is not None else events
    by_ref = {e["ref"]: e for e in pool if e.get("ref")}
    for e in pool:
        for tid in e.get("mitre") or []:
            f.add_technique(tid, tactics_of(tid), e.get("rid"))
    for e in events:
        if e.get("ref"):
            f.refs[e["ref"]] = _ref_entry(e)
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
            # A batch digest's citations are evidence the reduce call may
            # cite too: the finding was read, only not quoted again.
            for ref in ev.get("refs") or []:
                if ref in by_ref:
                    f.refs[ref] = _ref_entry(by_ref[ref])
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


def _refs(f: Facts, cap: int) -> dict:
    # At least one: a stage or a timeline entry with no finding behind it is
    # exactly the claim this field exists to rule out.
    if not f.refs:
        return {"type": "array", "maxItems": 0}
    refs = sorted(f.refs, key=ref_order)
    return {"type": "array", "minItems": 1, "maxItems": cap, "items": {"enum": refs}}


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
            "refs": _refs(f, REFS_CAP),
            "basis": {"enum": BASES},
        },
        "required": ["stage", "description", "timestamp_range", "confidence", "mitre",
                     "refs", "basis"],
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
            "refs": _refs(f, REFS_CAP),
            "basis": {"enum": BASES},
        },
        "required": ["timestamp", "event", "severity", "source_ip", "target", "mitre",
                     "refs", "basis"],
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
                        "refs": _refs(f, NOTABLE_REFS_CAP),
                    },
                    "required": ["ts", "event", "sev", "src", "target", "mitre", "refs"],
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


def check(result: dict, prompt: str, refs: dict | None = None) -> dict:
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
    if refs is not None:
        checked += _check_citations(result, refs, unsupported)
    return {"ok": not unsupported, "checked": checked, "unsupported": unsupported}


def _cited(result: dict):
    for key in ("attack_chain", "timeline"):
        for i, item in enumerate(result.get(key) or []):
            if isinstance(item, dict):
                yield f"{key}[{i}]", item


def _ref_list(item: dict) -> list[str]:
    # Unconstrained (Groq) output can write "refs": "F3" - one ref, not the
    # letters F and 3.
    refs = item.get("refs")
    if isinstance(refs, str):
        refs = [refs]
    return [r for r in refs or [] if isinstance(r, str)]


def _covers(text_ip: str, prefix: str | None, stated: set) -> bool:
    if not prefix:
        return text_ip in stated
    try:
        net = ipaddress.ip_network(f"{text_ip}/{prefix}", strict=False)
    except ValueError:
        return False
    return any(_valid(ip) and ipaddress.ip_address(ip) in net for ip in stated)


def _check_citations(result: dict, refs: dict, unsupported: list) -> int:
    """Citations the schema cannot police: Groq gets no schema, so a ref can
    be absent or invented there; and on either path an entry can cite real
    findings that are about a different source than the one it names."""
    checked = 0
    for path, item in _cited(result):
        cited = _ref_list(item)
        checked += 1
        if not cited:
            unsupported.append({"path": f"{path}.refs", "kind": "uncited", "value": ""})
            continue
        for r in cited:
            if r not in refs:
                unsupported.append({"path": f"{path}.refs", "kind": "ref", "value": r})
        src = item.get("source_ip")
        known = [refs[r] for r in cited if r in refs]
        if not known:
            continue
        if src:
            checked += 1
            if not any(src in (k.get("srcip"), k.get("username")) for k in known):
                unsupported.append({
                    "path": f"{path}.source_ip", "kind": "relation",
                    "value": f"{src} - not the source of {', '.join(cited)}",
                })
        # The same test on the prose: an address the entry names must be one
        # its own citations state. "Brute-forced root on 10.10.1.5", citing
        # auth-log findings that never name a host, joins two real entities
        # the evidence does not join - an inference written as a fact.
        stated = {ip for k in known for ip in k.get("ips") or []}
        for field_ in ("description", "event", "target"):
            for m in _IPV4.finditer(str(item.get(field_) or "")):
                checked += 1
                # A network that covers a stated address is the same claim,
                # less specific - as in check().
                if not _covers(m.group(1), m.group(2), stated):
                    unsupported.append({
                        "path": f"{path}.{field_}", "kind": "relation",
                        "value": f"{m.group(0)} - not in {', '.join(cited)}",
                    })
    return checked


def resolve(result: dict, refs: dict) -> dict:
    """Turn each cited ref into the finding key the analyst reviews, in
    place, and count what was cited - `_meta.citations`."""
    out = {"entries": 0, "cited": 0, "fact": 0, "inference": 0, "findings": 0}
    seen = set()
    for _, item in _cited(result):
        out["entries"] += 1
        cited = list(dict.fromkeys(r for r in _ref_list(item) if r in refs))
        item["refs"] = cited
        item["finding_keys"] = [refs[r]["key"] for r in cited]
        if cited:
            out["cited"] += 1
        if item.get("basis") in BASES:
            out[item["basis"]] += 1
        seen.update(item["finding_keys"])
    out["findings"] = len(seen)
    return out


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
