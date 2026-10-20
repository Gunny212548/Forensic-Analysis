"""A case as a VERIS incident record (VERIS Community Schema 1.4).

VERIS (Vocabulary for Event Recording and Incident Sharing) describes an
incident by its "4 A's": Actor (who), Action (what they did), Asset (what was
affected), Attribute (how - confidentiality, integrity, availability). Here
the classification is **computed from the findings, not written by the
model** - the lesson of CLAUDE.md gotcha #13: hand the model the fact, do not
ask it to infer it. The AI narrative is then given this record as context.

What goes in, and why each choice is what a log can support:

- Only findings in the workflow (Sigma high/critical, lifecycle.py) - the
  alert-worthy ones. Medium noise such as the former R3000 would otherwise turn every
  internal user of a risky app into an "internal actor". A case with none
  has no VERIS record.
- **Actor** is the attacking side of each finding: the source for auth,
  scan and policy-gap rules, but the *destination* for C2 / malware /
  exfiltration rules, whose source is the victim host. A public address is
  `external` (variety and motive Unknown - a log does not tell you who).
  A private one is `unknown` with a note, because an internal address does
  not mean an internal person.
- **Action** varieties map one-to-one from rules (table below); vectors come
  from the log source that recorded the finding (OpenSSH -> "Command shell",
  VERIS's remote shell; Entra ID -> "Web application"), else Unknown.
- **Asset** is counted, not guessed: distinct victim hosts/accounts as
  variety "Unknown" - nothing in a log says whether a host is a laptop or a
  VM host. Cloud is "External Cloud Asset(s)" only for an Entra ID source.
- **Attribute**: confidentiality "Potentially" disclosed only when a large
  outbound transfer is part of a compromised-host path; otherwise omitted.
- **security_incident** follows the lifecycle: Confirmed if any finding was
  closed as a true positive, False positive if every tracked finding was
  closed as false/benign, else Suspected. **confidence** is the best
  Admiralty label (confidence.py) among them.

Enumeration values and required fields were checked against
vz-risk/veris verisc-enum.json / verisc-merged.json; the output validates
against the merged schema (see CLAUDE.md gotcha #36).
"""

import uuid
from datetime import datetime, timedelta, timezone

from .confidence import _member_of
from .lifecycle import RESOLVED, tracked

SCHEMA_VERSION = "1.4.0"  # what verisc.json declares as its schema_version default
NAMESPACE = uuid.uuid5(uuid.NAMESPACE_URL, "https://github.com/Gunny212548/Forensic-Analysis/veris")
GMT7 = timezone(timedelta(hours=7))

# rule -> (VERIS action category, variety, whose address is the actor)
ACTION = {
    "R2000": ("hacking", "Brute force", "src"),
    "R2005": ("hacking", "Brute force", "src"),
    "R2009": ("hacking", "Brute force", "src"),
    "R2008": ("hacking", "Use of stolen creds", "src"),
    "R2006": ("hacking", "Use of stolen creds", "src"),
    "R2002": ("hacking", "Scan network", "src"),
    "R2003": ("hacking", "Scan network", "src"),
    "R3004": ("hacking", "Scan network", "src"),
    "R2004": ("hacking", "Unknown", "src"),
    "R2007": ("malware", "C2", "dst"),
    "R3003": ("malware", "C2", "dst"),
    "R3005": ("malware", "C2", "dst"),
    "R3002": ("malware", "Downloader", "dst"),
    "R3001": ("malware", "Export data", "dst"),
}
_VECTOR = {"openssh-sshd": "Command shell", "entra-signin": "Web application"}


def _private(ip: str) -> bool:
    import ipaddress
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def _source_profile(f: dict, manifest: dict) -> str | None:
    member = _member_of(f.get("sample_row_id"), manifest.get("members") or [])
    mapping = (member or {}).get("mapping") if member else manifest.get("mapping")
    if not mapping:
        return None
    if mapping.get("profile"):
        return mapping["profile"]
    lines = mapping.get("line_profiles") or []
    return lines[0]["profile"] if lines else None


def _dest(f: dict) -> str | None:
    """The other end of a finding's traffic, from its description - collapsed
    findings keep the source and account, not the destination column."""
    import re
    m = re.search(r"->\s*([0-9a-fA-F:.]+)", f.get("descr") or "")
    return m.group(1) if m else None


def build(case_id: str, manifest: dict, findings: list[dict]) -> dict | None:
    """The VERIS record, or None when no finding is in the workflow."""
    tf = [f for f in findings if tracked(f)]
    if not tf:
        return None

    actors_ext, actors_int = set(), set()
    hacking_var, hacking_vec, malware_var = set(), set(), set()
    victims = set()
    cloud = set()
    exfil = False
    for f in tf:
        cat, variety, side = ACTION.get(f["rid"], ("hacking", "Unknown", "src"))
        actor_ip = f.get("srcip") if side == "src" else _dest(f)
        victim = (f.get("username") or _dest(f)) if side == "src" else f.get("srcip")
        if actor_ip:
            (actors_int if _private(actor_ip) else actors_ext).add(actor_ip)
        if victim:
            victims.add(victim)
        profile = _source_profile(f, manifest)
        if profile == "entra-signin":
            cloud.add("External Cloud Asset(s)")
        if any(e.get("pattern") == "credential-compromise" for e in f.get("escalation") or []):
            hacking_var.add("Use of stolen creds")
        if cat == "hacking":
            hacking_var.add(variety)
            hacking_vec.add(_VECTOR.get(profile, "Unknown"))
        else:
            malware_var.add(variety)
            if variety == "Export data" and f.get("level") == "critical":
                exfil = True

    action = {}
    if hacking_var:
        action["hacking"] = {"variety": sorted(hacking_var), "vector": sorted(hacking_vec)}
    if malware_var:
        action["malware"] = {"variety": sorted(malware_var), "vector": ["Unknown"]}

    actor = {}
    if actors_ext:
        actor["external"] = {"variety": ["Unknown"], "motive": ["Unknown"],
                             "notes": "Public source address(es): " + ", ".join(sorted(actors_ext)[:20])}
    if actors_int:
        actor["unknown"] = {"notes": (
            "Activity came from internal address(es) " + ", ".join(sorted(actors_int)[:20])
            + " - a log cannot show whether the person was internal or an external "
              "attacker operating from an internal host.")}

    lc = [f.get("lifecycle") or {} for f in tf]
    resolved = [x for x in lc if x.get("status") == RESOLVED]
    if any(x.get("classification") == "true_positive" for x in resolved):
        security_incident = "Confirmed"
    elif resolved and len(resolved) == len(lc):
        security_incident = "False positive"
    else:
        security_incident = "Suspected"
    best = min((f.get("credibility", 3) for f in tf), default=3)
    confidence = "High" if best <= 2 else "Medium" if best == 3 else "Low"

    first = min((f["ts_min"] for f in tf if f.get("ts_min")), default=None)
    timeline = {"incident": {"year": first.year, "month": first.month, "day": first.day}} if first \
        else {"incident": {"year": datetime.now(GMT7).year}}

    record = {
        "schema_version": SCHEMA_VERSION,
        "incident_id": str(uuid.uuid5(NAMESPACE, case_id)),
        "security_incident": security_incident,
        "confidence": confidence,
        "summary": (
            f"forensic-analyzer case {case_id} ({manifest.get('original_filename')}) "
            f"for {manifest.get('company_name') or 'an unnamed customer'}: "
            f"{len(tf)} high/critical finding group(s); actions "
            + ", ".join(sorted(hacking_var | malware_var)) + "."
        ),
        "actor": actor,
        "action": action,
        "asset": {
            "assets": [{"variety": "Unknown", "amount": max(1, len(victims))}],
            "cloud": sorted(cloud) or ["Unknown"],
            "notes": "Affected: " + ", ".join(sorted(victims)[:20]) if victims else "Affected: unknown",
        },
        "discovery_method": {"internal": {"variety": ["Log review"]}},
        "timeline": timeline,
        "targeted": "Unknown",
        # No `victim`: VERIS requires country, employee_count, industry and
        # government on it, none of which a log holds - the customer is
        # named in the summary instead of filling those with guesses.
        "reference": f"evidence sha256 {(manifest.get('evidence') or {}).get('sha256') or 'not recorded'}",
    }
    if exfil:
        record["attribute"] = {"confidentiality": {"data_disclosure": "Potentially"}}
    return record


def summary_line(record: dict | None) -> str | None:
    """One compact line of the 4 A's, for the AI prompt and the UI."""
    if not record:
        return None
    actor = ", ".join(k for k in ("external", "internal", "unknown") if k in record["actor"])
    action = "; ".join(f"{k}: {', '.join(v['variety'])} via {', '.join(v['vector'])}"
                       for k, v in record["action"].items())
    attr = "confidentiality potentially disclosed" if record.get("attribute") else "no attribute established"
    return (f"VERIS - actor: {actor}; action: {action}; asset: {record['asset']['assets'][0]['amount']} "
            f"affected; attribute: {attr}; status: {record['security_incident']} "
            f"(confidence {record['confidence']})")
