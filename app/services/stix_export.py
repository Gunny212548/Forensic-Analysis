"""A case as a STIX 2.1 bundle (OASIS STIX Version 2.1).

STIX is how threat intelligence moves between tools; a bundle from here can
be loaded into a TIP or SIEM, or handed to another team, without them
learning this tool's schema. What is emitted:

- `identity` x2 - this tool (`created_by_ref` of everything) and the
  customer (where the activity was sighted).
- `attack-pattern` per ATT&CK technique the rules tagged, with the
  `mitre-attack` external reference.
- `ipv4-addr` / `ipv6-addr` / `user-account` SCOs for the entities, with the
  spec's deterministic ids (UUIDv5 under the STIX SCO namespace over the
  id-contributing properties), so the same address is one object everywhere.
- per collapsed finding, an `observed-data` (first/last seen, how many rows,
  which entities) and one `sighting` per technique - "this technique was
  seen N times, here, between these times" - carrying `confidence` from the
  finding's Admiralty credibility via the STIX 2.1 mapping (1->90, 2->70,
  3->50, 4->30, 5->10; 6 has no value and is omitted).
- one `report` that references all of it, naming the evidence SHA-256.

Findings whose rule carries no ATT&CK technique (R1001 login success, R1003
connection, R1004 password change - context, not techniques) have nothing
to be a sighting *of*; they are left out and the report says how many.

SDO/SRO ids are UUIDv5 under this tool's own namespace over the case and
finding, rather than random: exporting the same case twice gives the same
ids, so a receiving platform updates objects instead of duplicating them.
Times are UTC, as STIX requires; the tool's own times are GMT+7.
"""

import json
import uuid
from datetime import datetime, timedelta, timezone

from .overview import TECHNIQUE_NAMES

SCO_NAMESPACE = uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")  # STIX 2.1, deterministic SCO ids
TOOL_NAMESPACE = uuid.uuid5(uuid.NAMESPACE_URL, "https://github.com/Gunny212548/Forensic-Analysis")

ADMIRALTY_TO_STIX = {1: 90, 2: 70, 3: 50, 4: 30, 5: 10}  # 6 "cannot be judged": no value
GMT7 = timezone(timedelta(hours=7))


def _sdo_id(kind: str, *parts: str) -> str:
    return f"{kind}--{uuid.uuid5(TOOL_NAMESPACE, '|'.join(parts))}"


def _sco_id(kind: str, contributing: dict) -> str:
    canon = json.dumps(contributing, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return f"{kind}--{uuid.uuid5(SCO_NAMESPACE, canon)}"


def _utc(value) -> str | None:
    """A naive GMT+7 datetime (raw_events.ts) or an aware ISO string -> STIX
    timestamp (UTC, millisecond precision, Z)."""
    if value is None or value == "":
        return None
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value)
        except ValueError:
            return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=GMT7)
    v = value.astimezone(timezone.utc)
    return v.strftime("%Y-%m-%dT%H:%M:%S.") + f"{v.microsecond // 1000:03d}Z"


def _ip_sco(value: str) -> dict:
    kind = "ipv6-addr" if ":" in value else "ipv4-addr"
    return {"type": kind, "spec_version": "2.1", "id": _sco_id(kind, {"value": value}), "value": value}


def _account_sco(login: str) -> dict:
    return {"type": "user-account", "spec_version": "2.1",
            "id": _sco_id("user-account", {"user_id": login}), "user_id": login}


def build(case_id: str, manifest: dict, findings: list[dict], created_at: str | None) -> dict:
    """`findings` are collapsed findings as /findings serves them (with
    `admiralty`, `review`, `lifecycle`)."""
    created = _utc(created_at) or _utc(datetime.now(timezone.utc))
    tool = {"type": "identity", "spec_version": "2.1", "id": _sdo_id("identity", "tool"),
            "created": created, "modified": created, "name": "forensic-analyzer",
            "identity_class": "system"}
    customer_name = manifest.get("company_name") or "unknown customer"
    customer = {"type": "identity", "spec_version": "2.1",
                "id": _sdo_id("identity", "customer", manifest.get("company_id") or customer_name),
                "created": created, "modified": created, "created_by_ref": tool["id"],
                "name": customer_name, "identity_class": "organization"}
    objects: dict[str, dict] = {tool["id"]: tool, customer["id"]: customer}

    def attack_pattern(tech: str) -> str:
        oid = _sdo_id("attack-pattern", tech)
        if oid not in objects:
            objects[oid] = {
                "type": "attack-pattern", "spec_version": "2.1", "id": oid,
                "created": created, "modified": created, "created_by_ref": tool["id"],
                "name": f"{tech} {TECHNIQUE_NAMES.get(tech, '')}".strip(),
                "external_references": [{
                    "source_name": "mitre-attack", "external_id": tech,
                    "url": f"https://attack.mitre.org/techniques/{tech.replace('.', '/')}/",
                }],
            }
        return oid

    skipped = 0
    for f in findings:
        techniques = f.get("mitre") or []
        if not techniques:
            skipped += 1
            continue
        refs = []
        for sco in ([_ip_sco(f["srcip"])] if f.get("srcip") else []) + \
                   ([_account_sco(f["username"])] if f.get("username") else []):
            objects.setdefault(sco["id"], sco)
            refs.append(sco["id"])
        first, last = _utc(f.get("ts_min")) or created, _utc(f.get("ts_max")) or created
        observed = None
        if refs:
            observed = {
                "type": "observed-data", "spec_version": "2.1",
                "id": _sdo_id("observed-data", case_id, f["key"]),
                "created": created, "modified": created, "created_by_ref": tool["id"],
                "first_observed": first, "last_observed": last,
                "number_observed": max(1, int(f.get("cnt") or 1)), "object_refs": refs,
            }
            objects[observed["id"]] = observed
        adm = f.get("admiralty") or {}
        lc = f.get("lifecycle") or {}
        detail = [f"{f['rid']}: {f.get('descr') or ''}".strip(),
                  f"level {f.get('level')}"
                  + (f" (raised from {f.get('base_level')})" if f.get("base_level") != f.get("level") else ""),
                  f"Admiralty {adm.get('code')}" if adm else "",
                  f"review {f.get('review', {}).get('status')}",
                  f"workflow {lc.get('status')}" if lc.get("tracked") else "not in workflow"]
        for tech in techniques:
            sighting = {
                "type": "sighting", "spec_version": "2.1",
                "id": _sdo_id("sighting", case_id, f["key"], tech),
                "created": created, "modified": created, "created_by_ref": tool["id"],
                "sighting_of_ref": attack_pattern(tech),
                "first_seen": first, "last_seen": last,
                "count": max(1, int(f.get("cnt") or 1)),
                "where_sighted_refs": [customer["id"]],
                "description": "; ".join(d for d in detail if d),
            }
            if observed:
                sighting["observed_data_refs"] = [observed["id"]]
            grade = (adm.get("credibility") or {}).get("grade")
            if grade in ADMIRALTY_TO_STIX:
                sighting["confidence"] = ADMIRALTY_TO_STIX[grade]
            objects[sighting["id"]] = sighting

    evidence = manifest.get("evidence") or {}
    report = {
        "type": "report", "spec_version": "2.1", "id": _sdo_id("report", case_id),
        "created": created, "modified": created, "created_by_ref": tool["id"],
        "name": f"{manifest.get('original_filename') or case_id} ({case_id})",
        "report_types": ["observed-data"],
        "published": created,
        "description": (
            f"Findings of forensic-analyzer on case {case_id} for {customer_name}. "
            f"Evidence SHA-256 {evidence.get('sha256') or 'not recorded'}"
            f"{' (recorded retroactively)' if evidence.get('retroactive') else ''}. "
            f"{skipped} finding group(s) without an ATT&CK technique are not included. "
            "Sighting confidence is the Admiralty credibility mapped per STIX 2.1."
        ),
        "object_refs": [oid for oid in objects if oid != tool["id"]],
    }
    return {"type": "bundle", "id": f"bundle--{uuid.uuid4()}",
            "objects": list(objects.values()) + [report]}
