"""A case's techniques as a MITRE ATT&CK Navigator layer (layer format 4.5).

The layer is the standard way to hand ATT&CK coverage to another tool or
person: open it in the ATT&CK Navigator and the case's techniques light up
on the Enterprise matrix. Format per the Navigator's own specification
(`layers/spec/v4.5/layerformat.md`): `name`, `domain` and `versions` are
required; each technique has `techniqueID` and, here, `tactic`, `score`,
`comment` and `metadata`.

- **score** is the Sigma level weight (severity.py: 1 informational ...
  16 critical) of the most severe finding that used the technique, so the
  colour means the same thing the rest of the app's levels mean. The legend
  says so.
- **tactic** comes from rule_meta.TACTICS, in the Navigator's spelling
  (`credential-access`, not Sigma's `credential_access`). A technique under
  several tactics (T1078, T1133) gets one entry per tactic, as the format
  expects when annotations should not appear under every tactic at once.
- The layer's metadata carries the case id and the evidence SHA-256, so a
  layer passed on can be traced back to the exact file it came from.
"""

from . import db
from .rule_meta import TACTICS
from .rules import RULE_LABELS
from .severity import LEVELS, WEIGHT, level_of

LAYER_VERSION = "4.5"
NAVIGATOR_VERSION = "4.9.0"  # the minimum the 4.5 spec accepts

# One colour per Sigma level, matching the app's severity colours in spirit:
# grey -> blue -> amber -> red.
_GRADIENT = ["#d9dde3", "#9fb7d6", "#e8b04b", "#d9822b", "#c0392b"]


def build(case_id: str, manifest: dict) -> dict:
    """The layer for one case. Techniques come from the ATT&CK ids the rules
    wrote into findings - the same ids the Events and Review tabs show."""
    rows = []
    if db.db_path(case_id).exists():
        con = db.connect(case_id, read_only=True)
        try:
            rows = con.execute(
                """
                SELECT t, rid, max(lvl), count(*)
                FROM (SELECT unnest(mitre) AS t, rid, lvl FROM findings)
                GROUP BY t, rid
                ORDER BY t, max(lvl) DESC, rid
                """
            ).fetchall()
        finally:
            con.close()

    by_tech: dict[str, list[tuple[str, int, int]]] = {}
    for tech, rid, lvl, n in rows:
        by_tech.setdefault(tech, []).append((rid, lvl, n))

    techniques = []
    for tech, hits in sorted(by_tech.items()):
        top = max(lvl for _, lvl, _ in hits)
        comment = "; ".join(
            f"{rid} {RULE_LABELS.get(rid, rid)} x{n} ({level_of(lvl)})" for rid, lvl, n in hits
        )
        tactics = TACTICS.get(tech.lower().split(".")[0], [])
        base = {
            "techniqueID": tech,
            "score": top,
            "comment": comment,
            "enabled": True,
            "metadata": [{"name": "highest level", "value": level_of(top)},
                         {"name": "rules", "value": ", ".join(rid for rid, _, _ in hits)}],
        }
        if tactics:
            for tactic in tactics:
                techniques.append({**base, "tactic": tactic.replace("_", "-")})
        else:
            techniques.append(base)

    evidence = manifest.get("evidence") or {}
    name = manifest.get("original_filename") or case_id
    return {
        "name": f"{name} ({case_id})",
        "versions": {"layer": LAYER_VERSION, "navigator": NAVIGATOR_VERSION},
        "domain": "enterprise-attack",
        "description": (
            "Techniques tagged by forensic-analyzer's detection rules on this case. "
            "Score = Sigma level weight of the most severe finding using the technique "
            "(1 informational, 2 low, 4 medium, 8 high, 16 critical)."
        ),
        "sorting": 3,  # by score, descending
        "hideDisabled": False,
        "techniques": techniques,
        "gradient": {"colors": _GRADIENT, "minValue": WEIGHT["informational"],
                     "maxValue": WEIGHT["critical"]},
        "legendItems": [
            {"label": f"{lvl} ({WEIGHT[lvl]})", "color": color}
            for lvl, color in zip(LEVELS, _GRADIENT)
        ],
        "showTacticRowBackground": False,
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False,
        "metadata": [
            {"name": "case_id", "value": case_id},
            {"name": "customer", "value": manifest.get("company_name") or ""},
            {"name": "evidence_sha256", "value": evidence.get("sha256") or "not recorded"},
            {"name": "evidence_retroactive", "value": str(bool(evidence.get("retroactive"))).lower()},
        ],
    }
