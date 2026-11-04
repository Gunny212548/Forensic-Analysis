from fastapi import APIRouter, HTTPException

from ..services.detection import rule_meta
from ..services.detection.rules import RULES

router = APIRouter(prefix="/api/rules", tags=["rules"])


@router.get("")
async def list_rules():
    """Every detection rule in Sigma field names, with its ADS documentation
    (services/detection/rule_meta.py)."""
    return [rule_meta.describe(rid) for rid, _ in RULES if rid in rule_meta.RULE_META]


@router.get("/{rid}")
async def get_rule(rid: str):
    if rid not in rule_meta.RULE_META:
        raise HTTPException(404, "Rule not found")
    return rule_meta.describe(rid)
