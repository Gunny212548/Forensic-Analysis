import asyncio

from fastapi import APIRouter, HTTPException, Query

from ..services import areas, findings_index, lifecycle, storage

router = APIRouter(prefix="/api/findings", tags=["findings"])


@router.get("")
async def list_findings(
    company_id: str | None = None,
    project_id: str | None = None,
    status: str | None = None,
    severity: str | None = None,
    area: str | None = None,
    unassigned: bool = False,
    decision: str | None = None,
    q: str | None = Query(None, max_length=200),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    """Every finding that entered the status workflow (high and critical),
    across cases, newest activity first within a severity. `undecided_count` is
    what the Findings menu badge shows (FR-0.2) since the page filters by the
    analyst's decision rather than the status workflow (2026-10-27)."""
    if company_id is not None and storage.load_company(company_id) is None:
        raise HTTPException(404, "Customer not found")
    # One investigation (specs/projects.md P2): a project is a customer's.
    if project_id is not None and (company_id is None or storage.load_project(company_id, project_id) is None):
        raise HTTPException(404, "Project not found for this customer")
    if status is not None and status not in (*lifecycle.STATES, findings_index.OPEN_FILTER):
        raise HTTPException(400, "status must be one of: "
                                 + ", ".join((*lifecycle.STATES, findings_index.OPEN_FILTER)))
    if decision is not None and decision not in findings_index.DECISIONS:
        raise HTTPException(400, f"decision must be one of: {', '.join(findings_index.DECISIONS)}")
    if severity is not None and severity not in findings_index.SEVERITIES:
        raise HTTPException(400, f"severity must be one of: {', '.join(findings_index.SEVERITIES)}")
    if area is not None and area not in areas.AREA_IDS:
        raise HTTPException(400, f"area must be one of: {', '.join(areas.AREA_IDS)}")
    # Reads DuckDB for every case it has not cached: off the event loop.
    return await asyncio.to_thread(
        findings_index.listing, company_id, status, severity, q, limit, offset, area, unassigned, decision,
        project_id)
