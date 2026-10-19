import asyncio

from fastapi import APIRouter, HTTPException, Query

from ..services import findings_index, lifecycle, storage

router = APIRouter(prefix="/api/findings", tags=["findings"])


@router.get("")
async def list_findings(
    company_id: str | None = None,
    status: str | None = None,
    severity: str | None = None,
    q: str | None = Query(None, max_length=200),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    """Every finding that entered the status workflow (high and critical),
    across cases, newest activity first within a severity. `open_count` is what
    the Findings menu badge shows (FR-0.2)."""
    if company_id is not None and storage.load_company(company_id) is None:
        raise HTTPException(404, "Customer not found")
    if status is not None and status not in lifecycle.STATES:
        raise HTTPException(400, f"status must be one of: {', '.join(lifecycle.STATES)}")
    if severity is not None and severity not in findings_index.SEVERITIES:
        raise HTTPException(400, f"severity must be one of: {', '.join(findings_index.SEVERITIES)}")
    # Reads DuckDB for every case it has not cached: off the event loop.
    return await asyncio.to_thread(
        findings_index.listing, company_id, status, severity, q, limit, offset)
