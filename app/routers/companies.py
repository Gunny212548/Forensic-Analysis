from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from ..services import overview, storage

router = APIRouter(prefix="/api/companies", tags=["companies"])


class CompanyIn(BaseModel):
    name: str


@router.get("")
async def list_companies():
    return storage.list_companies()


# The Customers page (FR-6.1). Separate from the plain list above because it
# opens case DuckDBs, and the upload form only needs names. Sync on purpose,
# like /api/overview: FastAPI runs a plain `def` in its threadpool.
@router.get("/summary")
def company_summary():
    return overview.customers()


@router.post("")
async def create_company(payload: CompanyIn):
    name = payload.name.strip()
    if not name:
        raise HTTPException(400, "Company name is required")
    # Idempotent by name (case-insensitive) so re-submitting the same
    # company from the upload form's inline "add new" doesn't fork it.
    existing = storage.find_company_by_name(name)
    if existing:
        return existing
    return storage.create_company(name)
