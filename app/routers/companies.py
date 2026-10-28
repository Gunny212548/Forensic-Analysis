import asyncio

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from ..services import authz, customer_delete, overview, projects, storage

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
async def create_company(payload: CompanyIn, request: Request):
    name = payload.name.strip()
    if not name:
        raise HTTPException(400, "Company name is required")
    # Idempotent by name (case-insensitive) so re-submitting the same
    # company from the upload form's inline "add new" doesn't fork it.
    existing = storage.find_company_by_name(name)
    if existing:
        return existing
    try:
        authz.require(request.state.user, authz.CUSTOMERS)  # a new customer is a manager's (IAI-14)
    except authz.Forbidden as exc:
        raise HTTPException(403, str(exc))
    return storage.create_company(name)


def _may_delete(request: Request, company_id: str) -> None:
    try:
        authz.require(request.state.user, authz.DELETE_CUSTOMER, company_id)
    except authz.Forbidden as exc:
        raise HTTPException(403, str(exc))


# What deleting the customer would remove, for the confirmation, and the cases
# that block it now (specs/customer_delete.md D1). Sync: it opens case DuckDBs.
@router.get("/{company_id}/deletion")
def deletion_preview(company_id: str, request: Request):
    _may_delete(request, company_id)
    try:
        return customer_delete.preview(company_id)
    except LookupError:
        raise HTTPException(404, "Company not found")


@router.delete("/{company_id}")
async def delete_company(company_id: str, request: Request):
    """Delete the customer with every case it holds, for good (specs/customer_delete.md):
    admin and manager; refused while one of its cases is processed or analysed. The
    deletion is recorded, hash-chained, in DATA_DIR/deleted/customers.jsonl."""
    _may_delete(request, company_id)
    try:
        record = await asyncio.to_thread(customer_delete.delete, company_id, request.state.user["email"])
    except customer_delete.Busy as exc:
        raise HTTPException(409, str(exc))
    except LookupError:
        raise HTTPException(404, "Company not found")
    return {"deleted": company_id, "record": record}


# Each project with its status and what its cases hold (specs/projects.md P1), Open
# first. Sync: it reads case DuckDBs (cached, overview._case_facts).
@router.get("/{company_id}/projects")
def list_projects(company_id: str):
    if storage.load_company(company_id) is None:
        raise HTTPException(404, "Company not found")
    return projects.summary(company_id)


@router.post("/{company_id}/projects/{project_id}/{action}")
async def change_project(company_id: str, project_id: str, action: str, request: Request):
    """Close or reopen a project (specs/projects.md P1, Q110 / Q113): manager and admin;
    closing is refused while a case of it is not processed or a suggestion not decided."""
    change = {"close": projects.close, "reopen": projects.reopen}.get(action)
    if change is None:
        raise HTTPException(404, "Not found")
    try:
        authz.require(request.state.user, authz.CUSTOMERS, company_id)
    except authz.Forbidden as exc:
        raise HTTPException(403, str(exc))
    try:
        return await asyncio.to_thread(change, company_id, project_id, request.state.user["email"])
    except projects.Refused as exc:
        raise HTTPException(409, str(exc))
    except LookupError:
        raise HTTPException(404, "Project not found")
