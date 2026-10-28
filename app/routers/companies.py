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


async def _project_change(request: Request, action: str, company_id: str, change, *args):
    """Run one change to a project as the signed-in account: 403 without `action`,
    409 when it cannot be made now, 404 for no such project or case, 400 for a bad value."""
    try:
        authz.require(request.state.user, action, company_id)
    except authz.Forbidden as exc:
        raise HTTPException(403, str(exc))
    try:
        return await asyncio.to_thread(change, *args, request.state.user["email"])
    except projects.Refused as exc:
        raise HTTPException(409, str(exc))
    except LookupError:
        raise HTTPException(404, "Project or case not found")
    except ValueError as exc:
        raise HTTPException(400, str(exc))


# Close or reopen a project (specs/projects.md P1, Q110 / Q113): manager and admin;
# closing is refused while a case of it is not processed or a suggestion not decided.
@router.post("/{company_id}/projects/{project_id}/close")
async def close_project(company_id: str, project_id: str, request: Request):
    return await _project_change(request, authz.CUSTOMERS, company_id, projects.close, company_id, project_id)


@router.post("/{company_id}/projects/{project_id}/reopen")
async def reopen_project(company_id: str, project_id: str, request: Request):
    return await _project_change(request, authz.CUSTOMERS, company_id, projects.reopen, company_id, project_id)


class ProjectIn(BaseModel):
    name: str


@router.put("/{company_id}/projects/{project_id}")
async def rename_project(company_id: str, project_id: str, payload: ProjectIn, request: Request):
    """Rename a project, on it and on every case of it (P3): manager and admin."""
    return await _project_change(request, authz.CUSTOMERS, company_id, projects.rename,
                                 company_id, project_id, payload.name)


class MoveIn(BaseModel):
    case_id: str


@router.post("/{company_id}/projects/{project_id}/cases")
async def move_case(company_id: str, project_id: str, payload: MoveIn, request: Request):
    """Move one of the customer's cases into this project (P3): manager and admin; never
    across customers, into or out of a Closed project, or while the case is processed."""
    manifest = storage.load_manifest(payload.case_id) if storage.valid_case_id(payload.case_id) else None
    if manifest is None or manifest.get("company_id") != company_id:
        raise HTTPException(404, "Case not found for this customer")
    return await _project_change(request, authz.CUSTOMERS, company_id, projects.move_case,
                                 payload.case_id, project_id)


# The whole investigation (P4), read-only for every role: the confirmed groups of every
# case in time order, and the cases' attack graphs and risk ranking joined. Sync: they
# read case DuckDBs.
@router.get("/{company_id}/projects/{project_id}/timeline")
def project_timeline(company_id: str, project_id: str):
    try:
        return projects.timeline(company_id, project_id)
    except LookupError:
        raise HTTPException(404, "Project not found")


@router.get("/{company_id}/projects/{project_id}/graph")
def project_graph(company_id: str, project_id: str):
    try:
        return projects.graph(company_id, project_id)
    except LookupError:
        raise HTTPException(404, "Project not found")


# What deleting the project would remove, and the cases that block it now (P3).
@router.get("/{company_id}/projects/{project_id}/deletion")
def project_deletion_preview(company_id: str, project_id: str, request: Request):
    _may_delete(request, company_id)
    try:
        return projects.preview_delete(company_id, project_id)
    except LookupError:
        raise HTTPException(404, "Project not found")


@router.delete("/{company_id}/projects/{project_id}")
async def delete_project(company_id: str, project_id: str, request: Request):
    """Delete the project with every case in it, for good (P3): admin and manager, as a
    customer; recorded in the customer's deleted/log.jsonl."""
    record = await _project_change(request, authz.DELETE_CUSTOMER, company_id, projects.delete,
                                   company_id, project_id)
    return {"deleted": project_id, "record": record}
