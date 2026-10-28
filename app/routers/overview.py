from fastapi import APIRouter, HTTPException

from ..services import overview, storage

router = APIRouter(prefix="/api", tags=["overview"])


# Sync on purpose: it may open several case DuckDBs, and FastAPI runs a plain
# `def` in its threadpool instead of on the event loop.
@router.get("/overview")
def get_overview(company_id: str | None = None, project_id: str | None = None):
    if company_id is not None and storage.load_company(company_id) is None:
        raise HTTPException(404, "Customer not found")
    # One investigation's dashboard (specs/projects.md P2): a project is a customer's.
    if project_id is not None and (company_id is None or storage.load_project(company_id, project_id) is None):
        raise HTTPException(404, "Project not found for this customer")
    return overview.build(company_id, project_id)
