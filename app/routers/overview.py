from fastapi import APIRouter

from ..services import overview

router = APIRouter(prefix="/api", tags=["overview"])


# Sync on purpose: it may open several case DuckDBs, and FastAPI runs a plain
# `def` in its threadpool instead of on the event loop.
@router.get("/overview")
def get_overview():
    return overview.build()
