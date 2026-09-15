from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from .routers import cases as cases_router
from .routers import companies as companies_router
from .routers import upload as upload_router
from .services import storage

app = FastAPI(title="Forensic Analyzer")

STATIC_DIR = Path(__file__).resolve().parent.parent / "static"

app.include_router(upload_router.router)
app.include_router(cases_router.router)
app.include_router(companies_router.router)


@app.on_event("startup")
async def on_startup():
    storage.ensure_dirs()


@app.get("/api/health")
async def health():
    return {"status": "ok"}


app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/")
async def index():
    return FileResponse(str(STATIC_DIR / "index.html"))
