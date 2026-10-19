import logging
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from .routers import auth as auth_router
from .routers import cases as cases_router
from .routers import companies as companies_router
from .routers import findings as findings_router
from .routers import overview as overview_router
from .routers import rules as rules_router
from .routers import upload as upload_router
from . import config
from .services import auth, jobs, storage

app = FastAPI(title="Forensic Analyzer")

STATIC_DIR = Path(__file__).resolve().parent.parent / "static"

app.include_router(auth_router.router)
app.include_router(upload_router.router)
app.include_router(cases_router.router)
app.include_router(findings_router.router)
app.include_router(companies_router.router)
app.include_router(overview_router.router)
app.include_router(rules_router.router)


# Everything under /api needs a signed-in user except what the login page
# itself calls. The page and its bundle stay public - they hold no data, and
# the login form is part of them.
PUBLIC_API = {"/api/health", "/api/auth/login", "/api/auth/config"}


@app.middleware("http")
async def require_login(request: Request, call_next):
    path = request.url.path
    if path.startswith("/api/") and path not in PUBLIC_API:
        user = auth.user_from_token(request.cookies.get(auth.COOKIE_NAME))
        if user is None:
            return JSONResponse({"detail": "Sign-in required"}, status_code=401)
        request.state.user = user
        if request.method == "POST" and path == "/api/upload":
            refused = _refuse_oversized_upload(request)
            if refused:
                return refused
    return await call_next(request)


# Multipart framing (boundaries, part headers, the small form fields) that
# Content-Length counts on top of the file itself.
MULTIPART_SLACK = 64 * 1024


def _refuse_oversized_upload(request: Request) -> JSONResponse | None:
    """FR-2.2 before the body is read - see upload.capacity_problem() for why
    it cannot wait for the handler. Only for signed-in users, so the disk's
    free space is not told to anyone who asks."""
    length = request.headers.get("content-length", "")
    if not length.isdigit():
        return None  # no declared size; the handler's own limit still applies
    problem = upload_router.capacity_problem(max(0, int(length) - MULTIPART_SLACK))
    if problem is None:
        return None
    status, detail = problem
    return JSONResponse({"detail": detail}, status_code=status)


@app.exception_handler(storage.StoreNeedsMigration)
async def needs_migration(_request: Request, exc: storage.StoreNeedsMigration):
    return JSONResponse({"detail": str(exc)}, status_code=503)


@app.on_event("startup")
async def on_startup():
    # Accounts belong in AUTH_DIR, not beside customer data (config.py).
    stray = [n for n in ("users.json", "session_secret") if (Path(config.DATA_DIR) / n).exists()]
    if stray:
        logging.getLogger("forensic").warning(
            "%s found in DATA_DIR (%s) - accounts now live in AUTH_DIR (%s) and these are "
            "not read; move them there or delete them", ", ".join(stray), config.DATA_DIR,
            config.AUTH_DIR)
    legacy = storage.ensure_root()
    if legacy:
        # Cases in the pre-2026-10-14 flat layout are invisible until moved
        # into their customers' stores - say so instead of showing an empty app.
        logging.getLogger("forensic").warning(
            "%s customer/case record(s) are still in the old shared layout and are not "
            "shown; adding customers or cases is refused until you run: "
            "python tools/migrate_to_customers.py --apply", legacy)
    # Start the pipeline workers, and queue again whatever a previous run
    # left unfinished (services/jobs.py). Not while the store is in the
    # old layout: those cases are not visible to it.
    if not legacy:
        jobs.start()


@app.on_event("shutdown")
async def on_shutdown():
    # A deliberate stop (deploy, reboot): running jobs give their attempt back, so
    # only a stop nobody announced counts against a file (services/jobs.py).
    jobs.stop()


@app.get("/api/health")
async def health():
    return {"status": "ok"}


app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/")
async def index():
    return FileResponse(str(STATIC_DIR / "index.html"))
