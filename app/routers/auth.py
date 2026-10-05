from fastapi import APIRouter, Body, HTTPException, Request, Response

from .. import config
from ..services import auth

router = APIRouter(prefix="/api/auth", tags=["auth"])


@router.get("/config")
async def login_config():
    """What the login page needs before anyone is signed in."""
    return {"it_contact_url": config.IT_CONTACT_URL}


# Sync on purpose: the scrypt check takes ~50ms, and FastAPI runs a plain
# `def` in its threadpool instead of on the event loop.
@router.post("/login")
def login(request: Request, response: Response, body: dict = Body(...)):
    user = auth.authenticate(body.get("email") or "", body.get("password") or "")
    if user is None:
        # One message for unknown account and wrong password alike.
        raise HTTPException(401, "Incorrect account ID or password")
    response.set_cookie(
        auth.COOKIE_NAME,
        auth.issue_token(user["email"]),
        max_age=config.SESSION_HOURS * 3600,
        httponly=True,
        samesite="lax",
        secure=request.url.scheme == "https",
    )
    return auth.public(user)


@router.post("/logout")
async def logout(response: Response):
    response.delete_cookie(auth.COOKIE_NAME)
    return {"ok": True}


@router.get("/me")
async def me(request: Request):
    # The middleware in main.py has already rejected a missing session.
    return auth.public(request.state.user)
