from fastapi import APIRouter, Body, HTTPException, Request, Response

from .. import config
from ..services import auth, authz

router = APIRouter(prefix="/api/auth", tags=["auth"])


def _session_view(user: dict) -> dict:
    """The account, its permissions, and which roles each action needs - so
    the page can say why a control is disabled (IAI-14)."""
    return {**auth.public(user), "needs": authz.NEEDS}


@router.get("/config")
async def login_config():
    """What the login page needs before anyone is signed in."""
    return {"it_contact_url": config.IT_CONTACT_URL}


def _client(request: Request) -> str | None:
    # The address the server saw - behind Docker's port mapping that can be
    # the bridge gateway, not the analyst's machine (CLAUDE.md gotcha #28).
    return request.client.host if request.client else None


# Sync on purpose: the scrypt check takes ~50ms, and FastAPI runs a plain
# `def` in its threadpool instead of on the event loop.
@router.post("/login")
def login(request: Request, response: Response, body: dict = Body(...)):
    email, password = body.get("email") or "", body.get("password") or ""
    # Anything but two strings of sane length is a failed attempt like any
    # other: counted, logged, and the same 401 - never a 500, and never a
    # megabyte handed to scrypt.
    valid = (isinstance(email, str) and isinstance(password, str)
             and len(email) <= auth.MAX_EMAIL and len(password) <= auth.MAX_PASSWORD)
    key = auth.normalize_email(email) if valid else "(invalid)"
    known = auth.load_users().get(key)
    client = _client(request)

    wait, token, scope = auth.throttle.begin(key)
    if token is None:
        if auth.throttle.first_refusal(scope):
            auth.audit("login_throttled", account=known["email"] if known else None,
                       attempted=None if known else key, client=client)
        minutes = -(-wait // 60)
        raise HTTPException(
            429, f"Too many failed sign-ins. Try again in {minutes} minute{'s' if minutes != 1 else ''}.",
            headers={"Retry-After": str(wait)})

    user = auth.authenticate(email, password) if valid else None
    if user is None:
        auth.audit("login_failed", account=known["email"] if known else None,
                   attempted=None if known else key, client=client)
        # One message for unknown account and wrong password alike.
        raise HTTPException(401, "Incorrect account ID or password")

    auth.throttle.succeed(key, token)
    auth.audit("login_ok", account=user["email"], client=client)
    response.set_cookie(
        auth.COOKIE_NAME,
        auth.issue_token(user),
        max_age=config.SESSION_HOURS * 3600,
        httponly=True,
        samesite="lax",
        secure=request.url.scheme == "https",
    )
    return _session_view(user)


@router.post("/logout")
def logout(request: Request, response: Response):
    # The middleware has already required a session, so the account is known.
    auth.audit("logout", account=request.state.user["email"], client=_client(request))
    response.delete_cookie(auth.COOKIE_NAME)
    return {"ok": True}


@router.get("/me")
async def me(request: Request):
    # The middleware in main.py has already rejected a missing session.
    return _session_view(request.state.user)
