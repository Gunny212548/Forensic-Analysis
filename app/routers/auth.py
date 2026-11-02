from fastapi import APIRouter, Body, HTTPException, Request, Response
from fastapi.responses import RedirectResponse

from .. import config
from ..services import auth, authz, google_login

router = APIRouter(prefix="/api/auth", tags=["auth"])


def _session_view(user: dict) -> dict:
    """The account, its permissions, and which roles each action needs - so
    the page can say why a control is disabled (IAI-14)."""
    return {**auth.public(user), "needs": authz.NEEDS}


@router.get("/config")
async def login_config():
    """What the login page needs before anyone is signed in."""
    return {"it_contact_url": config.IT_CONTACT_URL, "google": google_login.enabled()}


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
    _set_session(request, response, user)
    return _session_view(user)


def _set_session(request: Request, response: Response, user: dict) -> None:
    response.set_cookie(
        auth.COOKIE_NAME,
        auth.issue_token(user),
        max_age=config.SESSION_HOURS * 3600,
        httponly=True,
        samesite="lax",
        # Behind a TLS proxy the request reads http; PUBLIC_URL says what the browser sees.
        secure=request.url.scheme == "https" or google_login.secure_cookies(),
    )


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


# --- Sign in with Google (specs/google_login.md) -----------------------------
# Both routes are open without a session (main.PUBLIC_API) and answer with a
# redirect, never a page: the browser navigates here, it does not fetch.

@router.get("/google/start")
def google_start(request: Request):
    try:
        url, pending = google_login.begin()
    except google_login.Refused as exc:
        return RedirectResponse(f"/?signin={exc.reason}#/login", status_code=303)
    resp = RedirectResponse(url, status_code=303)
    # Lax, not Strict: the callback is a top-level GET from accounts.google.com,
    # which Lax sends the cookie with and Strict would not.
    resp.set_cookie(google_login.PENDING_COOKIE, pending, max_age=google_login.PENDING_SECONDS,
                    path="/api/auth/google", httponly=True, samesite="lax",
                    secure=request.url.scheme == "https" or google_login.secure_cookies())
    return resp


# Sync on purpose: the code exchange is a blocking HTTPS call to Google, so it
# runs in FastAPI's threadpool and not on the event loop.
@router.get("/google/callback")
def google_callback(request: Request, state: str | None = None, code: str | None = None,
                    error: str | None = None):
    client = _client(request)
    try:
        user = google_login.finish(request.cookies.get(google_login.PENDING_COOKIE), state, code, error)
    except google_login.Refused as exc:
        known = auth.load_users().get(exc.email) if exc.email else None
        # An address with no account is kept as a keyed digest, as for passwords.
        auth.audit("login_failed", account=known["email"] if known else None,
                   attempted=None if known else exc.email, client=client,
                   method="google", reason=exc.reason)
        resp = RedirectResponse(f"/?signin={exc.reason}#/login", status_code=303)
    else:
        auth.audit("login_ok", account=user["email"], client=client, method="google")
        resp = RedirectResponse("/#/dashboard", status_code=303)
        _set_session(request, resp, user)
    # One use only, whatever happened.
    resp.delete_cookie(google_login.PENDING_COOKIE, path="/api/auth/google")
    return resp
