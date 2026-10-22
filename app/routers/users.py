"""Accounts, for an administrator (IAI-14, Q59): the Users page.

Every route needs `account:manage` (authz.py - admin only). Every change is a
hash-chained line in AUTH_DIR/audit/accounts.jsonl, written before the change
(auth.py); the history is served back with its chain checked.
"""

from fastapi import APIRouter, Body, HTTPException, Request

from ..services import auth, authz, hashchain

router = APIRouter(prefix="/api/users", tags=["users"])


def _admin(request: Request) -> str:
    try:
        authz.require(request.state.user, authz.ACCOUNTS)
    except authz.Forbidden as exc:
        raise HTTPException(403, str(exc))
    return request.state.user["email"]


def _view(user: dict) -> dict:
    return {**auth.public(user), "created_at": user.get("created_at"), "created_by": user.get("created_by")}


@router.get("")
def list_users(request: Request):
    _admin(request)
    return {"users": [_view(u) for u in sorted(auth.load_users().values(), key=lambda u: u["email"])],
            "roles": list(authz.ROLES),
            # What each role may do - the page shows it beside the role picker.
            "permissions": {r: sorted(authz.PERMISSIONS[r]) for r in authz.ROLES},
            "min_password": auth.MIN_PASSWORD}


# Sync: scrypt (~50 ms) runs in FastAPI's threadpool, not on the event loop.
@router.post("")
def create_user(request: Request, body: dict = Body(...)):
    actor = _admin(request)
    try:
        user = auth.create_account(actor, body.get("email") or "", body.get("name") or "",
                                   body.get("role") or "", body.get("password") or "")
    except auth.AccountError as exc:
        raise HTTPException(400, str(exc))
    return _view(user)


@router.patch("/{email}")
def update_user(email: str, request: Request, body: dict = Body(...)):
    actor = _admin(request)
    try:
        user = auth.update_account(actor, email, name=body.get("name"), role=body.get("role"),
                                   disabled=body.get("disabled"))
    except LookupError as exc:
        raise HTTPException(404, str(exc))
    except auth.AccountError as exc:
        raise HTTPException(400, str(exc))
    return _view(user)


@router.post("/{email}/password")
def reset_password(email: str, request: Request, body: dict = Body(...)):
    actor = _admin(request)
    try:
        auth.reset_password(actor, email, body.get("password") or "")
    except LookupError as exc:
        raise HTTPException(404, str(exc))
    except auth.AccountError as exc:
        raise HTTPException(400, str(exc))
    return {"ok": True}


@router.delete("/{email}")
def remove_user(email: str, request: Request):
    actor = _admin(request)
    try:
        auth.remove_account(actor, email)
    except LookupError as exc:
        raise HTTPException(404, str(exc))
    except auth.AccountError as exc:
        raise HTTPException(400, str(exc))
    return {"ok": True}


@router.get("/audit")
def account_audit(request: Request, limit: int = 100):
    """The newest account changes, and whether their chain is intact."""
    _admin(request)
    path = auth.accounts_audit_path()
    entries = hashchain.entries(path) if path.exists() else []
    return {"entries": entries[-max(1, min(limit, 1000)):][::-1], "chain": hashchain.verify(path)}
