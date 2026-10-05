"""Accounts and sessions (FR-1). Standard library only - no new dependency.

Accounts live in DATA_DIR/users.json and are created with
`tools/create_user.py`; there is no sign-up page, because this is an internal
tool and who may read customer logs is decided by an administrator, not by
whoever reaches the login screen.

Sessions are a signed cookie rather than server-side state: the payload is
{email, exp}, HMAC-signed with a secret from SESSION_SECRET or, failing that,
one generated once and kept in DATA_DIR. Every request re-reads the account,
so deleting a user ends their sessions immediately. The price of being
stateless is that logging out clears the cookie in the browser but cannot
revoke a copy of it taken elsewhere before it expires (SESSION_HOURS).

`role` is a stored label only. Roles and what each may do are undefined until
IAI-14, so nothing here enforces one.
"""

import base64
import hashlib
import hmac
import json
import os
import secrets
import threading
import time
from pathlib import Path

from .. import config

COOKIE_NAME = "fa_session"
DEFAULT_ROLE = "analyst"

# scrypt at the parameters hashlib documents as the interactive-login
# baseline: ~50ms and 16MB per check, which is the point.
_SCRYPT = {"n": 2**14, "r": 8, "p": 1, "dklen": 32}

_lock = threading.Lock()
_cache: dict = {"mtime": None, "users": {}}


def _users_path() -> Path:
    return Path(config.DATA_DIR) / "users.json"


def _secret_path() -> Path:
    return Path(config.DATA_DIR) / "session_secret"


# --- passwords -------------------------------------------------------------

def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, **_SCRYPT)
    return f"scrypt${salt.hex()}${digest.hex()}"


def _check_hash(password: str, stored: str) -> bool:
    try:
        scheme, salt_hex, digest_hex = stored.split("$")
    except ValueError:
        return False
    if scheme != "scrypt":
        return False
    digest = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt_hex), **_SCRYPT)
    return hmac.compare_digest(digest.hex(), digest_hex)


# A real hash to check against when the email is unknown, so an unknown
# account costs the same time as a wrong password and response timing does
# not reveal which addresses have accounts.
_DUMMY_HASH = hash_password(secrets.token_hex(8))


# --- accounts --------------------------------------------------------------

def load_users() -> dict:
    """{email: user}. Re-read only when the file changes."""
    path = _users_path()
    try:
        mtime = path.stat().st_mtime_ns
    except FileNotFoundError:
        return {}
    with _lock:
        if _cache["mtime"] != mtime:
            data = json.loads(path.read_text(encoding="utf-8") or "[]")
            _cache["users"] = {u["email"]: u for u in data}
            _cache["mtime"] = mtime
        return dict(_cache["users"])


def save_users(users: dict) -> None:
    path = _users_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(sorted(users.values(), key=lambda u: u["email"]),
                              ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(tmp, path)


def normalize_email(email: str) -> str:
    return (email or "").strip().lower()


def public(user: dict) -> dict:
    """What the browser is allowed to see - never the hash."""
    return {"email": user["email"], "name": user.get("name") or user["email"],
            "role": user.get("role") or DEFAULT_ROLE}


def authenticate(email: str, password: str) -> dict | None:
    user = load_users().get(normalize_email(email))
    ok = _check_hash(password or "", user["password"] if user else _DUMMY_HASH)
    return user if (user and ok) else None


# --- sessions --------------------------------------------------------------

def _secret() -> bytes:
    env = os.environ.get("SESSION_SECRET", "")
    if env:
        return env.encode()
    path = _secret_path()
    with _lock:
        if not path.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(secrets.token_hex(32), encoding="utf-8")
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
        return path.read_text(encoding="utf-8").strip().encode()


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def issue_token(email: str) -> str:
    payload = _b64(json.dumps({"email": email,
                               "exp": int(time.time()) + config.SESSION_HOURS * 3600}).encode())
    sig = _b64(hmac.new(_secret(), payload.encode(), hashlib.sha256).digest())
    return f"{payload}.{sig}"


def user_from_token(token: str | None) -> dict | None:
    if not token or "." not in token:
        return None
    payload, sig = token.rsplit(".", 1)
    expected = _b64(hmac.new(_secret(), payload.encode(), hashlib.sha256).digest())
    if not hmac.compare_digest(sig, expected):
        return None
    try:
        data = json.loads(_unb64(payload))
    except (ValueError, json.JSONDecodeError):
        return None
    if data.get("exp", 0) < time.time():
        return None
    return load_users().get(data.get("email"))
