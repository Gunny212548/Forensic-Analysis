"""Accounts and sessions (FR-1). Standard library only - no new dependency.

Accounts live in AUTH_DIR/users.json - not with customer data (config.py) -
and are created with
`tools/create_user.py`; there is no sign-up page, because this is an internal
tool and who may read customer logs is decided by an administrator, not by
whoever reaches the login screen.

Sessions are a signed cookie rather than server-side state: the payload is
{email, exp}, HMAC-signed with a secret from SESSION_SECRET or, failing that,
one generated once and kept in AUTH_DIR. Every request re-reads the account,
so deleting a user ends their sessions immediately. The price of being
stateless is that logging out clears the cookie in the browser but cannot
revoke a copy of it taken elsewhere before it expires (SESSION_HOURS).

An account's `role` (admin, manager, analyst) decides what it may do -
`authz.py` (IAI-14). Accounts are changed here, by an administrator through the
Users page or by `tools/create_user.py`, and every change is a hash-chained
line in AUTH_DIR/audit/accounts.jsonl (NIST SP 800-53 AC-2(7), AC-6(9)). A
disabled account cannot sign in and its sessions end at once.
"""

import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import threading
import time
from pathlib import Path

from .. import config
from . import authz, hashchain

COOKIE_NAME = "fa_session"
DEFAULT_ROLE = "analyst"

# scrypt at the parameters hashlib documents as the interactive-login
# baseline: ~50ms and 16MB per check, which is the point.
_SCRYPT = {"n": 2**14, "r": 8, "p": 1, "dklen": 32}

_lock = threading.Lock()
_cache: dict = {"mtime": None, "users": {}}


def _users_path() -> Path:
    return Path(config.AUTH_DIR) / "users.json"


def _secret_path() -> Path:
    return Path(config.AUTH_DIR) / "session_secret"


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
    """What the browser is allowed to see - never the hash. `permissions` are
    the authz actions the account may take, so the page can say which
    controls need another role (the server decides regardless)."""
    return {"email": user["email"], "name": user.get("name") or user["email"],
            "role": user.get("role") or DEFAULT_ROLE, "disabled": bool(user.get("disabled")),
            "permissions": authz.permissions(user)}


def authenticate(email: str, password: str) -> dict | None:
    user = load_users().get(normalize_email(email))
    ok = _check_hash(password or "", user["password"] if user else _DUMMY_HASH)
    return user if (user and ok and not user.get("disabled")) else None


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


def _password_version(user: dict) -> str:
    """Changes whenever the stored password does, so a cookie issued before a
    reset stops working. Keyed with the session secret: the token is signed
    but readable, and this should not hand out a bare digest of the hash."""
    return hmac.new(_secret(), user["password"].encode(), hashlib.sha256).hexdigest()[:16]


def issue_token(user: dict) -> str:
    payload = _b64(json.dumps({"email": user["email"], "pv": _password_version(user),
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
    user = load_users().get(data.get("email"))
    if user is None or not hmac.compare_digest(str(data.get("pv", "")), _password_version(user)):
        return None  # no such account any more, or its password changed since
    if user.get("disabled"):
        return None  # disabled since the session began
    return user


# --- sign-in throttle ------------------------------------------------------

MAX_EMAIL = 254      # RFC 5321 path limit
MAX_PASSWORD = 1024  # far above any real password; stops a megabyte reaching scrypt


class Throttle:
    """Failed sign-ins in a sliding window, per account and across all accounts.

    In memory, so it resets on restart and is per process - fine for the one
    uvicorn worker docker-compose runs (hashchain.py relies on the same).
    An attempt is counted when it *starts*, before the password is checked,
    and taken back if it succeeds: counting afterwards would let a burst of
    parallel requests all pass the check before any of them was recorded.
    Unknown accounts are counted exactly like known ones, so a 429 does not
    say which addresses have an account."""

    def __init__(self):
        self._lock = threading.Lock()
        self._by_key: dict[str, list[float]] = {}
        self._all: list[float] = []
        self._noted: dict[str, float] = {}

    def reset(self) -> None:
        with self._lock:
            self._by_key, self._all, self._noted = {}, [], {}

    @staticmethod
    def _wait(hits: list[float], limit: int, now: float) -> int:
        # The failure that has to leave the window for the count to drop below
        # the limit is the (len - limit)th, oldest first.
        return max(1, int(hits[len(hits) - limit] + config.LOGIN_WINDOW_SECONDS - now) + 1)

    def begin(self, key: str) -> tuple[int, float | None, str]:
        """(0, token, "") when the attempt may go ahead, else (seconds to wait,
        None, which limit refused it: "acct:<key>" or "all")."""
        now = time.monotonic()
        cutoff = now - config.LOGIN_WINDOW_SECONDS
        with self._lock:
            self._all = [t for t in self._all if t > cutoff]
            hits = [t for t in self._by_key.get(key, ()) if t > cutoff]
            if len(hits) >= config.LOGIN_MAX_FAILURES:
                self._by_key[key] = hits
                return self._wait(hits, config.LOGIN_MAX_FAILURES, now), None, f"acct:{key}"
            if len(self._all) >= config.LOGIN_GLOBAL_MAX_FAILURES:
                return self._wait(self._all, config.LOGIN_GLOBAL_MAX_FAILURES, now), None, "all"
            hits.append(now)
            self._by_key[key] = hits
            self._all.append(now)
            if len(self._by_key) > 1000:
                self._by_key = {k: v for k, v in self._by_key.items() if v and v[-1] > cutoff}
            return 0, now, ""

    def succeed(self, key: str, token: float) -> None:
        """A correct password: this attempt is no failure, and the account's
        earlier slips are forgiven."""
        with self._lock:
            self._by_key.pop(key, None)
            try:
                self._all.remove(token)
            except ValueError:
                pass

    def first_refusal(self, scope: str) -> bool:
        """True once per limit per window - the audit log records that a limit
        engaged, not every request turned away, or a flood of refused requests
        would grow it without bound."""
        now = time.monotonic()
        with self._lock:
            last = self._noted.get(scope)
            if last is not None and now - last <= config.LOGIN_WINDOW_SECONDS:
                return False
            self._noted[scope] = now
            if len(self._noted) > 1000:
                self._noted = {k: v for k, v in self._noted.items()
                               if now - v <= config.LOGIN_WINDOW_SECONDS}
            return True


throttle = Throttle()


# --- sign-in audit ---------------------------------------------------------

def audit_path() -> Path:
    return Path(config.AUTH_DIR) / "audit" / "login.jsonl"


def audit(event: str, *, account: str | None, client: str | None,
          attempted: str | None = None) -> None:
    """One hash-chained line per sign-in event (ISO/IEC 27001 A.8.15, like the
    review and custody logs). Never the password. An address that matches no
    account is recorded as a short digest, not as typed: people paste a
    password into the account field.

    A failure to write is logged and swallowed - an unwritable audit file must
    not lock every analyst out of an internal tool - but it is not silent."""
    entry = {"event": event, "account": account, "client": client}
    if account is None and attempted is not None:
        # Keyed: a bare SHA-256 of a pasted password is a dictionary lookup
        # away for whoever reads this file. The same input still gives the
        # same digest, so repeated attempts can be told apart and counted.
        entry["attempted_hmac"] = hmac.new(_secret(), attempted.encode(errors="replace"),
                                           hashlib.sha256).hexdigest()[:12]
    try:
        hashchain.append(audit_path(), entry)
    except Exception:
        logging.getLogger("forensic").exception("could not write the sign-in audit log")


# --- account management (IAI-14) -------------------------------------------

MIN_PASSWORD = 10
_accounts_lock = threading.Lock()


class AccountError(ValueError):
    """A refused account change; the message says why."""


def accounts_audit_path() -> Path:
    return Path(config.AUTH_DIR) / "audit" / "accounts.jsonl"


def _audit_account(actor: str, event: str, account: str, **details) -> None:
    """The line first: an account change that is not in the chain did not
    happen (AC-6(9)) - unlike the sign-in log, a failure here refuses the
    change. Never a password."""
    hashchain.append(accounts_audit_path(), {"event": event, "actor": actor, "account": account, **details})


def _check_password(password: str) -> None:
    if not isinstance(password, str) or len(password) < MIN_PASSWORD:
        raise AccountError(f"a password needs at least {MIN_PASSWORD} characters")
    if len(password) > MAX_PASSWORD:
        raise AccountError("that password is too long")


def _check_role(role: str) -> None:
    if role not in authz.ROLES:
        raise AccountError(f"role must be one of {', '.join(authz.ROLES)}")


def _admins_left(users: dict) -> int:
    return sum(1 for u in users.values() if u.get("role") == authz.ADMIN and not u.get("disabled"))


def create_account(actor: str, email: str, name: str, role: str, password: str) -> dict:
    email = normalize_email(email)
    if "@" not in email or len(email) > MAX_EMAIL:
        raise AccountError("an account ID is an email address")
    _check_role(role)
    _check_password(password)
    with _accounts_lock:
        users = load_users()
        if email in users:
            raise AccountError(f"{email} already has an account")
        user = {"email": email, "name": (name or "").strip()[:200], "role": role,
                "password": hash_password(password), "created_at": _now(), "created_by": actor}
        _audit_account(actor, "account_created", email, role=role, name=user["name"])
        users[email] = user
        save_users(users)
    return user


def update_account(actor: str, email: str, *, name: str | None = None, role: str | None = None,
                   disabled: bool | None = None) -> dict:
    """Name, role, enabled. An administrator does not change their own role or
    disable themself (another administrator does), and the last enabled
    administrator stays one - or nobody could manage accounts again."""
    email = normalize_email(email)
    if name is not None and not isinstance(name, str):
        raise AccountError("a name is text")
    if disabled is not None and not isinstance(disabled, bool):
        raise AccountError("disabled is true or false")  # "false" would read as true
    with _accounts_lock:
        users = load_users()
        user = users.get(email)
        if user is None:
            raise LookupError(f"no account {email}")
        changes = {}
        if name is not None and name.strip()[:200] != (user.get("name") or ""):
            changes["name"] = [user.get("name") or "", name.strip()[:200]]
        if role is not None and role != user.get("role"):
            _check_role(role)
            changes["role"] = [user.get("role"), role]
        if disabled is not None and bool(disabled) != bool(user.get("disabled")):
            changes["disabled"] = [bool(user.get("disabled")), bool(disabled)]
        if not changes:
            return user
        if email == actor and ({"role", "disabled"} & set(changes)):
            raise AccountError("you cannot change your own role or disable yourself - ask another administrator")
        after = {**user, **{k: v[1] for k, v in changes.items()}}
        if user.get("role") == authz.ADMIN and _admins_left({**users, email: after}) == 0:
            raise AccountError("this is the last enabled administrator")
        _audit_account(actor, "account_changed", email, changes=changes)
        users[email] = {k: v for k, v in after.items() if not (k == "disabled" and not v)}
        save_users(users)
    return users[email]


def reset_password(actor: str, email: str, password: str) -> None:
    """A new password; the account's sessions end (the session is bound to it)."""
    email = normalize_email(email)
    _check_password(password)
    with _accounts_lock:
        users = load_users()
        if email not in users:
            raise LookupError(f"no account {email}")
        _audit_account(actor, "password_reset", email)
        users[email] = {**users[email], "password": hash_password(password)}
        save_users(users)


def remove_account(actor: str, email: str) -> None:
    email = normalize_email(email)
    with _accounts_lock:
        users = load_users()
        user = users.get(email)
        if user is None:
            raise LookupError(f"no account {email}")
        if email == actor:
            raise AccountError("you cannot remove your own account - ask another administrator")
        rest = {k: v for k, v in users.items() if k != email}
        if user.get("role") == authz.ADMIN and _admins_left(rest) == 0:
            raise AccountError("this is the last enabled administrator")
        _audit_account(actor, "account_removed", email, role=user.get("role"))
        save_users(rest)


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
