"""Sign in with Google (specs/google_login.md, gotcha #82). Standard library only.

OpenID Connect Core 1.0's authorization code flow (§3.1) with PKCE (RFC 7636,
S256), run by the server - the page loads nothing from Google, it only links to
/api/auth/google/start:

  start     state, nonce and code_verifier are made here and kept in a short-lived
            cookie signed with the session secret (`fa_oauth`, 10 minutes), then
            the browser is sent to Google's authorization endpoint.
  callback  the cookie is read and cleared; `state` must match it (RFC 6749
            §10.12: CSRF on the redirection URI); the code is exchanged at
            Google's token endpoint with the client secret and the verifier.

The ID token comes straight from Google's token endpoint over TLS, so its
signature is not checked: OIDC Core §3.1.3.7 step 6 allows TLS server
validation in its place for exactly this case, and Google's guide says the same
of a token obtained "directly with Google over an intermediary-free HTTPS
channel". Every other step that applies is checked: iss, aud (and azp), exp,
iat, nonce; then email_verified, and the `hd` claim against
GOOGLE_ALLOWED_DOMAINS - the claim, never the `hd` request parameter, which
Google says only steers the account chooser. Who may then sign in, and as
what, is auth.google_account().

Each refusal has a reason code, the only thing passed back to the page, which
words it itself - no text from Google or from the request is reflected.
"""

import base64
import hashlib
import hmac
import json
import secrets
import time
import urllib.error
import urllib.parse
import urllib.request

from ... import config
from . import auth

AUTH_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"
ISSUERS = ("https://accounts.google.com", "accounts.google.com")  # Google's ID token iss values
CALLBACK_PATH = "/api/auth/google/callback"
PENDING_COOKIE = "fa_oauth"
PENDING_SECONDS = 600
CLOCK_SKEW = 300  # seconds of iat in the future, or of exp passed, that are tolerated

# What the login page may be told. Anything else is "failed".
REASONS = ("cancelled", "expired", "domain", "unverified", "disabled", "google_mismatch",
           "bad_token", "unreachable", "failed", "off")


class Refused(Exception):
    def __init__(self, reason: str, email: str | None = None):
        super().__init__(reason)
        self.reason = reason if reason in REASONS else "failed"
        self.email = email  # the Google account's address, once the token said it


def enabled() -> bool:
    return bool(config.GOOGLE_CLIENT_ID and config.GOOGLE_CLIENT_SECRET
                and config.GOOGLE_ALLOWED_DOMAINS and config.PUBLIC_URL)


def redirect_uri() -> str:
    return config.PUBLIC_URL + CALLBACK_PATH


def secure_cookies() -> bool:
    return config.PUBLIC_URL.lower().startswith("https://")


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _same(a, b) -> bool:
    """Constant-time equality for any text: compare_digest raises TypeError on a
    non-ASCII str, which a forged ?state= or cookie could otherwise turn into a 500."""
    return hmac.compare_digest(str(a).encode("utf-8", "replace"), str(b).encode("utf-8", "replace"))


def _sign(payload: str) -> str:
    # Purpose-tagged, so a pending-login cookie can never be passed off as a session.
    return _b64(hmac.new(auth._secret(), b"google-pending:" + payload.encode(), hashlib.sha256).digest())


# --- start -------------------------------------------------------------------

def begin() -> tuple[str, str]:
    """(URL to send the browser to, value of the pending cookie)."""
    if not enabled():
        raise Refused("off")
    state, nonce = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    verifier = secrets.token_urlsafe(48)  # 64 unreserved characters (RFC 7636 §4.1: 43-128)
    challenge = _b64(hashlib.sha256(verifier.encode("ascii")).digest())  # S256, §4.2
    payload = _b64(json.dumps({"s": state, "n": nonce, "v": verifier,
                               "exp": int(time.time()) + PENDING_SECONDS}).encode())
    domains = config.GOOGLE_ALLOWED_DOMAINS
    params = {
        "response_type": "code",
        "client_id": config.GOOGLE_CLIENT_ID,
        "redirect_uri": redirect_uri(),
        "scope": "openid email profile",
        "state": state,
        "nonce": nonce,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "prompt": "select_account",
        # Only a hint to the account chooser; the claim is what is checked.
        "hd": domains[0] if len(domains) == 1 else "*",
    }
    return f"{AUTH_ENDPOINT}?{urllib.parse.urlencode(params)}", f"{payload}.{_sign(payload)}"


def _pending(cookie: str | None) -> dict:
    if not cookie or "." not in cookie:
        raise Refused("expired")
    payload, sig = cookie.rsplit(".", 1)
    if not _same(sig, _sign(payload)):
        raise Refused("expired")
    try:
        data = json.loads(_unb64(payload))
    except (ValueError, json.JSONDecodeError):
        raise Refused("expired")
    if not isinstance(data, dict) or data.get("exp", 0) < time.time():
        raise Refused("expired")
    return data


# --- callback ----------------------------------------------------------------

def _exchange(code: str, verifier: str) -> dict:
    """The token response. Its own function so tests can stand in for Google."""
    body = urllib.parse.urlencode({
        "code": code, "client_id": config.GOOGLE_CLIENT_ID,
        "client_secret": config.GOOGLE_CLIENT_SECRET, "redirect_uri": redirect_uri(),
        "grant_type": "authorization_code", "code_verifier": verifier,
    }).encode()
    req = urllib.request.Request(TOKEN_ENDPOINT, data=body, method="POST",
                                 headers={"Content-Type": "application/x-www-form-urlencoded",
                                          "Accept": "application/json"})
    try:
        # urllib verifies Google's certificate and host name by default - which
        # is what lets the ID token's signature go unchecked (module docstring).
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read(1_000_000))
    except urllib.error.HTTPError:
        raise Refused("failed")  # a used, expired or forged code; a wrong secret
    except (urllib.error.URLError, TimeoutError, OSError):
        raise Refused("unreachable")
    except (ValueError, json.JSONDecodeError):
        raise Refused("failed")


def _claims(id_token: str) -> dict:
    parts = id_token.split(".") if isinstance(id_token, str) else []
    if len(parts) != 3:
        raise Refused("bad_token")
    try:
        claims = json.loads(_unb64(parts[1]))
    except (ValueError, json.JSONDecodeError):
        raise Refused("bad_token")
    if not isinstance(claims, dict):
        raise Refused("bad_token")
    return claims


def validate(claims: dict, nonce: str, now: float | None = None) -> dict:
    """OIDC Core §3.1.3.7 steps 2, 3, 5, 9, 10, 11, then Google's own claims.
    Returns {email, name, sub}."""
    now = time.time() if now is None else now
    cid = config.GOOGLE_CLIENT_ID
    if claims.get("iss") not in ISSUERS:
        raise Refused("bad_token")
    aud = claims.get("aud")
    if not (aud == cid or (isinstance(aud, list) and aud == [cid])):  # no other audience trusted
        raise Refused("bad_token")
    if "azp" in claims and claims["azp"] != cid:
        raise Refused("bad_token")
    try:
        exp, iat = float(claims["exp"]), float(claims["iat"])
    except (KeyError, TypeError, ValueError):
        raise Refused("bad_token")
    if exp + CLOCK_SKEW < now or iat - CLOCK_SKEW > now:
        raise Refused("bad_token")
    if not _same(claims.get("nonce", ""), nonce):
        raise Refused("bad_token")
    sub, email = claims.get("sub"), claims.get("email")
    if not isinstance(sub, str) or not sub or not isinstance(email, str) or "@" not in email:
        raise Refused("bad_token")
    email = auth.normalize_email(email)
    if claims.get("email_verified") not in (True, "true"):
        raise Refused("unverified", email)
    hd = claims.get("hd")
    # No hd claim = not a Workspace account (a personal @gmail.com) - Google.
    if not isinstance(hd, str) or hd.lower() not in config.GOOGLE_ALLOWED_DOMAINS:
        raise Refused("domain", email)
    name = claims.get("name") if isinstance(claims.get("name"), str) else ""
    return {"email": email, "name": name, "sub": sub}


def finish(cookie: str | None, state: str | None, code: str | None, error: str | None) -> dict:
    """The signed-in account, or Refused(reason)."""
    if not enabled():
        raise Refused("off")
    pending = _pending(cookie)
    if not isinstance(state, str) or not _same(state, pending.get("s", "")):
        raise Refused("expired")  # started in another browser or tab, or forged
    if error:
        raise Refused("cancelled" if error == "access_denied" else "failed")
    if not isinstance(code, str) or not code or len(code) > 2048:
        raise Refused("failed")
    tokens = _exchange(code, str(pending.get("v", "")))
    who = validate(_claims(tokens.get("id_token") if isinstance(tokens, dict) else None),
                   str(pending.get("n", "")))
    try:
        user = auth.google_account(who["email"], who["name"], who["sub"])
    except auth.AccountError as exc:
        raise Refused(str(exc), who["email"])
    if user.get("disabled"):  # created a moment ago by nobody else, but checked anyway
        raise Refused("disabled", who["email"])
    return user
