"""Sign in with Google (specs/google_login.md, gotcha #82): the start redirect,
the PKCE / state / nonce round trip, every ID-token check, who gets in and as
what, and the audit lines - against a stand-in for Google's token endpoint.

    python tests/check_google_login.py [repo dir] [--scratch DIR]

A throwaway DATA_DIR and AUTH_DIR, the real app through FastAPI's TestClient.
No network, no Google account.
"""
import argparse
import base64
import hashlib
import json
import os
import shutil
import sys
import tempfile
import time
import urllib.parse
from pathlib import Path

ap = argparse.ArgumentParser()
ap.add_argument("repo", nargs="?", default=str(Path(__file__).resolve().parents[1]))
ap.add_argument("--scratch", default=None)
args = ap.parse_args()
scratch = Path(args.scratch or tempfile.mkdtemp(prefix="google-login-"))
shutil.rmtree(scratch, ignore_errors=True)
(scratch / "data").mkdir(parents=True)
(scratch / "auth").mkdir(parents=True)
os.environ.update({
    "DATA_DIR": str(scratch / "data"), "AUTH_DIR": str(scratch / "auth"), "TRIAGE_ENABLED": "0",
    "GOOGLE_CLIENT_ID": "cid-123.apps.googleusercontent.com", "GOOGLE_CLIENT_SECRET": "shh",
    "GOOGLE_ALLOWED_DOMAINS": "Corp.test, @lab.test", "PUBLIC_URL": "https://forensic.corp.test/",
})
sys.path.insert(0, args.repo)

from fastapi.testclient import TestClient  # noqa: E402

from app import config  # noqa: E402
from app.main import app  # noqa: E402
from app.services.access import auth, google_login  # noqa: E402
from app.services.store import hashchain  # noqa: E402

CID = os.environ["GOOGLE_CLIENT_ID"]
PW = "correct horse battery"
failures = 0


def check(name: str, ok: bool) -> None:
    global failures
    print(("  ok   " if ok else "  FAIL ") + name)
    failures += 0 if ok else 1


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


# The stand-in for Google: whatever claims the test sets, as an unsigned JWT,
# after checking what the server sent it.
google = {"claims": {}, "raise": None, "seen": None}


def fake_exchange(code, verifier):
    google["seen"] = (code, verifier)
    if google["raise"]:
        raise google_login.Refused(google["raise"])
    head = b64(json.dumps({"alg": "RS256"}).encode())
    return {"id_token": f"{head}.{b64(json.dumps(google['claims']).encode())}.sig"}


google_login._exchange = fake_exchange


def claims(nonce, **over):
    now = int(time.time())
    c = {"iss": "https://accounts.google.com", "aud": CID, "azp": CID, "sub": "1001",
         "email": "Ann@Corp.test", "email_verified": True, "hd": "corp.test", "name": "Ann",
         "iat": now, "exp": now + 3600, "nonce": nonce}
    c.update(over)
    return {k: v for k, v in c.items() if v is not None}


def client():
    return TestClient(app, base_url="https://forensic.corp.test", follow_redirects=False)


def start(c):
    r = c.get("/api/auth/google/start")
    q = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(r.headers["location"]).query))
    pending = c.cookies.get(google_login.PENDING_COOKIE)
    data = json.loads(unb64(pending.rsplit(".", 1)[0]))
    return r, q, data


def sign_in(c=None, state=None, **over):
    """One whole round trip; returns (client, callback response)."""
    c = c or client()
    _, q, data = start(c)
    google["claims"] = claims(data["n"], **over)
    r = c.get("/api/auth/google/callback", params={"state": state or q["state"], "code": "4/abc"})
    return c, r


def reason(r):
    loc = r.headers.get("location", "")
    return dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(loc).query)).get("signin", "ok" if "dashboard" in loc else loc)


def login_lines():
    path = auth.audit_path()
    return hashchain.entries(path) if path.exists() else []


print("configuration")
check("domains read lower case, '@' and spaces dropped", config.GOOGLE_ALLOWED_DOMAINS == ("corp.test", "lab.test"))
check("PUBLIC_URL without its trailing slash", google_login.redirect_uri() == "https://forensic.corp.test/api/auth/google/callback")
c = client()
check("/api/auth/config says Google is on", c.get("/api/auth/config").json().get("google") is True)
check("start and callback need no session", c.get("/api/auth/google/start").status_code == 303
      and c.get("/api/auth/google/callback").status_code == 303)

print("start (OIDC Core 3.1.2.1, RFC 7636 4.1-4.3)")
c = client()
r, q, data = start(c)
check("303 to Google's authorization endpoint", r.status_code == 303
      and r.headers["location"].startswith("https://accounts.google.com/o/oauth2/v2/auth?"))
check("code flow, openid scope, our client and redirect URI",
      q.get("response_type") == "code" and "openid" in q.get("scope", "").split()
      and q.get("client_id") == CID and q.get("redirect_uri") == google_login.redirect_uri())
check("state and nonce sent are the ones kept", q["state"] == data["s"] and q["nonce"] == data["n"])
check("S256 challenge of a 43-128 character verifier",
      q.get("code_challenge_method") == "S256" and 43 <= len(data["v"]) <= 128
      and q.get("code_challenge") == b64(hashlib.sha256(data["v"].encode()).digest()))
check("two domains: hd=* (a hint only), account chooser", q.get("hd") == "*" and q.get("prompt") == "select_account")
sc = r.headers.get("set-cookie", "").lower()
check("pending cookie HttpOnly, Secure, SameSite=Lax, only for /api/auth/google, 10 min",
      all(x in sc for x in ("httponly", "secure", "samesite=lax", "path=/api/auth/google", "max-age=600")))
check("a second start gives a new state and verifier", start(client())[2]["s"] != data["s"])

print("first sign-in: an account made as an analyst")
c, r = sign_in()
check("303 to the Overview", r.status_code == 303 and r.headers["location"] == "/#/dashboard")
check("the code and our verifier reached the token endpoint", google["seen"][0] == "4/abc" and len(google["seen"][1]) >= 43)
me = c.get("/api/auth/me")
check("signed in, email lower-cased, analyst", me.status_code == 200 and me.json()["email"] == "ann@corp.test"
      and me.json()["role"] == "analyst")
ann = auth.load_users()["ann@corp.test"]
check("no usable password, bound to sub, made by google-sign-in",
      not auth.has_password(ann) and ann.get("google_sub") == "1001" and ann.get("created_by") == auth.GOOGLE_ACTOR)
check("no password signs in to it", client().post("/api/auth/login", json={"email": "ann@corp.test", "password": "!"}).status_code == 401
      and client().post("/api/auth/login", json={"email": "ann@corp.test", "password": ann["password"]}).status_code == 401)
acct = hashchain.entries(auth.accounts_audit_path())
check("account_created in the account log, method google",
      acct[-1]["event"] == "account_created" and acct[-1]["actor"] == auth.GOOGLE_ACTOR and acct[-1].get("method") == "google")
google_lines = [e for e in login_lines() if e.get("method") == "google"]
check("login_ok in the sign-in log, method google",
      google_lines[-1]["event"] == "login_ok" and google_lines[-1]["account"] == "ann@corp.test")
check("pending cookie cleared after the callback", google_login.PENDING_COOKIE not in c.cookies)
check("second sign-in, same sub: in, no new account line",
      reason(sign_in()[1]) == "ok" and len(hashchain.entries(auth.accounts_audit_path())) == len(acct))
check("a session cookie is Secure", "secure" in r.headers.get("set-cookie", "").lower())

print("the same address, another Google account (Google: email is not a unique id)")
c, r = sign_in(sub="2002")
check("refused google_mismatch, no session", reason(r) == "google_mismatch" and c.get("/api/auth/me").status_code == 401)
check("audited against the account", login_lines()[-1]["event"] == "login_failed"
      and login_lines()[-1]["account"] == "ann@corp.test" and login_lines()[-1]["reason"] == "google_mismatch")

print("an account an administrator made keeps its role and its password")
auth.create_account("root", "boss@lab.test", "Boss", "manager", PW)
c, r = sign_in(email="boss@lab.test", hd="lab.test", sub="3003")
check("in, still a manager", reason(r) == "ok" and c.get("/api/auth/me").json()["role"] == "manager")
check("bound now, and an account_changed line", auth.load_users()["boss@lab.test"].get("google_sub") == "3003"
      and hashchain.entries(auth.accounts_audit_path())[-1]["event"] == "account_changed")
check("its password still signs in", client().post("/api/auth/login", json={"email": "boss@lab.test", "password": PW}).status_code == 200)

print("who is kept out (Google: check the hd claim, not the parameter)")
check("personal Google account (no hd)", reason(sign_in(email="eve@gmail.com", hd=None, sub="9")[1]) == "domain")
check("another Workspace", reason(sign_in(email="eve@other.test", hd="other.test", sub="9")[1]) == "domain")
check("an allowed-looking address in another Workspace", reason(sign_in(email="eve@corp.test", hd="evil.test", sub="9")[1]) == "domain")
check("nobody was made for them", not ({"eve@gmail.com", "eve@other.test", "eve@corp.test"} & set(auth.load_users())))
line = login_lines()[-1]
check("an address with no account is audited as a keyed digest", line["account"] is None
      and "attempted_hmac" in line and "@" not in json.dumps(line))
check("email not verified", reason(sign_in(email="new@corp.test", sub="8", email_verified=False)[1]) == "unverified")
check("email_verified as the string 'true' accepted", reason(sign_in(email="str@corp.test", sub="7", email_verified="true")[1]) == "ok")
auth.update_account("root", "ann@corp.test", disabled=True)
c, r = sign_in()
check("a disabled account", reason(r) == "disabled" and c.get("/api/auth/me").status_code == 401)
auth.update_account("root", "ann@corp.test", disabled=False)

print("ID token checks (OIDC Core 3.1.3.7)")
for label, over in [("another issuer", {"iss": "https://evil.test"}),
                    ("another audience", {"aud": "someone-else"}),
                    ("an extra audience", {"aud": [CID, "someone-else"]}),
                    ("azp of another client", {"azp": "someone-else"}),
                    ("expired", {"exp": int(time.time()) - 3600}),
                    ("issued in the future", {"iat": int(time.time()) + 3600}),
                    ("no exp", {"exp": None}),
                    ("no sub", {"sub": None}),
                    ("no email", {"email": None})]:
    check(f"{label}: bad_token", reason(sign_in(**over)[1]) == "bad_token")
check("issuer without the scheme is Google's too", reason(sign_in(iss="accounts.google.com")[1]) == "ok")
check("audience as a one-element list", reason(sign_in(aud=[CID])[1]) == "ok")
c = client()
_, q, data = start(c)
google["claims"] = claims("not-the-nonce")
check("another nonce: bad_token", reason(c.get("/api/auth/google/callback", params={"state": q["state"], "code": "x"})) == "bad_token")
google["claims"] = {}
c = client()
_, q, _ = start(c)
google_login._exchange = lambda code, v: {"id_token": "not-a-jwt"}
check("not a JWT: bad_token", reason(c.get("/api/auth/google/callback", params={"state": q["state"], "code": "x"})) == "bad_token")
google_login._exchange = fake_exchange

print("state and the pending cookie (RFC 6749 10.12)")
check("another state", reason(sign_in(state="forged")[1]) == "expired")
check("a non-ASCII state is refused, not a 500", reason(sign_in(state="été")[1]) == "expired")
try:
    google_login._pending("x.é")  # a header client libraries will not send, so asked directly
    check("a non-ASCII pending cookie is refused, not a 500", False)
except google_login.Refused as exc:
    check("a non-ASCII pending cookie is refused, not a 500", exc.reason == "expired")
r = client().get("/api/auth/google/callback", params={"state": "x", "code": "4/abc"})
check("no pending cookie (another browser)", reason(r) == "expired")
c = client()
_, q, _ = start(c)
raw = c.cookies.get(google_login.PENDING_COOKIE)
payload, sig = raw.rsplit(".", 1)
c.cookies.set(google_login.PENDING_COOKIE, payload + "." + sig[:-2] + "AA", domain="forensic.corp.test", path="/api/auth/google")
check("a pending cookie with a bad signature", reason(c.get("/api/auth/google/callback", params={"state": q["state"], "code": "x"})) == "expired")
old = json.loads(unb64(payload))
old["exp"] = int(time.time()) - 1
p2 = b64(json.dumps(old).encode())
c = client()
c.cookies.set(google_login.PENDING_COOKIE, f"{p2}.{google_login._sign(p2)}", domain="forensic.corp.test", path="/api/auth/google")
check("a pending cookie past its 10 minutes", reason(c.get("/api/auth/google/callback", params={"state": old["s"], "code": "x"})) == "expired")
try:
    google_login._pending(auth.issue_token(auth.load_users()["boss@lab.test"]))
    check("a session token is refused as a pending cookie", False)
except google_login.Refused as exc:
    check("a session token is refused as a pending cookie", exc.reason == "expired")

print("Google's answers")
c = client()
_, q, _ = start(c)
check("the user pressed Cancel", reason(c.get("/api/auth/google/callback", params={"state": q["state"], "error": "access_denied"})) == "cancelled")
google["raise"] = "unreachable"
check("Google not reachable", reason(sign_in()[1]) == "unreachable")
google["raise"] = None
check("a reason the page does not know is 'failed'", google_login.Refused("<script>").reason == "failed")
check("callback redirects stay on this site", not sign_in()[1].headers["location"].startswith("http")
      and not sign_in(state="forged")[1].headers["location"].startswith("http"))

print("removing and disabling")
auth.remove_account("root", "str@corp.test")
check("removed, then signs in again: a new account (disable to keep someone out)",
      reason(sign_in(email="str@corp.test", sub="7")[1]) == "ok" and "str@corp.test" in auth.load_users())
c, r = sign_in(email="str@corp.test", sub="7")
auth.update_account("root", "str@corp.test", disabled=True)
check("disabling ends a Google session at once", c.get("/api/auth/me").status_code == 401)

print("the Users page")
auth.create_account("root", "admin@x.test", "Admin", "admin", PW)
c = client()
c.post("/api/auth/login", json={"email": "admin@x.test", "password": PW})
u = c.get("/api/users").json()
rows = {x["email"]: x for x in u["users"]}
check("says how each account signs in", rows["ann@corp.test"]["google"] and not rows["ann@corp.test"]["has_password"]
      and rows["boss@lab.test"]["google"] and rows["boss@lab.test"]["has_password"]
      and not rows["admin@x.test"]["google"])
check("never Google's sub", "google_sub" not in json.dumps(u) and "1001" not in json.dumps(u))
check("lists the domains", u.get("google_domains") == ["corp.test", "lab.test"])
check("a password set for a Google account works beside Google",
      c.post("/api/users/ann@corp.test/password", json={"password": PW}).status_code == 200
      and client().post("/api/auth/login", json={"email": "ann@corp.test", "password": PW}).status_code == 200)

print("off")
saved = config.GOOGLE_ALLOWED_DOMAINS
config.GOOGLE_ALLOWED_DOMAINS = ()
c = client()
check("no domains: off - the page shows no button", c.get("/api/auth/config").json()["google"] is False)
r = c.get("/api/auth/google/start")
check("start refuses with 'off', sends nobody to Google", reason(r) == "off" and "accounts.google.com" not in r.headers["location"])
config.GOOGLE_ALLOWED_DOMAINS = saved

print("audit chains")
check("login.jsonl and accounts.jsonl chains verify",
      hashchain.verify(auth.audit_path())["intact"] and hashchain.verify(auth.accounts_audit_path())["intact"])

print(f"\n{'ALL OK' if not failures else f'{failures} FAILED'}")
shutil.rmtree(scratch, ignore_errors=True)
sys.exit(1 if failures else 0)
