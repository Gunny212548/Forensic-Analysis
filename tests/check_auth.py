"""Sign-in hardening: throttle, audit log, input limits, session invalidation, headers.

    python tests/check_auth.py <scratch dir> [--repo DIR]

Builds a throwaway store in <scratch dir> with throwaway accounts and drives
the real app through fastapi's TestClient (specs/login_hardening_design.md,
acceptance criteria 1-7 and 9's sign-in half; the Login page is by hand).
The window is shortened to 3 seconds so "after the window it works again" is
tested rather than assumed. stdlib + the app's own dependencies; no network.
"""

import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
ALICE, BOB = "alice@test.local", "bob@test.local"
PW_A, PW_B = "alice-throwaway-password", "bob-throwaway-password"
FAILED: list[str] = []


def check(ok: bool, what: str) -> None:
    print(f"  {'ok  ' if ok else 'FAIL'} {what}")
    if not ok:
        FAILED.append(what)


def add_user(repo: Path, email: str, password: str) -> None:
    subprocess.run([sys.executable, str(repo / "tools" / "create_user.py"), "add", email,
                    "--name", email, "--role", "analyst", "--password-stdin"],
                   input=password + "\n", text=True, capture_output=True, check=True)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("scratch")
    ap.add_argument("--repo", default=str(REPO))
    args = ap.parse_args()
    scratch, repo = Path(args.scratch), Path(args.repo)
    store = scratch / "store"
    store.mkdir(parents=True, exist_ok=True)
    os.environ["DATA_DIR"] = str(store)
    os.environ["LOGIN_WINDOW_SECONDS"] = "3"
    add_user(repo, ALICE, PW_A)
    add_user(repo, BOB, PW_B)
    sys.path.insert(0, str(repo))
    from fastapi.testclient import TestClient

    from app import config
    from app.main import app
    from app.services import auth, hashchain

    def login(c, email, password):
        return c.post("/api/auth/login", json={"email": email, "password": password})

    with TestClient(app) as c:
        print("throttle")
        auth.throttle.reset()
        for i in range(5):
            r = login(c, ALICE, "wrong-password")
            check(r.status_code == 401, f"wrong password {i + 1} -> 401")
        t0 = time.perf_counter()
        r = login(c, ALICE, "wrong-password")
        fast = time.perf_counter() - t0
        check(r.status_code == 429 and int(r.headers.get("Retry-After", 0)) >= 1,
              "6th attempt -> 429 with Retry-After")
        check("minute" in r.json().get("detail", ""), "429 says how long to wait")
        check(fast < 0.03, f"429 did not run scrypt ({fast * 1000:.1f} ms)")
        check(login(c, ALICE, PW_A).status_code == 429, "the correct password is refused while locked")
        check(login(c, BOB, PW_B).status_code == 200, "another account is unaffected")
        c.cookies.clear()

        print("unknown accounts count like known ones")
        auth.throttle.reset()
        codes = [login(c, "nobody@test.local", "x").status_code for _ in range(6)]
        check(codes == [401] * 5 + [429], f"unknown account: 5 x 401 then 429 ({codes})")

        print("the window passes")
        auth.throttle.reset()
        for _ in range(5):
            login(c, ALICE, "wrong-password")
        check(login(c, ALICE, PW_A).status_code == 429, "locked")
        time.sleep(config.LOGIN_WINDOW_SECONDS + 1)
        check(login(c, ALICE, PW_A).status_code == 200, "after the window the correct password signs in")
        c.cookies.clear()

        print("a success forgives earlier slips")
        auth.throttle.reset()
        for _ in range(4):
            login(c, ALICE, "wrong-password")
        check(login(c, ALICE, PW_A).status_code == 200, "4 failures then success")
        c.cookies.clear()
        codes = [login(c, ALICE, "wrong-password").status_code for _ in range(5)]
        check(codes == [401] * 5, "the count started again after the success")

        print("the overall ceiling")
        auth.throttle.reset()
        config.LOGIN_GLOBAL_MAX_FAILURES = 6
        codes = [login(c, f"user{i}@test.local", "x").status_code for i in range(7)]
        check(codes == [401] * 6 + [429], f"6 failures across accounts, then everyone waits ({codes})")
        check(login(c, BOB, PW_B).status_code == 429, "even a correct password waits")
        config.LOGIN_GLOBAL_MAX_FAILURES = 60
        auth.throttle.reset()

        print("input that is not two sane strings")
        auth.throttle.reset()
        c.cookies.clear()
        for what, body in {"email is a number": {"email": 1, "password": PW_A},
                           "password is a list": {"email": ALICE, "password": []},
                           "1 MB password": {"email": ALICE, "password": "x" * 1_000_000},
                           "email too long": {"email": "a" * 300 + "@x", "password": "x"}}.items():
            t0 = time.perf_counter()
            r = c.post("/api/auth/login", json=body)
            check(r.status_code == 401 and time.perf_counter() - t0 < 0.5, f"{what} -> 401, not 500")
        auth.throttle.reset()

        print("sessions")
        c.cookies.clear()
        check(login(c, ALICE, PW_A).status_code == 200 and c.get("/api/auth/me").status_code == 200,
              "signed in, /me works")
        old_cookie = c.cookies.get(auth.COOKIE_NAME)
        add_user(repo, ALICE, "alice-a-new-password")  # an administrator resets the password
        c.cookies.clear()
        c.cookies.set(auth.COOKIE_NAME, old_cookie)
        check(c.get("/api/auth/me").status_code == 401, "a cookie from before the reset is refused")
        check(login(c, ALICE, "alice-a-new-password").status_code == 200, "the new password works")
        check(c.get("/api/auth/me").status_code == 200, "and its cookie works")
        c.cookies.clear()
        c.cookies.set(auth.COOKIE_NAME, old_cookie.rsplit(".", 1)[0] + ".AAAA")
        check(c.get("/api/auth/me").status_code == 401, "a forged signature is refused")
        c.cookies.clear()
        legacy = auth._b64(json.dumps({"email": ALICE, "exp": int(time.time()) + 3600}).encode())
        sig = auth._b64(__import__("hmac").new(auth._secret(), legacy.encode(), "sha256").digest())
        c.cookies.set(auth.COOKIE_NAME, f"{legacy}.{sig}")
        check(c.get("/api/auth/me").status_code == 401, "a validly signed cookie without the password version is refused")
        c.cookies.clear()

        print("headers")
        for path in ("/", "/api/health", "/api/auth/me"):
            h = c.get(path).headers
            check(h.get("x-frame-options") == "DENY" and h.get("x-content-type-options") == "nosniff"
                  and "frame-ancestors 'none'" in h.get("content-security-policy", ""),
                  f"{path} carries the security headers (even the 401)")

        print("audit log")
        log = auth.audit_path()
        lines = hashchain.entries(log)
        events = [e["event"] for e in lines]
        check({"login_ok", "login_failed", "login_throttled"} <= set(events), f"events recorded: {sorted(set(events))}")
        check(hashchain.verify(log)["intact"], "the chain verifies")
        text = log.read_text(encoding="utf-8")
        check(PW_A not in text and "alice-a-new-password" not in text and "wrong-password" not in text,
              "no password appears in it")
        unknown = [e for e in lines if e["event"] == "login_failed" and e["account"] is None]
        check(unknown and all(len(e.get("attempted_hmac", "")) == 12 for e in unknown)
              and "nobody@test.local" not in text, "an address with no account is a digest, not as typed")
        bare = hashlib.sha256(b"nobody@test.local").hexdigest()[:12]
        check(bare not in text, "the digest is keyed, not a bare SHA-256 a dictionary could reverse")
        check(sum(e["event"] == "login_throttled" for e in lines) <= 6,
              "a limit engaging is recorded once, not once per refused request")
        c.post("/api/auth/login", json={"email": BOB, "password": PW_B})
        n = len(hashchain.entries(log))
        c.post("/api/auth/logout")
        after = hashchain.entries(log)
        check(len(after) == n + 1 and after[-1]["event"] == "logout" and after[-1]["account"] == BOB,
              "logout is recorded with its account")
        raw = log.read_text(encoding="utf-8").splitlines()
        raw[0] = raw[0].replace("login_", "logon_", 1)
        log.write_text("\n".join(raw) + "\n", encoding="utf-8")
        check(not hashchain.verify(log)["intact"], "an edited line is detected")

    print(f"\n{'FAILED: ' + str(len(FAILED)) if FAILED else 'all checks passed'}")
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
