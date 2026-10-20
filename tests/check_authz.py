"""The authz seam (ADR-003): allows everything today, and a denial becomes a 403.

    python tests/check_authz.py [repo dir]

stdlib + the app's imports; no store needed.
"""
import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, sys.argv[1] if len(sys.argv) > 1 else str(Path(__file__).resolve().parents[1]))

from fastapi import HTTPException  # noqa: E402

from app.routers import cases  # noqa: E402
from app.services import authz  # noqa: E402

failures = 0


def check(name: str, ok: bool) -> None:
    global failures
    print(("  ok   " if ok else "  FAIL ") + name)
    failures += 0 if ok else 1


user = {"email": "a@example.com", "role": "viewer"}
req = SimpleNamespace(state=SimpleNamespace(user=user))

check("allows every action today", all(
    authz.can(user, a, "co-1") for a in (authz.REVIEW, authz.LIFECYCLE, authz.VERIFY, authz.MERGE)))
check("allows an unknown action rather than raising", authz.can(user, "nope") is True)
check("allows with no customer", authz.can(user, authz.MERGE) is True)
check("require is silent when allowed", authz.require(user, authz.REVIEW, "co-1") is None)
check("the route helper is silent when allowed", cases._authorize(req, authz.REVIEW, "co-1") is None)

real = authz.can
authz.can = lambda u, action, company_id=None: False
try:
    try:
        authz.require(user, authz.REVIEW, "co-1")
        check("require raises Forbidden on a denial", False)
    except authz.Forbidden as exc:
        check("require raises Forbidden on a denial", "a@example.com" in str(exc) and authz.REVIEW in str(exc))
    try:
        cases._authorize(req, authz.LIFECYCLE, "co-1")
        check("a denial is a 403 at the route", False)
    except HTTPException as exc:
        check("a denial is a 403 at the route", exc.status_code == 403)
finally:
    authz.can = real

print("\nAUTHZ OK" if not failures else f"\n{failures} FAILED")
sys.exit(1 if failures else 0)
