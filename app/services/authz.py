"""The one place that answers "may this account do this to this customer's data".

A seam, not a policy (ADR-003): `can()` allows everything today, because roles
are undefined until IAI-14 (RBAC), which the user deferred. What the seam buys
is that every route that writes already asks, so IAI-14 changes this file and
adds no checks to the routers. `role` on an account is still a display label.
"""

# Actions a route may ask about. Strings, not an enum: IAI-14 decides the
# vocabulary, and an unknown action must not raise in a seam that allows all.
REVIEW = "finding:review"
LIFECYCLE = "finding:lifecycle"
VERIFY = "evidence:verify"
MERGE = "case:merge"


class Forbidden(Exception):
    """The account may not do this. Routes answer 403."""


def can(user: dict | None, action: str, company_id: str | None = None) -> bool:
    return True


def require(user: dict | None, action: str, company_id: str | None = None) -> None:
    if not can(user, action, company_id):
        raise Forbidden(f"{(user or {}).get('email', 'anonymous')} may not {action}")
