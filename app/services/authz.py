"""The one place that answers "may this account do this to this customer's data".

Roles and what each may do (IAI-14, specs/IAI-14_rbac.md, approved Q56-Q60), from
NIST SP 800-53 Rev. 5 AC-3 (enforced in the server), AC-5 (separation of duties)
and AC-6 (least privilege):

- **analyst** works cases: uploads evidence into existing customers, records
  provenance, reviews findings, works the findings assigned to them up to
  Contained, runs the AI analysis.
- **manager** does all of that, and decides: creates customers and projects,
  sets the investigation's question, merges cases, assigns anyone, and is
  the only role that closes (resolves) or reopens a finding (Q57).
- **admin** manages accounts and may read everything, but takes no case action
  (Q56): whoever administers accounts and also investigates uses a second,
  manager account (AC-6(2)).

Deny by default: an account with any other role may do nothing, not even read.
Every customer is open to every role for now (Q58); `company_id` is passed so
a per-customer rule can be added here without touching the routes (ADR-003).
"""

ADMIN, MANAGER, ANALYST = "admin", "manager", "analyst"
ROLES = (ADMIN, MANAGER, ANALYST)

# Actions a route may ask about.
READ = "data:read"
UPLOAD = "case:upload"
CUSTOMERS = "customer:manage"      # create a customer or a project
QUESTION = "investigation:question"
PROVENANCE = "evidence:provenance"
VERIFY = "evidence:verify"
REPROCESS = "case:reprocess"
MERGE = "case:merge"
ANALYZE = "case:analyze"
REVIEW = "finding:review"
ASSIGN = "finding:assign"          # to anyone; an analyst may take an unassigned finding
WORK = "finding:work"              # investigate / contain any finding; an analyst, their own
CLOSE = "finding:close"            # resolve
REOPEN = "finding:reopen"
ACCOUNTS = "account:manage"
# The lifecycle route asks for one of the finding actions; kept for callers
# that ask about "the lifecycle" as a whole.
LIFECYCLE = "finding:lifecycle"

_CASE_WORK = {READ, UPLOAD, PROVENANCE, VERIFY, REPROCESS, ANALYZE, REVIEW, LIFECYCLE}
PERMISSIONS = {
    ANALYST: frozenset(_CASE_WORK),
    MANAGER: frozenset(_CASE_WORK | {CUSTOMERS, QUESTION, MERGE, ASSIGN, WORK, CLOSE, REOPEN}),
    ADMIN: frozenset({READ, ACCOUNTS}),
}
# What a role that lacks an action is told it needs - the page shows it beside
# the disabled control.
NEEDS = {a: [r for r in ROLES if a in PERMISSIONS[r]] for p in PERMISSIONS.values() for a in p}


class Forbidden(Exception):
    """The account may not do this. Routes answer 403."""


def role(user: dict | None) -> str | None:
    r = (user or {}).get("role")
    return r if r in ROLES else None


def can(user: dict | None, action: str, company_id: str | None = None) -> bool:
    return action in PERMISSIONS.get(role(user), frozenset())


def permissions(user: dict | None) -> list[str]:
    return sorted(PERMISSIONS.get(role(user), frozenset()))


def require(user: dict | None, action: str, company_id: str | None = None) -> None:
    if not can(user, action, company_id):
        needs = " or ".join(NEEDS.get(action, [])) or "no role"
        raise Forbidden(f"{(user or {}).get('email', 'anonymous')} ({role(user) or 'no role'}) "
                        f"may not {action} - it needs {needs}")


def require_lifecycle(user: dict | None, action: str, current: dict | None, body: dict,
                      company_id: str | None = None) -> None:
    """One lifecycle change (lifecycle.py). A manager may do any; an analyst
    may take an unassigned finding for themself and investigate / contain the
    findings assigned to them; resolving and reopening are a manager's (Q57)."""
    require(user, LIFECYCLE, company_id)
    if role(user) == MANAGER:
        return
    me = (user or {}).get("email")
    assignee = (current or {}).get("assignee")
    wanted = (body.get("assignee") or "").strip().lower() or None
    if action == "assign":
        if wanted == me and assignee in (None, me):
            return
        require(user, ASSIGN, company_id)
    elif action in ("investigate", "contain"):
        if (wanted or assignee) == me and assignee in (None, me):
            return
        require(user, WORK, company_id)
    elif action == "resolve":
        require(user, CLOSE, company_id)
    elif action == "reopen":
        require(user, REOPEN, company_id)
