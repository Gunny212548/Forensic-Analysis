# ADR-003: One authorisation seam, allowing everything for now

Status: Accepted (2026-10-19) · Code: `app/services/authz.py` · Tests: `tests/check_authz.py`

## Context

Roles are undefined until IAI-14 (RBAC), which the user deferred; `role` on an account is a
display label and any signed-in account can read and write every customer. When RBAC comes,
each writing route would otherwise need a new check, found by reading every router.

## Decision

- `authz.can(user, action, company_id=None) -> bool` returns True. `authz.require()` raises
  `Forbidden`; a route turns that into 403 through `cases._authorize`.
- The routes that change evidence or decisions already ask: review, lifecycle, evidence
  verify (each with the case's customer) and merge.
- Actions are plain strings (`authz.REVIEW` ...). IAI-14 decides the vocabulary, so an
  unknown action does not raise.

## Consequences

- IAI-14 edits `can()` and adds actions; no router needs a new check for these four.
- **No behaviour changes today**: nothing is permitted or denied by it.
- **Not covered**: read routes, upload, analyze, and a merge's customer (the service decides
  it from the sources, so the route asks with no customer). They are added when `can()` has
  rules; a seam wired everywhere with no policy would be churn.
