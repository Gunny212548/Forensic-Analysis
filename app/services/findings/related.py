"""Related findings: which findings belong to the same attack chain (FR-4.2a).

The finding is the only unit (CLAUDE.md, *Decisions*); nothing is merged into
an incident. A finding just lists the others it is chained to, over the whole
case - no time windows.

Chains are linked **only through pivots**: a host that is the target of one
finding and the source of another (the attacker got in, then used the machine
to go further). Two findings that merely share a final target are not related -
attack graphs here are many sources converging on one target, and linking
through any shared target would relate every scanner that hit the same public
address (gotcha #24).

The exception is an attack on one account. A password spray (R2005) and a burst
of successful logins (R2006) against an account come from many sources and
share no pivot host, so they are related by the account. Accounts never form
pivots: a username is never a source address.
"""

ACCOUNT_RULES = ("R2005", "R2006")

# A finding lists at most this many neighbours; related_count says how many
# there really are (a spray of 14 sources is 27 neighbours each).
LIST_CAP = 12


def finding_key(rid: str, srcip: str | None, username: str | None) -> str:
    return f"{rid}|{srcip or ''}|{username or ''}"


class _Sets:
    def __init__(self) -> None:
        self.parent: dict = {}

    def find(self, x):
        self.parent.setdefault(x, x)
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a, b) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[max(ra, rb)] = min(ra, rb)


def chains(rows: list[dict]) -> dict[str, dict]:
    """rows: one per collapsed finding - rid, srcip, username, dstips (list),
    and optionally lvl/level. Returns {finding_key: {"chain": id, "related":
    [...], "related_count": n}} for findings that have at least one relation."""
    findings = {}
    for r in rows:
        key = finding_key(r["rid"], r.get("srcip"), r.get("username"))
        findings[key] = r

    sources = {r.get("srcip") for r in findings.values() if r.get("srcip")}
    targets = {d for r in findings.values() for d in (r.get("dstips") or []) if d}
    pivots = sources & targets

    sets = _Sets()
    for key, r in findings.items():
        sets.find(("f", key))
        hosts = {r.get("srcip"), *(r.get("dstips") or [])}
        for h in hosts:
            if h and h in pivots:
                sets.union(("f", key), ("h", h))
        if r["rid"] in ACCOUNT_RULES and r.get("username"):
            sets.union(("f", key), ("a", r["username"]))

    groups: dict = {}
    for key in findings:
        groups.setdefault(sets.find(("f", key)), []).append(key)

    out: dict[str, dict] = {}
    for members in groups.values():
        if len(members) < 2:
            continue
        members.sort()
        chain_id = members[0]
        for key in members:
            others = [m for m in members if m != key]
            # Most severe neighbours first, so the cap keeps the ones that matter.
            others.sort(key=lambda m: (-(findings[m].get("lvl") or 0), m))
            out[key] = {
                "chain": chain_id,
                "related_count": len(others),
                "related": [
                    {"key": m, "rid": findings[m]["rid"], "srcip": findings[m].get("srcip"),
                     "username": findings[m].get("username"), "level": findings[m].get("level")}
                    for m in others[:LIST_CAP]
                ],
            }
    return out
