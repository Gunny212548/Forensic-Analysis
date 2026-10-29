"""SigmaHQ's Windows rules on a case's win_events (specs/sigma_windows.md).

The rules arrive converted: the image's `sigma` build stage runs tools/sigma_build.py on a
pinned SigmaHQ commit and leaves one JSON at SIGMA_RULES (S-D3). Nothing here imports
pySigma. High / critical rules of `rules` and `rules-emerging-threats` become findings
through rules_sigma.py and rules.apply_rules, like every product rule (S-D4); every other
runnable rule, and an in-house rule's twin (S-D7), only marks the events it matches
(`sigma_marks`). Every match names its rule's author (DRL 1.1).
"""
import functools
import hashlib
import json
import os
from pathlib import Path

RULES_PATH = Path(os.environ.get("SIGMA_RULES", "/opt/sigma/windows_rules.json"))
SUGGEST_LEVELS = ("high", "critical")
SUGGEST_FOLDERS = ("rules", "rules-emerging-threats")
# S-D7 (Q130): SigmaHQ rules on the events an in-house rule already decides - marks only. A twin
# selects only event ids of the provider that rule reads, and decides nothing more about them.
TWINS = {
    "57b649ef-ff42-4fb0-8bf6-62da243a1708": "WIN-MAL-2",   # Windows Defender Threat Detected (1006/1015/1116/1117)
    "ea9bf0fa-edec-4fb8-8b78-b119f2528186": "WIN-MAL-2",   # Windows Defender AMSI Trigger Detected (1116, AMSI)
    "b28e58e4-2a72-4fae-bdee-0fbe904db642": "WIN-HOST-3",  # Windows Defender Real-time Protection Disabled (5001)
    "bc275be9-0bec-4d77-8c8f-281a2df6710f": "WIN-HOST-3",  # Windows Defender Malware And PUA Scanning Disabled (5010)
    "686c0b4b-9dd3-4847-9077-d6c1bbe36fcb": "WIN-HOST-3",  # Windows Defender Virus Scanning Feature Disabled (5012)
    "49e5bc24-8b86-49f1-b743-535f332c2856": "WIN-HOST-3",  # Microsoft Defender Tamper Protection Trigger (5013)
}
# win_events' own columns under the names Sigma rules use; any other field is an item of data.
COLUMNS = {"EventID": "CAST(w.event_id AS VARCHAR)", "Channel": "w.channel",
           "Provider_Name": "w.provider", "Computer": "w.computer"}
HOST = "upper(split_part(w.computer, '.', 1))"
# The account the event is about (S-D5): Sysmon's User, else the Security subject - the
# name without its domain, lower case (as rules_windows._account).
ACCOUNT = ("nullif(lower(regexp_replace(split_part(coalesce(w.data['User'], w.data['SubjectUserName'], "
           "w.data['TargetUserName'], ''), '@', 1), '^.*\\\\', '')), '-')")


@functools.lru_cache(maxsize=1)
def bundle() -> dict:
    """The converted rule set and its provenance; empty when the image has none."""
    if not RULES_PATH.is_file():
        return {"provenance": None, "rules": [], "sha256": None}
    raw = RULES_PATH.read_bytes()
    body = json.loads(raw)
    body["sha256"] = hashlib.sha256(raw).hexdigest()
    return body


def runnable(r: dict) -> bool:
    return bool(r.get("conditions")) and not r.get("not_readable") and not r.get("error")


def suggests(r: dict) -> bool:
    return (runnable(r) and r["level"] in SUGGEST_LEVELS and r["folder"] in SUGGEST_FOLDERS
            and r["id"] not in TWINS)


def _lit(s: str | None) -> str:
    return "'" + (s or "").replace("'", "''") + "'"


def _column(field: str) -> str:
    return COLUMNS.get(field, f"w.data[{_lit(field)}]")


def logs_cte(r: dict) -> str:
    """`logs`: the rule's logsource rows of win_events, its fields under its own names, and the
    event's host and account under names no Sigma field has. Nothing else is in scope where the
    rule's condition runs: a field called "Data" would otherwise be win_events' `data` column."""
    cols = "".join(f', {_column(f)} AS "{f.replace(chr(34), chr(34) * 2)}"' for f in r.get("fields") or [])
    return (f"logs AS (SELECT w.row_id, {HOST} AS \"__fa_host\", {ACCOUNT} AS \"__fa_account\"{cols} "
            f"FROM win_events w WHERE {r['where']})")


def condition(r: dict) -> str:
    return " OR ".join(f"({c})" for c in r["conditions"])


def author(r: dict) -> str:
    return r.get("author") or "unknown author"


def finding_sql(r: dict) -> str:
    """The INSERT a suggesting rule runs (rules_sigma.RULES): one row per matched event, the
    host and account it names (S-D5), the rule's techniques, its author (DRL 1.1)."""
    techs = "[" + ", ".join(_lit(t) for t in r["techniques"]) + "]" if r["techniques"] else "[]::VARCHAR[]"
    head = _lit(f"{r['title']} (SigmaHQ, by {author(r)}) on ")
    return f"""
        INSERT INTO findings
        WITH {logs_cte(r)}
        SELECT row_id, {_lit(r['rid'])}, NULL,
               {head} || "__fa_host" || coalesce(' as ' || "__fa_account", ''),
               {techs}, "__fa_host", "__fa_account"
        FROM logs
        WHERE {condition(r)}
    """


def apply_marks(con, on_rule=None) -> dict:
    """Marks for every runnable rule that is not a suggestion, and the case's SigmaHQ record:
    the rule set's provenance, and per rule whether it ran, had no event of its logsource
    (not applicable), could not be read or converted (ADR-006 decision 3)."""
    b = bundle()
    con.execute("CREATE TABLE IF NOT EXISTS sigma_marks (row_id BIGINT, rid VARCHAR, level VARCHAR)")
    con.execute("DELETE FROM sigma_marks")
    if not b["rules"]:
        return {"status": "not run", "reason": f"no converted SigmaHQ rules at {RULES_PATH}"}
    has_events = con.execute("SELECT count(*) FROM duckdb_tables() WHERE table_name = 'win_events'").fetchone()[0]
    rules = b["rules"]
    present: dict[str, bool] = {}
    counts = {"ran": 0, "not_applicable": 0, "not_readable": 0, "not_convertible": 0}
    errors, marked, suggested = [], {}, {}
    marks = [r for r in rules if runnable(r) and not suggests(r)]
    for i, r in enumerate(rules, 1):
        if r.get("error"):
            counts["not_convertible"] += 1
        elif r.get("not_readable"):
            counts["not_readable"] += 1
        else:
            if r["where"] not in present:
                present[r["where"]] = bool(has_events) and con.execute(
                    f"SELECT EXISTS (SELECT 1 FROM win_events w WHERE {r['where']})").fetchone()[0]
            counts["ran" if present[r["where"]] else "not_applicable"] += 1
        if on_rule:
            on_rule(i, len(rules) + len(marks))
    for i, r in enumerate(marks, 1):
        if present.get(r["where"]):
            try:
                n = con.execute(f"INSERT INTO sigma_marks WITH {logs_cte(r)} "
                                f"SELECT row_id, {_lit(r['rid'])}, {_lit(r['level'])} FROM logs "
                                f"WHERE {condition(r)}").fetchone()[0]
                if n:
                    marked[r["rid"]] = n
            except Exception as e:  # one rule's failure is listed, the others run
                errors.append({"rid": r["rid"], "error": f"{type(e).__name__}: {str(e)[:200]}"})
        if on_rule:
            on_rule(len(rules) + i, len(rules) + len(marks))
    if con.execute("SELECT count(*) FROM duckdb_tables() WHERE table_name = 'findings'").fetchone()[0]:
        suggested = dict(con.execute("SELECT rid, count(*) FROM findings WHERE rid LIKE 'SIGMA-%' "
                                     "GROUP BY 1").fetchall())
    return {"status": "ran", "provenance": b["provenance"], "sha256": b["sha256"], "rules": len(rules),
            "suggesting_rules": sum(1 for r in rules if suggests(r)), **counts,
            "suggestions": suggested, "marks": marked, "errors": errors}


@functools.lru_cache(maxsize=1)
def by_rid() -> dict[str, dict]:
    return {r["rid"]: r for r in bundle()["rules"]}
