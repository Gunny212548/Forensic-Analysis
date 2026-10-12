"""Assert every detection rule carries consistent Sigma + ADS metadata.

    python tests/check_rule_meta.py

Fails (exit 1) when a rule in rules.RULES has no entry in
rule_meta.RULE_META, when the ATT&CK techniques its metadata documents
differ from the ones its SQL writes into findings, when a status is not one
of Sigma's, or when an id repeats. Run it after adding or changing a rule.
Needs only duckdb (imported by rules.py), like the rest of the host tooling.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.services import rule_meta  # noqa: E402
from app.services.rules import RULES  # noqa: E402


def main() -> int:
    problems = rule_meta.problems()
    for p in problems:
        print(f"PROBLEM  {p}")
    statuses: dict[str, list[str]] = {}
    for rid, _ in RULES:
        if rid in rule_meta.RULE_META:
            statuses.setdefault(rule_meta.RULE_META[rid]["status"], []).append(rid)
    for status, rids in sorted(statuses.items()):
        print(f"{status:<13} {len(rids):>2}  {' '.join(rids)}")
    print("RULE METADATA OK" if not problems else f"{len(problems)} problem(s)")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
