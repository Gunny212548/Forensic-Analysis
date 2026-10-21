"""The reproducibility record of one processing run (story 3, I9).

ACPO principle 3: "An independent third party should be able to examine those
processes and achieve the same result." RFC 3227 sec. 3.1: methods "transparent
and reproducible"; SP 800-86 sec. 3.1.2: a log of every step "including
information about each tool used". So every `processed` custody line says
exactly what produced the findings: the application code, the rule set, the
log source profile each file was read through, the threat-intel feed files,
the DuckDB version, and the time settings applied.

The image carries no `.git`, so the code is identified by a digest over its
own source files rather than a commit: two runs with the same digests on the
same evidence must give the same result, and a different digest says the
method changed. Feed files are hashed because a feed refresh moves the intel
rules by design (gotcha #17).
"""

import hashlib
import json
from functools import lru_cache
from pathlib import Path

import duckdb

from . import intel, rules

_APP_DIR = Path(__file__).resolve().parents[1]


@lru_cache(maxsize=1)
def code_digest() -> str:
    """SHA-256 over every .py file of the app, by sorted relative path. Cached:
    the code does not change under a running process (a dev reload restarts it)."""
    h = hashlib.sha256()
    for path in sorted(_APP_DIR.rglob("*.py")):
        rel = path.relative_to(_APP_DIR).as_posix()
        if "__pycache__" in rel:
            continue
        h.update(rel.encode() + b"\0" + path.read_bytes() + b"\0")
    return h.hexdigest()


def rules_digest() -> str:
    """SHA-256 over every rule's id, SQL and Sigma level, in run order."""
    body = [(rid, sql, rules.RULE_LEVEL.get(rid)) for rid, sql in rules.RULES]
    return hashlib.sha256(json.dumps(body).encode()).hexdigest()


def feeds() -> list[dict]:
    """The intel feed files a run reads (intel.load_indicators), with digests."""
    directory = intel.intel_dir()
    if not directory.is_dir():
        return []
    out = []
    for path in sorted(directory.iterdir()):
        if path.is_file() and path.suffix.lower() in intel.FEED_SUFFIXES:
            out.append({"file": path.name, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
    return out


def record(mappings: list[dict], time_applied: list[dict]) -> dict:
    """The `method` block of a `processed` custody line."""
    return {
        "app_code_sha256": code_digest(),
        "rules_sha256": rules_digest(),
        "rules": len(rules.RULES),
        "profiles": sorted({m.get("profile") or m.get("method") or "none" for m in mappings}),
        "intel_feeds": feeds(),
        "duckdb": duckdb.__version__,
        "time_applied": time_applied,
    }
