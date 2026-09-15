"""Flat-file storage for case manifests and cached AI analysis results.

Event data itself lives in a per-case DuckDB file (see db.py); this module
only handles the small JSON sidecars - the case manifest (status, counts,
filename) and the cached analysis output.
"""

import json
import os
import re
import secrets
from datetime import datetime, timezone
from pathlib import Path

from .. import config

_SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9._-]+")


def new_case_id() -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    return f"case-{stamp}-{secrets.token_hex(4)}"


def sanitize_original_name(name: str) -> str:
    name = os.path.basename(name or "upload")
    name = _SAFE_NAME_RE.sub("_", name)
    return name[:200] or "upload"


def cases_dir() -> Path:
    return Path(config.DATA_DIR) / "cases"


def analysis_dir() -> Path:
    return Path(config.DATA_DIR) / "analysis"


def raw_dir() -> Path:
    return Path(config.DATA_DIR) / "raw"


def companies_dir() -> Path:
    return Path(config.DATA_DIR) / "companies"


def ensure_dirs() -> None:
    for d in (cases_dir(), analysis_dir(), raw_dir(), companies_dir()):
        d.mkdir(parents=True, exist_ok=True)


def manifest_path(case_id: str) -> Path:
    return cases_dir() / f"{case_id}.json"


def save_manifest(manifest: dict) -> None:
    ensure_dirs()
    manifest_path(manifest["case_id"]).write_text(
        json.dumps(manifest, indent=2, default=str), encoding="utf-8"
    )


def load_manifest(case_id: str) -> dict | None:
    path = manifest_path(case_id)
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def list_manifests() -> list[dict]:
    ensure_dirs()
    manifests = []
    for path in cases_dir().glob("*.json"):
        try:
            manifests.append(json.loads(path.read_text(encoding="utf-8")))
        except (json.JSONDecodeError, OSError):
            continue
    manifests.sort(key=lambda m: m.get("uploaded_at", ""), reverse=True)
    return manifests


def update_case(case_id: str, **fields) -> None:
    manifest = load_manifest(case_id)
    if manifest is None:
        return
    manifest.update(fields)
    save_manifest(manifest)


def update_status(case_id: str, status: str) -> None:
    update_case(case_id, status=status)


def create_case(
    original_filename: str,
    file_kind: str,
    size_bytes: int,
    note: str = "",
    company_id: str | None = None,
    company_name: str | None = None,
) -> dict:
    ensure_dirs()
    manifest = {
        "case_id": new_case_id(),
        "original_filename": sanitize_original_name(original_filename),
        "file_kind": file_kind,  # "csv" | "json" | "log"
        "size_bytes": size_bytes,
        "note": note[:1000],
        "company_id": company_id,
        "company_name": company_name,
        "uploaded_at": datetime.now(timezone.utc).isoformat(),
        "status": "queued",
        "total_rows": 0,
        "flagged_count": 0,
    }
    save_manifest(manifest)
    return manifest


# ---------------------------------------------------------------- companies
# Cases are grouped by company/client the same way they're grouped by
# nothing today - a flat JSON sidecar per company, mirroring the case
# manifest pattern rather than pulling in a real database for one lookup
# table.

def new_company_id() -> str:
    return f"co-{secrets.token_hex(6)}"


def company_path(company_id: str) -> Path:
    return companies_dir() / f"{company_id}.json"


def create_company(name: str) -> dict:
    ensure_dirs()
    company = {
        "company_id": new_company_id(),
        "name": name[:200],
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    company_path(company["company_id"]).write_text(
        json.dumps(company, indent=2, default=str), encoding="utf-8"
    )
    return company


def load_company(company_id: str) -> dict | None:
    path = company_path(company_id)
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def list_companies() -> list[dict]:
    ensure_dirs()
    companies = []
    for path in companies_dir().glob("*.json"):
        try:
            companies.append(json.loads(path.read_text(encoding="utf-8")))
        except (json.JSONDecodeError, OSError):
            continue
    companies.sort(key=lambda c: c.get("name", "").lower())
    return companies


def find_company_by_name(name: str) -> dict | None:
    target = name.strip().lower()
    for c in list_companies():
        if c.get("name", "").strip().lower() == target:
            return c
    return None


def raw_path(case_id: str, ext: str) -> Path:
    return raw_dir() / f"{case_id}.{ext}"


def analysis_path(case_id: str) -> Path:
    return analysis_dir() / f"{case_id}.json"


def save_analysis(case_id: str, result: dict) -> None:
    ensure_dirs()
    analysis_path(case_id).write_text(json.dumps(result, indent=2, default=str), encoding="utf-8")


def load_analysis(case_id: str) -> dict | None:
    path = analysis_path(case_id)
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))
