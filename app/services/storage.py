"""Flat-file storage for case manifests and cached AI analysis results - and
where every case's files live.

Event data itself lives in a per-case DuckDB file (see db.py); this module
handles the small JSON sidecars - the case manifest (status, counts,
filename) and the cached analysis output - and owns the layout.

**Each customer has its own store** (since 2026-10-14): adding a customer
creates `DATA_DIR/customers/<company_id>/`, and everything of that
customer's cases lives under it and nowhere else -

    customers/<company_id>/
        customer.json   the customer record
        projects/       the customer's projects (one investigation each)
        cases/          manifests          db/        per-case DuckDB
        raw/            evidence as given  analysis/  cached AI output
        review/         decision logs      custody/   chain of custody

so one customer's evidence is never in a file, folder or database shared
with another's. What stays shared is not customer data: accounts
(users.json), the public threat-intel feeds (intel/), the MCP access log,
and transient staging under tmp/. `case_dir()` is the one place that
answers "which customer's store is this case in"; db.py, review.py and
custody.py build their paths on it. `tools/migrate_to_customers.py` moves a
store from the old flat layout.
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


# ------------------------------------------------------- per-customer stores

CASE_SUBDIRS = ("cases", "db", "raw", "analysis", "review", "custody")

# Ids are checked before they become a path component: a case or company id
# arrives in a URL, and "../users" must never resolve to a file.
_CASE_ID_RE = re.compile(r"^case-[0-9A-Za-z-]{1,64}$")
_COMPANY_ID_RE = re.compile(r"^co-[0-9a-f]{12}$")
_PROJECT_ID_RE = re.compile(r"^pj-[0-9a-f]{12}$")

# Reads of a case no customer owns land here. It is never created, so they
# miss; writes refuse instead (require_owner).
_UNOWNED = "_unowned"


class UnownedCase(LookupError):
    """A write was attempted for a case that is in no customer's store."""


class StoreNeedsMigration(RuntimeError):
    """The old shared layout still holds customers or cases. Until they are
    moved, adding a customer or a case is refused: the old customers are not
    visible, so "Bigfish" typed on the upload form would become a second,
    different Bigfish."""


def valid_case_id(case_id: str) -> bool:
    return bool(_CASE_ID_RE.match(case_id or ""))


def valid_company_id(company_id: str) -> bool:
    return bool(_COMPANY_ID_RE.match(company_id or ""))


def customers_dir() -> Path:
    return Path(config.DATA_DIR) / "customers"


def customer_dir(company_id: str) -> Path:
    if not valid_company_id(company_id):
        raise ValueError(f"not a customer id: {company_id!r}")
    return customers_dir() / company_id


def legacy_count() -> int:
    """Customer and case records still in the old shared layout
    (DATA_DIR/companies, DATA_DIR/cases), which nothing reads any more."""
    data = Path(config.DATA_DIR)
    return sum(sum(1 for _ in (data / d).glob("*.json"))
               for d in ("cases", "companies") if (data / d).is_dir())


def _refuse_if_legacy() -> None:
    if legacy_count():
        raise StoreNeedsMigration(
            "This store still has customers or cases in the old shared layout. "
            "Run tools/migrate_to_customers.py --apply before adding anything.")


def ensure_root() -> int:
    """Create DATA_DIR/customers; return legacy_count()."""
    customers_dir().mkdir(parents=True, exist_ok=True)
    return legacy_count()


def ensure_customer_store(company_id: str) -> Path:
    """The customer's own store - created when the customer is added, and
    re-asserted (idempotently) whenever a case is written into it."""
    root = customer_dir(company_id)
    for sub in CASE_SUBDIRS:
        (root / sub).mkdir(parents=True, exist_ok=True)
    return root


# case_id -> company_id. A case never changes customer, so an entry never
# goes stale; a miss is looked up on disk once and remembered.
_owner: dict[str, str] = {}


def case_company(case_id: str) -> str | None:
    """Which customer's store holds this case, or None."""
    if case_id in _owner:
        return _owner[case_id]
    if not valid_case_id(case_id):
        return None
    root = customers_dir()
    if root.is_dir():
        for d in root.iterdir():
            if (d / "cases" / f"{case_id}.json").is_file() and valid_company_id(d.name):
                _owner[case_id] = d.name
                return d.name
    return None


def case_dir(case_id: str, sub: str) -> Path:
    """`sub` (one of CASE_SUBDIRS) inside the store of the customer who owns
    the case. For a case nobody owns: a path that does not exist."""
    company_id = case_company(case_id)
    return customers_dir() / (company_id or _UNOWNED) / sub


def require_owner(case_id: str) -> str:
    company_id = case_company(case_id)
    if company_id is None:
        raise UnownedCase(f"{case_id} belongs to no customer - nothing is written for it")
    return company_id


def manifest_path(case_id: str) -> Path:
    return case_dir(case_id, "cases") / f"{case_id}.json"


def save_manifest(manifest: dict) -> None:
    # The manifest says whose case it is, and that decides where it goes:
    # this is the write that puts a new case into its customer's store.
    company_id = manifest.get("company_id")
    if not company_id:
        raise UnownedCase(f"{manifest.get('case_id')} has no customer (FR-2.1)")
    ensure_customer_store(company_id)
    _owner[manifest["case_id"]] = company_id
    # Write-then-rename: the pipeline now rewrites a manifest about once a
    # second to report progress (FR-2.5) while the UI polls it, and a reader
    # must never catch a half-written file.
    path = manifest_path(manifest["case_id"])
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(manifest, indent=2, default=str), encoding="utf-8")
    os.replace(tmp, path)


def load_manifest(case_id: str) -> dict | None:
    path = manifest_path(case_id)
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def list_manifests(company_id: str | None = None) -> list[dict]:
    """One customer's cases, or - with no customer named - every customer's,
    each read from its own store."""
    if company_id is not None:
        stores = [customer_dir(company_id)]
    else:
        root = customers_dir()
        stores = [d for d in root.iterdir() if valid_company_id(d.name)] if root.is_dir() else []
    manifests = []
    for store in stores:
        for path in (store / "cases").glob("*.json"):
            try:
                m = json.loads(path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                continue
            _owner.setdefault(m.get("case_id", ""), store.name)
            manifests.append(m)
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
    merged_from: list[dict] | None = None,
    project: dict | None = None,
) -> dict:
    _refuse_if_legacy()
    if not company_id or load_company(company_id) is None:
        # FR-2.1 - and since 2026-10-14 also where the case is stored.
        raise UnownedCase("a case needs an existing customer")
    if project and load_project(company_id, project["project_id"]) is None:
        raise ValueError("the project is not one of this customer's")
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
    if merged_from:
        # Provenance for a case built by POST /api/cases/merge: the source
        # cases in the order their bytes were concatenated. It lives on the
        # manifest rather than inside `note` because it is structured audit
        # trail - the same reason the original upload is kept in raw/ - and
        # `note` is capped at 1000 chars, which a dozen case ids overflow.
        manifest["merged_from"] = merged_from
    if project:
        manifest["project_id"] = project["project_id"]
        manifest["project_name"] = project["name"]
    save_manifest(manifest)
    return manifest


# ---------------------------------------------------------------- companies
# A customer is its store's customer.json. Adding one creates the store, so
# a customer's first case already has somewhere of its own to go.

def new_company_id() -> str:
    return f"co-{secrets.token_hex(6)}"


def company_path(company_id: str) -> Path:
    return customer_dir(company_id) / "customer.json"


def create_company(name: str) -> dict:
    _refuse_if_legacy()
    company = {
        "company_id": new_company_id(),
        "name": name[:200],
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    ensure_customer_store(company["company_id"])
    company_path(company["company_id"]).write_text(
        json.dumps(company, indent=2, default=str), encoding="utf-8"
    )
    return company


def load_company(company_id: str) -> dict | None:
    if not valid_company_id(company_id):
        return None
    path = company_path(company_id)
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def list_companies() -> list[dict]:
    root = customers_dir()
    companies = []
    for d in (root.iterdir() if root.is_dir() else []):
        if not valid_company_id(d.name):
            continue
        try:
            companies.append(json.loads((d / "customer.json").read_text(encoding="utf-8")))
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


# ----------------------------------------------------------------- projects
# A project is one investigation for one customer, grouping the cases
# uploaded for it. It is kept in that customer's store, so it can never
# hold another customer's case. Optional: a case without one is "No project".

def valid_project_id(project_id: str) -> bool:
    return bool(_PROJECT_ID_RE.match(project_id or ""))


def project_path(company_id: str, project_id: str) -> Path:
    if not valid_project_id(project_id):
        raise ValueError(f"not a project id: {project_id!r}")
    return customer_dir(company_id) / "projects" / f"{project_id}.json"


def create_project(company_id: str, name: str, created_by: str) -> dict:
    if load_company(company_id) is None:
        raise UnownedCase("a project needs an existing customer")
    project = {
        "project_id": f"pj-{secrets.token_hex(6)}",
        "company_id": company_id,
        "name": name.strip()[:200],
        "created_at": datetime.now(timezone.utc).isoformat(),
        "created_by": created_by,
    }
    path = project_path(company_id, project["project_id"])
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(project, indent=2, default=str), encoding="utf-8")
    return project


def load_project(company_id: str, project_id: str) -> dict | None:
    if not (valid_company_id(company_id) and valid_project_id(project_id)):
        return None
    path = project_path(company_id, project_id)
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def list_projects(company_id: str) -> list[dict]:
    projects = []
    for path in (customer_dir(company_id) / "projects").glob("pj-*.json"):
        try:
            projects.append(json.loads(path.read_text(encoding="utf-8")))
        except (json.JSONDecodeError, OSError):
            continue
    projects.sort(key=lambda p: p.get("created_at", ""), reverse=True)
    return projects


def find_project_by_name(company_id: str, name: str) -> dict | None:
    target = name.strip().lower()
    for p in list_projects(company_id):
        if p.get("name", "").strip().lower() == target:
            return p
    return None


def raw_path(case_id: str, ext: str) -> Path:
    return case_dir(case_id, "raw") / f"{case_id}.{ext}"


def analysis_path(case_id: str) -> Path:
    return case_dir(case_id, "analysis") / f"{case_id}.json"


def save_analysis(case_id: str, result: dict) -> None:
    require_owner(case_id)
    analysis_path(case_id).write_text(json.dumps(result, indent=2, default=str), encoding="utf-8")


def load_analysis(case_id: str) -> dict | None:
    path = analysis_path(case_id)
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


# ------------------------------------------------------- analysis job state
# A map-reduce narrative is N+1 Groq calls at roughly one call's worth of
# output budget a minute, which is minutes of wall clock - too long to hold an
# HTTP request open, so /analyze queues it the same way /upload queues the
# pipeline and the client polls. The job lives in its OWN sidecar rather than
# inside the analysis file, because a force-refresh must not overwrite the
# last good analysis with a progress stub: while the job runs, the previous
# narrative is still the best answer available.

def analysis_job_path(case_id: str) -> Path:
    return case_dir(case_id, "analysis") / f"{case_id}.job.json"


def save_analysis_job(case_id: str, job: dict) -> dict:
    require_owner(case_id)
    job = dict(job, case_id=case_id, updated_at=datetime.now(timezone.utc).isoformat())
    analysis_job_path(case_id).write_text(
        json.dumps(job, indent=2, default=str), encoding="utf-8"
    )
    return job


def load_analysis_job(case_id: str) -> dict | None:
    path = analysis_job_path(case_id)
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None


def update_analysis_job(case_id: str, **fields) -> dict | None:
    job = load_analysis_job(case_id)
    if job is None:
        return None
    job.update(fields)
    return save_analysis_job(case_id, job)
