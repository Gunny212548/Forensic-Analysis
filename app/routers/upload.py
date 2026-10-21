import hashlib
import shutil
import zipfile
import zlib

from fastapi import APIRouter, File, Form, HTTPException, Query, Request, UploadFile

from .. import config
from ..services import archive, custody, jobs, storage

router = APIRouter(prefix="/api", tags=["upload"])

CHUNK = 1024 * 1024  # 1MB


def _gb(n: float) -> str:
    return f"{n / 1024**3:.1f} GB"


def capacity_problem(size: int) -> tuple[int, str] | None:
    """FR-2.2's two refusals for a file of `size` bytes, or None if it fits.

    These have to run before the request body is read, not in upload_log():
    Starlette parses the multipart form - spooling the whole file into a temp
    file - before the handler is even called, so a check in the handler
    only fires after 10 GB has already crossed the network and hit the disk.
    main.py calls this on Content-Length, and the page calls /upload/check
    before it starts sending."""
    if size > config.MAX_UPLOAD_BYTES:
        return 413, f"File is {_gb(size)}; the limit is {_gb(config.MAX_UPLOAD_BYTES)} per file"
    free = shutil.disk_usage(config.DATA_DIR).free
    need = size * config.UPLOAD_DISK_FACTOR
    if free < need:
        return 507, (f"Not enough disk space: a {_gb(size)} file needs {_gb(need)} free "
                     f"({config.UPLOAD_DISK_FACTOR:g}x its size), only {_gb(free)} is available")
    return None


@router.get("/upload/check")
async def upload_check(size: int = Query(0, ge=0)):
    """Pre-flight for the upload page: limits, and whether `size` would be
    accepted - so a refusal arrives before the file is sent, not after."""
    if size:
        problem = capacity_problem(size)
        if problem:
            raise HTTPException(*problem)
    return {
        "max_bytes": config.MAX_UPLOAD_BYTES,
        "free_bytes": shutil.disk_usage(config.DATA_DIR).free,
        "disk_factor": config.UPLOAD_DISK_FACTOR,
    }


@router.post("/upload")
async def upload_log(
    request: Request,
    file: UploadFile = File(...),
    note: str = Form(""),
    company_id: str = Form(""),
    company_name: str = Form(""),
    project_id: str = Form(""),
    project_name: str = Form(""),
):
    filename = file.filename or "upload"
    # FR-2.3: "fw.csv.gz" is a gzip'd CSV, a .zip is a bundle of logs.
    kind, compression = archive.detect(filename)

    # FR-2.1: every case belongs to exactly one customer, so an upload without
    # one is refused here and not only greyed out in the UI - the API is also
    # called by scripts (tests/check_parity.py).
    if company_id:
        company = storage.load_company(company_id)
        if company is None:
            raise HTTPException(404, "Company not found")
    elif company_name.strip():
        # Inline "add new company" from the upload form - idempotent by
        # name so re-submitting doesn't fork a duplicate company.
        company = storage.find_company_by_name(company_name) or storage.create_company(company_name.strip())
    else:
        raise HTTPException(400, "A customer is required - every case belongs to exactly one customer")

    # Optional. A project is one of the chosen customer's - an id from any
    # other customer is refused, never filed under this one.
    project = None
    if project_id:
        project = storage.load_project(company["company_id"], project_id)
        if project is None:
            raise HTTPException(409, "Project not found for this customer")
    elif project_name.strip():
        # Inline "add new project", idempotent by name like the customer.
        project = (storage.find_project_by_name(company["company_id"], project_name)
                   or storage.create_project(company["company_id"], project_name,
                                             request.state.user["email"]))

    manifest = storage.create_case(
        original_filename=filename,
        file_kind=kind,
        size_bytes=0,
        note=note,
        company_id=company["company_id"],
        company_name=company["name"],
        project=project,
    )
    case_id = manifest["case_id"]
    # Until the whole file is on disk a restart must fail this case, not leave it
    # `queued` for ever (services/jobs.py).
    jobs.begin(case_id)
    # The raw copy keeps the analyst's bytes as uploaded - compressed stays
    # compressed; the pipeline reads it through gzip/zip itself.
    dest = storage.raw_path(case_id, f"{kind}.gz" if compression == "gz" else kind)

    def discard() -> None:
        jobs.cancel(case_id)
        dest.unlink(missing_ok=True)
        storage.manifest_path(case_id).unlink(missing_ok=True)

    too_large = HTTPException(
        413, f"File exceeds the limit of {_gb(config.MAX_UPLOAD_BYTES)} per file (after decompression)"
    )

    # Stream to disk in chunks - never hold the whole upload in memory.
    # FR-2.2's limit is on the size *after* decompression; the early check in
    # main.py only sees the compressed Content-Length, so it is enforced here:
    # a .gz is inflated in memory as it arrives purely to count it (nothing
    # decompressed is kept), a .zip is judged by its directory below and
    # again, byte for byte, when the pipeline extracts it.
    size = 0
    counter = archive.GzipCounter(config.MAX_UPLOAD_BYTES) if compression == "gz" else None
    # The acquisition digest (custody.py): over exactly the bytes written to
    # raw/, computed as they stream rather than by reading 10 GB back.
    digest = hashlib.sha256()
    try:
        with open(dest, "wb") as out:
            while chunk := await file.read(CHUNK):
                size += len(chunk)
                if counter:
                    counter.feed(chunk)
                elif size > config.MAX_UPLOAD_BYTES:
                    raise too_large
                digest.update(chunk)
                out.write(chunk)
        uncompressed = counter.finish() if counter else size
    except archive.TooLarge:
        discard()
        raise too_large
    except (ValueError, zlib.error) as exc:  # corrupt or truncated gzip
        discard()
        raise HTTPException(400, f"Not a valid gzip file: {exc}")
    except HTTPException:
        discard()
        raise

    if size == 0:
        discard()
        raise HTTPException(400, "Uploaded file is empty")

    extra = {}
    if compression == "zip":
        try:
            members, skipped = archive.plan_zip(dest)
        except zipfile.BadZipFile as exc:
            discard()
            raise HTTPException(400, f"Not a valid zip file: {exc}")
        if not members:
            discard()
            raise HTTPException(400, "The zip contains no log files"
                                + (f" (skipped: {', '.join(s['name'] for s in skipped[:5])})" if skipped else ""))
        uncompressed = sum(m.size for m in members)
        if uncompressed > config.MAX_UPLOAD_BYTES:
            discard()
            raise too_large
        extra = {"members": [{"name": m.name, "kind": m.kind, "bytes": m.size} for m in members],
                 "skipped_members": skipped}

    # Who handed the evidence over, from where, and its digest - recorded
    # before anything reads it (RFC 3227 chain of custody).
    actor = request.state.user["email"]
    sha256 = digest.hexdigest()
    # The same bytes received before, for this customer only (D11, gotcha #40):
    # accepted as its own evidence item - receiving it twice is a custody fact.
    duplicate_of = [{"case_id": m["case_id"], "original_filename": m.get("original_filename"),
                     "project_name": m.get("project_name")}
                    for m in storage.list_manifests(company["company_id"])
                    if m["case_id"] != case_id and (m.get("evidence") or {}).get("sha256") == sha256]
    custody.record(
        case_id, "acquired", actor,
        sha256=sha256, bytes=size, original_filename=manifest["original_filename"],
        compression=compression, client_address=request.client.host if request.client else None,
        stored_as=dest.name,
        **({"duplicate_of": [d["case_id"] for d in duplicate_of]} if duplicate_of else {}),
    )
    fields = {"size_bytes": size, "uncompressed_bytes": uncompressed,
              "compression": compression, "evidence": custody.evidence(sha256, size, actor), **extra}
    if duplicate_of:
        fields["duplicate_of"] = duplicate_of
    storage.update_case(case_id, **fields)
    manifest.update(fields)

    jobs.submit(case_id, dest, kind)  # queued; a worker thread runs the pipeline
    return manifest
