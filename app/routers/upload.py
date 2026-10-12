import asyncio
import hashlib
import shutil
import zipfile
import zlib

from fastapi import APIRouter, BackgroundTasks, File, Form, HTTPException, Query, Request, UploadFile

from .. import config
from ..services import archive, custody, pipeline, storage

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


async def _run_pipeline(case_id: str, path, kind: str) -> None:
    # Off the event loop: the pipeline is CPU/IO-bound sync work, and
    # running it inline would stall every other request while a large
    # file is parsed.
    await asyncio.to_thread(pipeline.process_case, case_id, path, kind)


@router.post("/upload")
async def upload_log(
    request: Request,
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    note: str = Form(""),
    company_id: str = Form(""),
    company_name: str = Form(""),
):
    filename = file.filename or "upload"
    # FR-2.3: "fw.csv.gz" is a gzip'd CSV, a .zip is a bundle of logs.
    kind, compression = archive.detect(filename)

    storage.ensure_dirs()

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

    manifest = storage.create_case(
        original_filename=filename,
        file_kind=kind,
        size_bytes=0,
        note=note,
        company_id=company["company_id"],
        company_name=company["name"],
    )
    case_id = manifest["case_id"]
    # The raw copy keeps the analyst's bytes as uploaded - compressed stays
    # compressed; the pipeline reads it through gzip/zip itself.
    dest = storage.raw_path(case_id, f"{kind}.gz" if compression == "gz" else kind)

    def discard() -> None:
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
    custody.record(
        case_id, "acquired", actor,
        sha256=sha256, bytes=size, original_filename=manifest["original_filename"],
        compression=compression, client_address=request.client.host if request.client else None,
        stored_as=dest.name,
    )
    fields = {"size_bytes": size, "uncompressed_bytes": uncompressed,
              "compression": compression, "evidence": custody.evidence(sha256, size, actor), **extra}
    storage.update_case(case_id, **fields)
    manifest.update(fields)

    background_tasks.add_task(_run_pipeline, case_id, dest, kind)
    return manifest
