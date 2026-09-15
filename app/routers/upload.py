import asyncio
import os

from fastapi import APIRouter, BackgroundTasks, File, Form, HTTPException, UploadFile

from .. import config
from ..services import pipeline, storage

router = APIRouter(prefix="/api", tags=["upload"])

CHUNK = 1024 * 1024  # 1MB


def _detect_kind(filename: str) -> str:
    ext = os.path.splitext(filename or "")[1].lower()
    if ext == ".csv":
        return "csv"
    if ext == ".json":
        return "json"
    return "log"


async def _run_pipeline(case_id: str, path, kind: str) -> None:
    # Off the event loop: the pipeline is CPU/IO-bound sync work, and
    # running it inline would stall every other request while a large
    # file is parsed.
    await asyncio.to_thread(pipeline.process_case, case_id, path, kind)


@router.post("/upload")
async def upload_log(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    note: str = Form(""),
    company_id: str = Form(""),
    company_name: str = Form(""),
):
    filename = file.filename or "upload"
    kind = _detect_kind(filename)

    storage.ensure_dirs()

    company = None
    if company_id:
        company = storage.load_company(company_id)
        if company is None:
            raise HTTPException(404, "Company not found")
    elif company_name.strip():
        # Inline "add new company" from the upload form - idempotent by
        # name so re-submitting doesn't fork a duplicate company.
        company = storage.find_company_by_name(company_name) or storage.create_company(company_name.strip())

    manifest = storage.create_case(
        original_filename=filename,
        file_kind=kind,
        size_bytes=0,
        note=note,
        company_id=company["company_id"] if company else None,
        company_name=company["name"] if company else None,
    )
    case_id = manifest["case_id"]
    dest = storage.raw_path(case_id, kind)

    # Stream to disk in chunks - never hold the whole upload in memory.
    size = 0
    with open(dest, "wb") as out:
        while chunk := await file.read(CHUNK):
            size += len(chunk)
            if size > config.MAX_UPLOAD_BYTES:
                out.close()
                dest.unlink(missing_ok=True)
                storage.manifest_path(case_id).unlink(missing_ok=True)
                raise HTTPException(
                    413, f"File exceeds max size of {config.MAX_UPLOAD_BYTES} bytes"
                )
            out.write(chunk)

    if size == 0:
        dest.unlink(missing_ok=True)
        storage.manifest_path(case_id).unlink(missing_ok=True)
        raise HTTPException(400, "Uploaded file is empty")

    storage.update_case(case_id, size_bytes=size)
    manifest["size_bytes"] = size

    background_tasks.add_task(_run_pipeline, case_id, dest, kind)
    return manifest
