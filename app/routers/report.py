"""The forensic report (docs/specs/forensic_report.md, IAI-72 / IAI-73).

Settings: the skeleton an administrator uploads (R-D11). A project: its report gate, the
drafts the system made and the finals the analysts uploaded back (R-D2, R-D4). Drafts are
made by anyone who works cases (`case:analyze`); reading the list and downloading is
`data:read`, which every signed-in role with a role has (main.require_login).
"""
import asyncio

from fastapi import APIRouter, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse

from ..services.access import authz
from ..services.report import report, report_skeleton
from ..services.store import storage

router = APIRouter(tags=["report"])

DOCX = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"


def _require(request: Request, action: str) -> dict:
    try:
        authz.require(request.state.user, action)
    except authz.Forbidden as exc:
        raise HTTPException(403, str(exc))
    return request.state.user


def _project(company_id: str, project_id: str) -> dict:
    if not (storage.valid_company_id(company_id) and storage.valid_project_id(project_id)):
        raise HTTPException(404, "Project not found")
    project = storage.load_project(company_id, project_id)
    if project is None or project.get("company_id", company_id) != company_id:
        raise HTTPException(404, "Project not found")
    return project


async def _read(upload: UploadFile | None, limit: int, what: str) -> bytes | None:
    if upload is None:
        return None
    data = await upload.read(limit + 1)
    if len(data) > limit:
        raise HTTPException(413, f"the {what} is over {limit // (1024 * 1024)} MB")
    return data or None


# ---------------------------------------------------------------- Settings: the skeleton
@router.get("/api/settings/report-skeleton")
def skeleton_info(request: Request):
    _require(request, authz.ACCOUNTS)
    return {"current": report_skeleton.current(), "history": report_skeleton.history()[::-1],
            "tags": report_skeleton.TAGS, "required": list(report_skeleton.REQUIRED),
            "max_bytes": report_skeleton.MAX_BYTES}


@router.post("/api/settings/report-skeleton")
async def skeleton_upload(request: Request, file: UploadFile = File(...)):
    user = _require(request, authz.ACCOUNTS)
    data = await _read(file, report_skeleton.MAX_BYTES, "skeleton") or b""
    try:
        return await asyncio.to_thread(report_skeleton.upload, user["email"], file.filename or "", data)
    except report_skeleton.Refused as exc:
        raise HTTPException(400, {"message": "The skeleton is refused", "problems": exc.problems})


@router.get("/api/settings/report-skeleton/{sha256}")
def skeleton_download(sha256: str, request: Request):
    _require(request, authz.ACCOUNTS)
    entry = next((e for e in report_skeleton.history() if e["sha256"] == sha256), None)
    try:
        path = report_skeleton.path(sha256)
    except ValueError:
        raise HTTPException(404, "Skeleton not found")
    if entry is None or not path.exists():
        raise HTTPException(404, "Skeleton not found")
    return FileResponse(path, media_type=DOCX, filename=entry.get("file") or f"skeleton-{sha256[:12]}.docx")


# ---------------------------------------------------------------- a project's report
@router.get("/api/companies/{company_id}/projects/{project_id}/report")
def report_listing(company_id: str, project_id: str):
    _project(company_id, project_id)
    return report.listing(company_id, project_id)


@router.post("/api/companies/{company_id}/projects/{project_id}/report/draft")
async def report_draft(company_id: str, project_id: str, request: Request,
                       details: str = Form(""), author_position: str = Form(""),
                       approver_name: str = Form(""), approver_position: str = Form(""),
                       coordinator_name: str = Form(""), coordinator_position: str = Form(""),
                       png: UploadFile | None = File(None), svg: UploadFile | None = File(None)):
    user = _require(request, authz.ANALYZE)
    _project(company_id, project_id)
    png_bytes = await _read(png, report.IMAGE_MAX, "attack path picture")
    svg_bytes = await _read(svg, report.IMAGE_MAX, "attack path drawing")
    people = {"author_position": author_position[:200], "approver_name": approver_name[:200],
              "approver_position": approver_position[:200], "coordinator_name": coordinator_name[:200],
              "coordinator_position": coordinator_position[:200]}
    try:
        # The AI's summary (~12 s) and the render run off the event loop.
        return await asyncio.to_thread(report.make_draft, company_id, project_id, user,
                                       details=details[:500], people=people, png=png_bytes, svg=svg_bytes)
    except report.NotReady as exc:
        raise HTTPException(409, str(exc))
    except report.BadInput as exc:
        raise HTTPException(400, str(exc))


@router.post("/api/companies/{company_id}/projects/{project_id}/report/final")
async def report_final(company_id: str, project_id: str, request: Request,
                       version: str = Form(...), file: UploadFile = File(...)):
    user = _require(request, authz.ANALYZE)
    _project(company_id, project_id)
    data = await _read(file, report.FINAL_MAX, "final") or b""
    try:
        return await asyncio.to_thread(report.add_final, company_id, project_id, user,
                                       file.filename or "", data, version)
    except report.BadInput as exc:
        raise HTTPException(400, str(exc))


@router.get("/api/companies/{company_id}/projects/{project_id}/report/files/{name}")
def report_file(company_id: str, project_id: str, name: str):
    _project(company_id, project_id)
    try:
        path = report.file_path(company_id, project_id, name)
    except ValueError:
        raise HTTPException(404, "Report file not found")
    known = {e.get("file") for e in report.drafts(company_id, project_id) + report.finals(company_id, project_id)}
    if name not in known or not path.exists():
        raise HTTPException(404, "Report file not found")
    media = "application/pdf" if name.endswith(".pdf") else DOCX
    return FileResponse(path, media_type=media, filename=name)
