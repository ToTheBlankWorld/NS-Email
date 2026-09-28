"""Forensic case management endpoints (Stage 11).

Cases organize captures into investigations and preserve analyst
workflow context (notes, tags, bookmarks, timeline, reports) without
altering the underlying forensic evidence. Every endpoint here reads
evidence and writes only case metadata; the Stages 1-9 analysis
endpoints are untouched.

Error shape follows the repository convention:
``{"error": {"code", "message"}}`` with ``case_not_found`` (404) for
unknown or malformed case ids (a malformed id can never address
anything, so it is reported exactly like an unknown one) and
``invalid_request`` (422) for rejected analyst input.
"""

import logging
import re
import time
from collections.abc import Callable
from typing import Any

from fastapi import APIRouter, Request, Response
from pydantic import BaseModel, Field

from app.api_models import (
    CaseBookmarkResponse,
    CaseNoteResponse,
    CaseResponse,
    CaseTimelineEntryResponse,
)
from app.case_store import (
    BOOKMARK_ID_PATTERN,
    CASE_ID_PATTERN,
    NOTE_ID_PATTERN,
)
from app.errors import (
    ERROR_CAPTURE_NOT_FOUND,
    ERROR_CASE_NOT_FOUND,
    ERROR_INVALID_REQUEST,
    ApiError,
)
from app.services.analysis import CaptureNotFoundError
from app.services.case_report import case_report_to_json
from app.services.case_report_html import render_case_html_report
from app.services.case_report_pdf import render_case_pdf_report
from app.services.cases import CaseNotFoundError, CaseService, CaseValidationError

router = APIRouter(prefix="/api/cases", tags=["cases"])

logger = logging.getLogger("ns_email.cases")

# Tags travel in DELETE paths, so routing-safe values only.
_TAG_PATH_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._\-]{0,63}$")


def _cases(request: Request) -> CaseService:
    service: CaseService | None = getattr(request.app.state, "case_service", None)
    if service is None:  # pragma: no cover - wiring invariant
        raise RuntimeError("case service is not configured")
    return service


def _handle_case_errors[T](action: str, func: Callable[[], T]) -> T:
    """Map case-domain errors onto the structured API error shape."""
    try:
        return func()
    except CaseNotFoundError as error:
        raise ApiError(ERROR_CASE_NOT_FOUND, "no case exists with this id", 404) from error
    except CaseValidationError as error:
        raise ApiError(ERROR_INVALID_REQUEST, str(error), 422) from error
    except CaptureNotFoundError as error:
        raise ApiError(ERROR_CAPTURE_NOT_FOUND, str(error), 404) from error


def _case_out(record: Any) -> CaseResponse:
    return CaseResponse(
        case_id=record.case_id,
        case_number=record.case_number,
        title=record.title,
        description=record.description,
        status=record.status,
        priority=record.priority,
        created_at=record.created_at,
        updated_at=record.updated_at,
        closed_at=record.closed_at,
        schema_version=record.schema_version,
    )


def _note_out(note: Any) -> CaseNoteResponse:
    return CaseNoteResponse(
        note_id=note.note_id,
        case_id=note.case_id,
        target_type=note.target_type,
        target_id=note.target_id,
        content=note.content,
        created_at=note.created_at,
        updated_at=note.updated_at,
    )


def _bookmark_out(bookmark: Any) -> CaseBookmarkResponse:
    return CaseBookmarkResponse(
        bookmark_id=bookmark.bookmark_id,
        case_id=bookmark.case_id,
        target_type=bookmark.target_type,
        target_id=bookmark.target_id,
        label=bookmark.label,
        note=bookmark.note,
        created_at=bookmark.created_at,
    )


def _timeline_out(entry: Any) -> CaseTimelineEntryResponse:
    return CaseTimelineEntryResponse(
        entry_id=entry.entry_id,
        case_id=entry.case_id,
        event_type=entry.event_type,
        detail=dict(entry.detail),
        created_at=entry.created_at,
    )


def _require_case_path(case_id: str) -> str:
    # Malformed ids are unknown by definition and can never address storage.
    if not CASE_ID_PATTERN.fullmatch(case_id):
        raise ApiError(ERROR_CASE_NOT_FOUND, "no case exists with this id", 404)
    return case_id


def _require_note_path(note_id: str) -> str:
    if not NOTE_ID_PATTERN.fullmatch(note_id):
        raise ApiError(ERROR_INVALID_REQUEST, "unknown note", 422)
    return note_id


def _require_bookmark_path(bookmark_id: str) -> str:
    if not BOOKMARK_ID_PATTERN.fullmatch(bookmark_id):
        raise ApiError(ERROR_INVALID_REQUEST, "unknown bookmark", 422)
    return bookmark_id


def _require_tag_path(tag: str) -> str:
    if not _TAG_PATH_PATTERN.fullmatch(tag):
        raise ApiError(ERROR_INVALID_REQUEST, "invalid tag value", 422)
    return tag


# -- request models ----------------------------------------------------------


class CaseCreateInput(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    description: str = Field(default="", max_length=5000)
    priority: str = Field(default="MEDIUM", min_length=1, max_length=16)


class CaseUpdateInput(BaseModel):
    title: str | None = Field(default=None, min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=5000)
    status: str | None = Field(default=None, min_length=1, max_length=16)
    priority: str | None = Field(default=None, min_length=1, max_length=16)


class CaptureAttachInput(BaseModel):
    capture_id: str = Field(min_length=1, max_length=64)


class NoteCreateInput(BaseModel):
    target_type: str = Field(min_length=1, max_length=32)
    target_id: str = Field(min_length=1, max_length=256)
    content: str = Field(min_length=1, max_length=10000)


class NoteUpdateInput(BaseModel):
    content: str = Field(min_length=1, max_length=10000)


class TagCreateInput(BaseModel):
    tag: str = Field(min_length=1, max_length=64)


class BookmarkCreateInput(BaseModel):
    target_type: str = Field(min_length=1, max_length=32)
    target_id: str = Field(min_length=1, max_length=256)
    label: str = Field(default="", max_length=200)
    note: str = Field(default="", max_length=2000)


# -- cases -------------------------------------------------------------------


@router.post("", response_model=CaseResponse, summary="Create a forensic case")
def create_case(request: Request, body: CaseCreateInput) -> CaseResponse:
    service = _cases(request)
    record = _handle_case_errors(
        "create_case",
        lambda: service.create_case(body.title, body.description, body.priority.upper()),
    )
    logger.info("case created: case_id=%s priority=%s", record.case_id, record.priority)
    return _case_out(record)


@router.get("", response_model=list[CaseResponse], summary="List forensic cases")
def list_cases(request: Request, status: str | None = None) -> list[CaseResponse]:
    service = _cases(request)
    records = _handle_case_errors(
        "list_cases", lambda: service.list_cases(status.upper() if status else None)
    )
    return [_case_out(record) for record in records]


@router.get("/{case_id}", response_model=CaseResponse, summary="Get one case")
def get_case(case_id: str, request: Request) -> CaseResponse:
    _require_case_path(case_id)
    service = _cases(request)
    return _case_out(_handle_case_errors("get_case", lambda: service.get_case(case_id)))


@router.patch("/{case_id}", response_model=CaseResponse, summary="Update case metadata")
def update_case(case_id: str, request: Request, body: CaseUpdateInput) -> CaseResponse:
    _require_case_path(case_id)
    service = _cases(request)
    record = _handle_case_errors(
        "update_case",
        lambda: service.update_case(
            case_id,
            title=body.title,
            description=body.description,
            status=body.status.upper() if body.status else None,
            priority=body.priority.upper() if body.priority else None,
        ),
    )
    return _case_out(record)


@router.delete("/{case_id}", summary="Delete a case and its metadata")
def delete_case(case_id: str, request: Request) -> Response:
    _require_case_path(case_id)
    service = _cases(request)
    _handle_case_errors("delete_case", lambda: service.delete_case(case_id))
    logger.info("case deleted: case_id=%s", case_id)
    return Response(status_code=204)


# -- capture association -------------------------------------------------------


@router.post("/{case_id}/captures", summary="Attach a capture to a case")
def attach_capture(case_id: str, request: Request, body: CaptureAttachInput) -> dict[str, Any]:
    _require_case_path(case_id)
    service = _cases(request)
    attachment = _handle_case_errors(
        "attach_capture", lambda: service.attach_capture(case_id, body.capture_id)
    )
    return {
        "case_id": attachment.case_id,
        "capture_id": attachment.capture_id,
        "attached_at": attachment.attached_at.isoformat() if attachment.attached_at else None,
    }


@router.delete("/{case_id}/captures/{capture_id}", summary="Detach a capture from a case")
def detach_capture(case_id: str, capture_id: str, request: Request) -> Response:
    _require_case_path(case_id)
    service = _cases(request)
    _handle_case_errors("detach_capture", lambda: service.detach_capture(case_id, capture_id))
    return Response(status_code=204)


# -- notes ---------------------------------------------------------------------


@router.get("/{case_id}/notes", response_model=list[CaseNoteResponse], summary="List case notes")
def list_notes(case_id: str, request: Request) -> list[CaseNoteResponse]:
    _require_case_path(case_id)
    service = _cases(request)
    notes = _handle_case_errors("list_notes", lambda: service.list_notes(case_id))
    return [_note_out(note) for note in notes]


@router.post("/{case_id}/notes", response_model=CaseNoteResponse, summary="Create a note")
def create_note(case_id: str, request: Request, body: NoteCreateInput) -> CaseNoteResponse:
    _require_case_path(case_id)
    service = _cases(request)
    note = _handle_case_errors(
        "create_note",
        lambda: service.create_note(case_id, body.target_type, body.target_id, body.content),
    )
    return _note_out(note)


@router.patch(
    "/{case_id}/notes/{note_id}", response_model=CaseNoteResponse, summary="Update a note"
)
def update_note(
    case_id: str, note_id: str, request: Request, body: NoteUpdateInput
) -> CaseNoteResponse:
    _require_case_path(case_id)
    _require_note_path(note_id)
    service = _cases(request)
    note = _handle_case_errors(
        "update_note", lambda: service.update_note(case_id, note_id, body.content)
    )
    return _note_out(note)


@router.delete("/{case_id}/notes/{note_id}", summary="Delete a note")
def delete_note(case_id: str, note_id: str, request: Request) -> Response:
    _require_case_path(case_id)
    _require_note_path(note_id)
    service = _cases(request)
    _handle_case_errors("delete_note", lambda: service.delete_note(case_id, note_id))
    return Response(status_code=204)


# -- tags ------------------------------------------------------------------------


@router.get("/{case_id}/tags", summary="List case tags")
def list_tags(case_id: str, request: Request) -> dict[str, Any]:
    _require_case_path(case_id)
    service = _cases(request)
    tags = _handle_case_errors("list_tags", lambda: service.list_tags(case_id))
    return {"case_id": case_id, "tags": tags}


@router.post("/{case_id}/tags", summary="Add a tag to a case")
def add_tag(case_id: str, request: Request, body: TagCreateInput) -> dict[str, Any]:
    _require_case_path(case_id)
    service = _cases(request)
    tag = _handle_case_errors("add_tag", lambda: service.add_tag(case_id, body.tag))
    return {"case_id": case_id, "tag": tag}


@router.delete("/{case_id}/tags/{tag}", summary="Remove a tag from a case")
def remove_tag(case_id: str, tag: str, request: Request) -> Response:
    _require_case_path(case_id)
    _require_tag_path(tag)
    service = _cases(request)
    _handle_case_errors("remove_tag", lambda: service.remove_tag(case_id, tag))
    return Response(status_code=204)


# -- bookmarks ---------------------------------------------------------------------


@router.get(
    "/{case_id}/bookmarks",
    response_model=list[CaseBookmarkResponse],
    summary="List case bookmarks",
)
def list_bookmarks(case_id: str, request: Request) -> list[CaseBookmarkResponse]:
    _require_case_path(case_id)
    service = _cases(request)
    bookmarks = _handle_case_errors("list_bookmarks", lambda: service.list_bookmarks(case_id))
    return [_bookmark_out(bookmark) for bookmark in bookmarks]


@router.post(
    "/{case_id}/bookmarks",
    response_model=CaseBookmarkResponse,
    summary="Bookmark an evidence reference",
)
def create_bookmark(
    case_id: str, request: Request, body: BookmarkCreateInput
) -> CaseBookmarkResponse:
    _require_case_path(case_id)
    service = _cases(request)
    bookmark = _handle_case_errors(
        "create_bookmark",
        lambda: service.create_bookmark(
            case_id, body.target_type, body.target_id, body.label, body.note
        ),
    )
    return _bookmark_out(bookmark)


@router.delete("/{case_id}/bookmarks/{bookmark_id}", summary="Delete a bookmark")
def delete_bookmark(case_id: str, bookmark_id: str, request: Request) -> Response:
    _require_case_path(case_id)
    _require_bookmark_path(bookmark_id)
    service = _cases(request)
    _handle_case_errors("delete_bookmark", lambda: service.delete_bookmark(case_id, bookmark_id))
    return Response(status_code=204)


# -- timeline / summary --------------------------------------------------------------


@router.get(
    "/{case_id}/timeline",
    response_model=list[CaseTimelineEntryResponse],
    summary="Case investigation timeline",
)
def list_timeline(case_id: str, request: Request) -> list[CaseTimelineEntryResponse]:
    _require_case_path(case_id)
    service = _cases(request)
    entries = _handle_case_errors("list_timeline", lambda: service.list_timeline(case_id))
    return [_timeline_out(entry) for entry in entries]


@router.get("/{case_id}/summary", summary="Deterministic case summary")
def get_summary(case_id: str, request: Request) -> dict[str, Any]:
    _require_case_path(case_id)
    service = _cases(request)
    return _handle_case_errors("case_summary", lambda: service.case_summary(case_id))


# -- case reports ----------------------------------------------------------------------


def _case_report_filename(case_number: str, extension: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", case_number or "case")
    return f"securemailscope-case-{safe}.{extension}"


@router.get("/{case_id}/report.json", summary="Deterministic JSON case report")
def get_case_json_report(case_id: str, request: Request) -> Response:
    started = time.monotonic()
    _require_case_path(case_id)
    service = _cases(request)
    document = _handle_case_errors("case_report", lambda: service.build_case_report(case_id))
    body = case_report_to_json(document)
    _handle_case_errors("record_report", lambda: service.record_case_report(case_id, "json"))
    logger.info(
        "case report generated: case_id=%s format=json bytes=%d duration_ms=%d",
        case_id,
        len(body),
        int((time.monotonic() - started) * 1000),
    )
    case_number = str(document.get("report", {}).get("case_number") or "case")
    return Response(
        content=body,
        media_type="application/json",
        headers={
            "Content-Disposition": (
                f'attachment; filename="{_case_report_filename(case_number, "json")}"'
            )
        },
    )


@router.get("/{case_id}/report.html", summary="Standalone HTML case report")
def get_case_html_report(case_id: str, request: Request) -> Response:
    started = time.monotonic()
    _require_case_path(case_id)
    service = _cases(request)
    document = _handle_case_errors("case_report", lambda: service.build_case_report(case_id))
    html_body = render_case_html_report(document)
    _handle_case_errors("record_report", lambda: service.record_case_report(case_id, "html"))
    logger.info(
        "case report generated: case_id=%s format=html bytes=%d duration_ms=%d",
        case_id,
        len(html_body),
        int((time.monotonic() - started) * 1000),
    )
    case_number = str(document.get("report", {}).get("case_number") or "case")
    return Response(
        content=html_body,
        media_type="text/html; charset=utf-8",
        headers={
            "Content-Disposition": (
                f'attachment; filename="{_case_report_filename(case_number, "html")}"'
            )
        },
    )


@router.get("/{case_id}/report.pdf", summary="PDF case report")
def get_case_pdf_report(case_id: str, request: Request) -> Response:
    started = time.monotonic()
    _require_case_path(case_id)
    service = _cases(request)
    document = _handle_case_errors("case_report", lambda: service.build_case_report(case_id))
    pdf = render_case_pdf_report(document)
    _handle_case_errors("record_report", lambda: service.record_case_report(case_id, "pdf"))
    logger.info(
        "case report generated: case_id=%s format=pdf bytes=%d duration_ms=%d",
        case_id,
        len(pdf),
        int((time.monotonic() - started) * 1000),
    )
    case_number = str(document.get("report", {}).get("case_number") or "case")
    return Response(
        content=pdf,
        media_type="application/pdf",
        headers={
            "Content-Disposition": (
                f'attachment; filename="{_case_report_filename(case_number, "pdf")}"'
            )
        },
    )


# -- export / bundle / import ---------------------------------------------------------------


@router.get("/{case_id}/export", summary="Download the versioned case export (JSON)")
def export_case(case_id: str, request: Request) -> Response:
    started = time.monotonic()
    _require_case_path(case_id)
    service = _cases(request)
    document = _handle_case_errors("case_export", lambda: service.build_export(case_id))
    body = case_report_to_json(document)
    _handle_case_errors("record_export", lambda: service.record_export(case_id))
    logger.info(
        "case exported: case_id=%s bytes=%d duration_ms=%d",
        case_id,
        len(body),
        int((time.monotonic() - started) * 1000),
    )
    case_number = str((document.get("case") or {}).get("case_number") or "case")
    return Response(
        content=body,
        media_type="application/json",
        headers={
            "Content-Disposition": (
                f'attachment; filename="{_case_report_filename(case_number, "case")}.json"'
            )
        },
    )


@router.get("/{case_id}/bundle", summary="Download the reproducible case bundle (zip)")
def download_bundle(case_id: str, request: Request, include_evidence: bool = False) -> Response:
    started = time.monotonic()
    _require_case_path(case_id)
    service = _cases(request)
    bundle = _handle_case_errors(
        "case_bundle", lambda: service.build_bundle(case_id, include_evidence=include_evidence)
    )
    _handle_case_errors("record_export", lambda: service.record_export(case_id))
    logger.info(
        "case bundle generated: case_id=%s bytes=%d include_evidence=%s duration_ms=%d",
        case_id,
        len(bundle),
        include_evidence,
        int((time.monotonic() - started) * 1000),
    )
    return Response(
        content=bundle,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{case_id}-bundle.zip"'},
    )


@router.post("/import", response_model=CaseResponse, summary="Import a case metadata bundle")
def import_case(request: Request, body: dict[str, Any]) -> Any:
    service = _cases(request)
    try:
        record, _summary = service.import_case(body)
    except CaseValidationError as error:
        raise ApiError(ERROR_INVALID_REQUEST, str(error), 422) from error
    logger.info("case imported: case_id=%s", record.case_id)
    return _case_out(record)
