"""Capture ingestion and retrieval endpoints."""

import re
from typing import Annotated

from fastapi import APIRouter, File, Request, Response, UploadFile

from app.api_models import CaptureResponse
from app.errors import ERROR_CAPTURE_NOT_FOUND, ApiError
from app.services.ingestion import CaptureIngestionService

router = APIRouter(prefix="/api/captures", tags=["captures"])

# Capture ids are hash-derived; anything else is unknown by definition and
# can never address the filesystem.
_CAPTURE_ID_PATTERN = re.compile(r"^capture_[0-9a-f]{12}$")


def _service(request: Request) -> CaptureIngestionService:
    service: CaptureIngestionService | None = getattr(request.app.state, "ingestion_service", None)
    if service is None:  # pragma: no cover - wiring invariant
        raise RuntimeError("ingestion service is not configured")
    return service


@router.post("", response_model=CaptureResponse, summary="Ingest a PCAP/PCAPNG capture")
def upload_capture(
    request: Request,
    response: Response,
    file: Annotated[UploadFile, File(description="PCAP or PCAPNG capture file")],
) -> CaptureResponse:
    """Validate, hash, store, and register one capture.

    Re-uploading identical evidence returns the existing capture with
    ``duplicate: true`` (HTTP 200) — evidence identity is the content hash.
    """
    result = _service(request).ingest(filename=file.filename or "", source=file.file)
    response.status_code = 200 if result.duplicate else 201
    return CaptureResponse.from_result(result)


@router.get("", response_model=list[CaptureResponse], summary="List registered captures")
def list_captures(request: Request) -> list[CaptureResponse]:
    return [CaptureResponse.from_capture(capture) for capture in _service(request).list_captures()]


@router.get("/{capture_id}", response_model=CaptureResponse, summary="Get one capture")
def get_capture(capture_id: str, request: Request) -> CaptureResponse:
    if not _CAPTURE_ID_PATTERN.fullmatch(capture_id):
        raise ApiError(ERROR_CAPTURE_NOT_FOUND, "no capture exists with this id", 404)
    capture = _service(request).get_capture(capture_id)
    if capture is None:
        raise ApiError(ERROR_CAPTURE_NOT_FOUND, "no capture exists with this id", 404)
    return CaptureResponse.from_capture(capture)
