"""Capture ingestion, analysis, and retrieval endpoints."""

import re
from typing import Annotated

from engine.ingestion.errors import CaptureStorageError
from fastapi import APIRouter, File, Request, Response, UploadFile

from app.api_models import (
    AnalysisInfo,
    AnalysisResultResponse,
    CaptureResponse,
    SessionResponse,
)
from app.errors import (
    ERROR_CAPTURE_NOT_FOUND,
    ERROR_CAPTURE_PROCESSING,
    ApiError,
)
from app.services.analysis import CaptureAnalysisService, CaptureNotFoundError
from app.services.ingestion import CaptureIngestionService

router = APIRouter(prefix="/api/captures", tags=["captures"])

# Capture ids are hash-derived; anything else is unknown by definition and
# can never address the filesystem.
_CAPTURE_ID_PATTERN = re.compile(r"^capture_[0-9a-f]{12}$")


def _ingestion(request: Request) -> CaptureIngestionService:
    service: CaptureIngestionService | None = getattr(request.app.state, "ingestion_service", None)
    if service is None:  # pragma: no cover - wiring invariant
        raise RuntimeError("ingestion service is not configured")
    return service


def _analysis(request: Request) -> CaptureAnalysisService:
    service: CaptureAnalysisService | None = getattr(request.app.state, "analysis_service", None)
    if service is None:  # pragma: no cover - wiring invariant
        raise RuntimeError("analysis service is not configured")
    return service


def _require_capture_id(capture_id: str) -> str:
    if not _CAPTURE_ID_PATTERN.fullmatch(capture_id):
        raise ApiError(ERROR_CAPTURE_NOT_FOUND, "no capture exists with this id", 404)
    return capture_id


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
    result = _ingestion(request).ingest(filename=file.filename or "", source=file.file)
    response.status_code = 200 if result.duplicate else 201
    return CaptureResponse.from_result(result)


@router.get("", response_model=list[CaptureResponse], summary="List registered captures")
def list_captures(request: Request) -> list[CaptureResponse]:
    analysis = _analysis(request)
    return [
        CaptureResponse.from_capture(
            capture,
            analysis=AnalysisInfo.from_record(analysis.analysis_status(capture.id)),
        )
        for capture in _ingestion(request).list_captures()
    ]


@router.get("/{capture_id}", response_model=CaptureResponse, summary="Get one capture")
def get_capture(capture_id: str, request: Request) -> CaptureResponse:
    _require_capture_id(capture_id)
    capture = _ingestion(request).get_capture(capture_id)
    if capture is None:
        raise ApiError(ERROR_CAPTURE_NOT_FOUND, "no capture exists with this id", 404)
    return CaptureResponse.from_capture(
        capture,
        analysis=AnalysisInfo.from_record(_analysis(request).analysis_status(capture_id)),
    )


@router.post(
    "/{capture_id}/analyze",
    response_model=AnalysisResultResponse,
    summary="Analyze a registered capture",
)
def analyze_capture(capture_id: str, request: Request) -> AnalysisResultResponse:
    """Reconstruct TCP sessions and email protocol evidence for a capture.

    Re-analysis replaces previous results. Runs synchronously; captures
    are size-capped, so this is bounded work.
    """
    _require_capture_id(capture_id)
    analysis = _analysis(request)
    try:
        status, session_count = analysis.analyze(capture_id)
    except CaptureNotFoundError as error:
        raise ApiError(ERROR_CAPTURE_NOT_FOUND, str(error), 404) from error
    except CaptureStorageError as error:
        raise ApiError(ERROR_CAPTURE_PROCESSING, "analysis failed on the server", 500) from error
    record = analysis.analysis_status(capture_id)
    return AnalysisResultResponse(
        capture_id=capture_id,
        status=status,
        sessions_found=session_count,
        error_code=record.error_code,
        error_message=record.error_message,
    )


@router.get(
    "/{capture_id}/sessions",
    response_model=list[SessionResponse],
    summary="List reconstructed sessions for a capture",
)
def list_capture_sessions(capture_id: str, request: Request) -> list[SessionResponse]:
    _require_capture_id(capture_id)
    if _ingestion(request).get_capture(capture_id) is None:
        raise ApiError(ERROR_CAPTURE_NOT_FOUND, "no capture exists with this id", 404)
    return [
        SessionResponse.from_session(session, include_events=False)
        for session in _analysis(request).sessions_for(capture_id)
    ]
