"""Session retrieval endpoints."""

import re

from fastapi import APIRouter, Request

from app.api_models import SessionResponse
from app.errors import ERROR_SESSION_NOT_FOUND, ApiError
from app.services.analysis import CaptureAnalysisService

router = APIRouter(prefix="/api/sessions", tags=["sessions"])

# Session ids are flow-derived; anything else is unknown by definition.
_SESSION_ID_PATTERN = re.compile(r"^session_[0-9a-f]{16}$")


def _analysis(request: Request) -> CaptureAnalysisService:
    service: CaptureAnalysisService | None = getattr(request.app.state, "analysis_service", None)
    if service is None:  # pragma: no cover - wiring invariant
        raise RuntimeError("analysis service is not configured")
    return service


@router.get("/{session_id}", response_model=SessionResponse, summary="Get one session")
def get_session(session_id: str, request: Request) -> SessionResponse:
    if not _SESSION_ID_PATTERN.fullmatch(session_id):
        raise ApiError(ERROR_SESSION_NOT_FOUND, "no session exists with this id", 404)
    session = _analysis(request).session(session_id)
    if session is None:
        raise ApiError(ERROR_SESSION_NOT_FOUND, "no session exists with this id", 404)
    return SessionResponse.from_session(session)
