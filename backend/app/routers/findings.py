"""Findings retrieval endpoints."""

import re

from fastapi import APIRouter, Request

from app.api_models import FindingResponse
from app.errors import ERROR_FINDING_NOT_FOUND, ApiError
from app.services.analysis import CaptureAnalysisService

router = APIRouter(prefix="/api/findings", tags=["findings"])

_FINDING_ID_PATTERN = re.compile(r"^finding_[0-9a-f]{12}$")


def _analysis(request: Request) -> CaptureAnalysisService:
    service: CaptureAnalysisService | None = getattr(request.app.state, "analysis_service", None)
    if service is None:  # pragma: no cover - wiring invariant
        raise RuntimeError("analysis service is not configured")
    return service


@router.get("/{finding_id}", response_model=FindingResponse, summary="Get one finding")
def get_finding(finding_id: str, request: Request) -> FindingResponse:
    if not _FINDING_ID_PATTERN.fullmatch(finding_id):
        raise ApiError(ERROR_FINDING_NOT_FOUND, "no finding exists with this id", 404)
    finding = _analysis(request).finding(finding_id)
    if finding is None:
        raise ApiError(ERROR_FINDING_NOT_FOUND, "no finding exists with this id", 404)
    return FindingResponse.from_finding(finding)
