"""Anomaly retrieval endpoints (Stage 6)."""

import re
from typing import Any

from fastapi import APIRouter, Request

from app.errors import ERROR_ANOMALY_NOT_AVAILABLE, ApiError
from app.services.analysis import CaptureAnalysisService

router = APIRouter(prefix="/api", tags=["anomalies"])

_CAPTURE_ID_PATTERN = re.compile(r"^capture_[0-9a-f]{12}$")
_ANOMALY_ID_PATTERN = re.compile(r"^anomaly_[0-9a-f]{12}$")


def _analysis(request: Request) -> CaptureAnalysisService:
    service: CaptureAnalysisService | None = getattr(request.app.state, "analysis_service", None)
    if service is None:  # pragma: no cover - wiring invariant
        raise RuntimeError("analysis service is not configured")
    return service


@router.get(
    "/captures/{capture_id}/anomalies",
    summary="Behavioral anomaly results for all evaluated sessions",
)
def list_capture_anomalies(capture_id: str, request: Request) -> list[dict[str, Any]]:
    if not _CAPTURE_ID_PATTERN.fullmatch(capture_id):
        raise ApiError(ERROR_ANOMALY_NOT_AVAILABLE, "no capture exists with this id", 404)
    return _analysis(request).anomalies_for_capture(capture_id)


@router.get(
    "/captures/{capture_id}/anomaly-summary",
    summary="Anomaly band summary counts",
)
def get_anomaly_summary(capture_id: str, request: Request) -> dict[str, int]:
    if not _CAPTURE_ID_PATTERN.fullmatch(capture_id):
        raise ApiError(ERROR_ANOMALY_NOT_AVAILABLE, "no capture exists with this id", 404)
    summary = _analysis(request).anomaly_summary(capture_id)
    if summary is None:
        raise ApiError(ERROR_ANOMALY_NOT_AVAILABLE, "no anomaly analysis for this capture", 404)
    return summary


@router.get(
    "/sessions/{session_id}/anomaly",
    summary="Behavioral anomaly analysis for one session",
)
def get_session_anomaly(session_id: str, request: Request) -> dict[str, Any]:
    anomaly = _analysis(request).anomaly_for_session(session_id)
    if anomaly is None:
        raise ApiError(ERROR_ANOMALY_NOT_AVAILABLE, "no anomaly exists for this session", 404)
    return anomaly


@router.get(
    "/anomalies/{anomaly_id}",
    summary="One anomaly result with deviations and evidence",
)
def get_anomaly(anomaly_id: str, request: Request) -> dict[str, Any]:
    if not _ANOMALY_ID_PATTERN.fullmatch(anomaly_id):
        raise ApiError(ERROR_ANOMALY_NOT_AVAILABLE, "no anomaly exists with this id", 404)
    anomaly = _analysis(request).anomaly_result(anomaly_id)
    if anomaly is None:
        raise ApiError(ERROR_ANOMALY_NOT_AVAILABLE, "no anomaly exists with this id", 404)
    return anomaly
