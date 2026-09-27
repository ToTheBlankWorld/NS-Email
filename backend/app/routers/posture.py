"""Posture retrieval endpoints (Stage 5).

All posture data is read from the persisted snapshot that analysis
produced — never recomputed from frontend logic.
"""

import re
from typing import Any

from fastapi import APIRouter, Request

from app.api_models import FindingResponse
from app.errors import ERROR_POSTURE_NOT_AVAILABLE, ApiError
from app.services.analysis import CaptureAnalysisService

router = APIRouter(prefix="/api/captures", tags=["posture"])

_CAPTURE_ID_PATTERN = re.compile(r"^capture_[0-9a-f]{12}$")
_HOST_ID_PATTERN = re.compile(r"^host_[0-9a-f]{12}$")


def _analysis(request: Request) -> CaptureAnalysisService:
    service: CaptureAnalysisService | None = getattr(request.app.state, "analysis_service", None)
    if service is None:  # pragma: no cover - wiring invariant
        raise RuntimeError("analysis service is not configured")
    return service


def _require_capture_id(capture_id: str) -> str:
    if not _CAPTURE_ID_PATTERN.fullmatch(capture_id):
        raise ApiError(ERROR_POSTURE_NOT_AVAILABLE, "no capture exists with this id", 404)
    return capture_id


def _snapshot_or_404(request: Request, capture_id: str) -> dict[str, Any]:
    snapshot = _analysis(request).posture_snapshot(capture_id)
    if snapshot is None:
        raise ApiError(
            ERROR_POSTURE_NOT_AVAILABLE,
            "no posture snapshot exists for this capture; run analysis first",
            404,
        )
    return snapshot


@router.get("/{capture_id}/posture", summary="Explainable security posture")
def get_posture(capture_id: str, request: Request) -> dict[str, Any]:
    """Return the full explainable posture snapshot for one capture."""
    _require_capture_id(capture_id)
    snapshot: dict[str, Any] = _snapshot_or_404(request, capture_id)
    return snapshot


@router.get("/{capture_id}/hosts", summary="Observed hosts with posture context")
def list_hosts(capture_id: str, request: Request) -> list[dict[str, Any]]:
    _require_capture_id(capture_id)
    snapshot: dict[str, Any] = _snapshot_or_404(request, capture_id)
    hosts: list[dict[str, Any]] = snapshot.get("hosts", [])
    return hosts


@router.get(
    "/{capture_id}/hosts/{host_id}",
    summary="One host with sessions, findings, and posture factors",
)
def get_host(capture_id: str, host_id: str, request: Request) -> dict[str, Any]:
    _require_capture_id(capture_id)
    if not _HOST_ID_PATTERN.fullmatch(host_id):
        raise ApiError(ERROR_POSTURE_NOT_AVAILABLE, "no host exists with this id", 404)
    snapshot = _snapshot_or_404(request, capture_id)
    host = next((h for h in snapshot.get("hosts", []) if h["host_id"] == host_id), None)
    if host is None:
        raise ApiError(ERROR_POSTURE_NOT_AVAILABLE, "no host exists with this id", 404)

    session_service = _analysis(request)
    host_sessions = [
        session
        for session in session_service.sessions_for(capture_id)
        if str(session.server_ip) == host["ip"]
    ]
    host_findings = [
        finding
        for finding in session_service.findings_for_capture(capture_id)
        if finding.session_id in {s.id for s in host_sessions}
    ]
    return {
        "host": host,
        "sessions": [
            {
                "id": session.id,
                "protocol": session.protocol.value if session.protocol else None,
                "client_ip": str(session.client_ip),
                "client_port": session.client_port,
                "server_port": session.server_port,
                "started_at": session.started_at,
                "duration_seconds": session.duration_seconds,
                "complete": session.complete,
            }
            for session in host_sessions
        ],
        "findings": [
            FindingResponse.from_finding(finding).model_dump(mode="json")
            for finding in host_findings
        ],
        "factors": snapshot.get("factors", []),
    }


@router.get(
    "/{capture_id}/posture/protocols",
    summary="Posture aggregated per email protocol",
)
def get_protocol_posture(capture_id: str, request: Request) -> list[dict[str, Any]]:
    _require_capture_id(capture_id)
    snapshot: dict[str, Any] = _snapshot_or_404(request, capture_id)
    protocols: list[dict[str, Any]] = snapshot.get("protocols", [])
    return protocols


@router.get(
    "/{capture_id}/priorities",
    summary="Findings ordered by the deterministic priority model",
)
def get_priorities(capture_id: str, request: Request) -> list[dict[str, Any]]:
    _require_capture_id(capture_id)
    snapshot: dict[str, Any] = _snapshot_or_404(request, capture_id)
    priorities: list[dict[str, Any]] = snapshot.get("priorities", [])
    return priorities
