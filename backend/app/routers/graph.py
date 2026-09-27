"""Evidence graph and investigation context API endpoints (Stage 7)."""

import re
from typing import Any

from fastapi import APIRouter, Query, Request

from app.errors import ERROR_POSTURE_NOT_AVAILABLE, ApiError
from app.services.analysis import CaptureAnalysisService

router = APIRouter(prefix="/api", tags=["graph"])

_CAPTURE_ID_PATTERN = re.compile(r"^capture_[0-9a-f]{12}$")
_SESSION_ID_PATTERN = re.compile(r"^session_[0-9a-f]{16}$")


def _analysis(request: Request) -> CaptureAnalysisService:
    service: CaptureAnalysisService | None = getattr(request.app.state, "analysis_service", None)
    if service is None:  # pragma: no cover - wiring invariant
        raise RuntimeError("analysis service is not configured")
    return service


def _require_capture_id(capture_id: str) -> str:
    if not _CAPTURE_ID_PATTERN.fullmatch(capture_id):
        raise ApiError(ERROR_POSTURE_NOT_AVAILABLE, "no capture exists with this id", 404)
    return capture_id


@router.get(
    "/captures/{capture_id}/graph",
    summary="Evidence graph nodes and edges",
)
def get_graph(
    capture_id: str,
    request: Request,
    node_type: str = Query(default=""),
    protocol: str = Query(default=""),
) -> dict[str, Any]:
    """Return the evidence graph (nodes + edges) for one capture."""
    _require_capture_id(capture_id)
    graph = _analysis(request).graph(capture_id)
    if graph is None:
        raise ApiError(
            ERROR_POSTURE_NOT_AVAILABLE,
            "no graph exists for this capture; run analysis first",
            404,
        )
    nodes, edges = graph
    if node_type:
        nodes = [n for n in nodes if n["node_type"] == node_type]
    if protocol:
        node_ids = {
            n["node_id"]
            for n in nodes
            if n.get("metadata", {}).get("protocol", "").lower() == protocol.lower()
        }
        edges = [
            e for e in edges if e["source_node_id"] in node_ids or e["target_node_id"] in node_ids
        ]
    return {"capture_id": capture_id, "nodes": nodes, "edges": edges}


@router.get(
    "/sessions/{session_id}/context",
    summary="Combined investigation context for one session",
)
def get_session_context(session_id: str, request: Request) -> dict[str, Any]:
    """Return the structured investigation context consumed by the future AI layer."""
    if not re.fullmatch(r"session_[0-9a-f]{16}", session_id):
        raise ApiError(ERROR_POSTURE_NOT_AVAILABLE, "no session exists with this id", 404)
    analysis = _analysis(request)
    session = analysis.session(session_id)
    if session is None:
        raise ApiError(ERROR_POSTURE_NOT_AVAILABLE, "no session exists with this id", 404)

    findings = analysis.findings_for_session(session_id)
    anomaly = analysis.anomaly_for_session(session_id)
    all_sessions = analysis.sessions_for(session.capture_id)
    all_findings = analysis.findings_for_capture(session.capture_id)

    from engine.graph.builder import build_investigation_context

    context = build_investigation_context(
        session,
        findings,
        [anomaly] if anomaly else [],
        [f.factor for f in (analysis.posture_snapshot(session.capture_id) or {}).get("factors", [])]
        if analysis.posture_snapshot(session.capture_id)
        else [],
        all_sessions,
        all_findings,
    )

    from app.services.graph_serializer import context_to_payload

    return context_to_payload(context)
