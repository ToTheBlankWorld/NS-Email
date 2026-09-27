"""Forensic report endpoints (Stage 9): deterministic JSON, HTML, and PDF.

Reports are generated on demand from persisted evidence — never stored as
blobs. Every renderer consumes the same deterministic report document, so
the three formats always agree.
"""

import re
from typing import Any

from fastapi import APIRouter, Request, Response

from app.api_models import AnalysisInfo, CaptureResponse, FindingResponse, SessionResponse
from app.errors import (
    ERROR_CAPTURE_NOT_FOUND,
    ERROR_POSTURE_NOT_AVAILABLE,
    ApiError,
)
from app.services.report_builder import ReportInputs, build_report, report_to_json
from app.services.report_html import render_html_report
from app.services.report_pdf import render_pdf_report

router = APIRouter(prefix="/api/captures", tags=["reports"])

_CAPTURE_ID_PATTERN = re.compile(r"^capture_[0-9a-f]{12}$")


def _analysis(request: Request) -> Any:
    service = getattr(request.app.state, "analysis_service", None)
    if service is None:  # pragma: no cover - wiring invariant
        raise RuntimeError("analysis service is not configured")
    return service


def _ingestion(request: Request) -> Any:
    service = getattr(request.app.state, "ingestion_service", None)
    if service is None:  # pragma: no cover - wiring invariant
        raise RuntimeError("ingestion service is not configured")
    return service


def _store(request: Request) -> Any:
    store = getattr(request.app.state, "session_store", None)
    if store is None:  # pragma: no cover - wiring invariant
        raise RuntimeError("session store is not configured")
    return store


def _require_capture_id(capture_id: str) -> str:
    if not _CAPTURE_ID_PATTERN.fullmatch(capture_id):
        raise ApiError(ERROR_CAPTURE_NOT_FOUND, "no capture exists with this id", 404)
    return capture_id


def _build_report_document(capture_id: str, request: Request) -> dict[str, Any]:
    """Assemble the deterministic report document from persisted evidence."""
    analysis = _analysis(request)
    capture = _ingestion(request).get_capture(capture_id)
    if capture is None:
        raise ApiError(ERROR_CAPTURE_NOT_FOUND, "no capture exists with this id", 404)
    record = analysis.analysis_status(capture_id)
    if record.status != "completed":
        raise ApiError(
            ERROR_POSTURE_NOT_AVAILABLE,
            "no report exists for this capture; run analysis first",
            404,
        )

    sessions = [
        SessionResponse.from_session(session).model_dump(mode="json")
        for session in analysis.sessions_for(capture_id)
    ]
    findings = [
        FindingResponse.from_finding(finding).model_dump(mode="json")
        for finding in analysis.findings_for_capture(capture_id)
    ]

    anomaly_items = analysis.anomalies_for_capture(capture_id)
    anomaly_summary = analysis.anomaly_summary(capture_id)
    anomalies_payload: dict[str, Any] | None = None
    if anomaly_items or anomaly_summary is not None:
        anomalies_payload = {"anomalies": anomaly_items, "summary": anomaly_summary}

    graph = analysis.graph(capture_id)
    graph_nodes, graph_edges = graph if graph else ([], [])

    ai_history = _store(request).list_ai_history(capture_id)
    ai_service = getattr(request.app.state, "ai_service", None)
    ai_provider = getattr(ai_service, "_provider", None) if ai_service else None

    inputs = ReportInputs(
        capture=CaptureResponse.from_capture(
            capture, analysis=AnalysisInfo.from_record(record)
        ).model_dump(mode="json"),
        analysis_status=record.status,
        analyzed_at=record.analyzed_at.isoformat() if record.analyzed_at else None,
        sessions=sessions,
        findings=findings,
        posture=analysis.posture_snapshot(capture_id),
        anomalies=anomalies_payload,
        graph_nodes=graph_nodes,
        graph_edges=graph_edges,
        ai_history=ai_history,
        ai_configured=ai_provider is not None,
        ai_provider=ai_provider.provider_name if ai_provider else "",
        ai_model=ai_provider.model_name if ai_provider else "",
        application_version=request.app.state.settings.app_version,
    )
    return build_report(inputs)


def _report_filename(capture_id: str, extension: str) -> str:
    return f"securemailscope-report-{capture_id}.{extension}"


@router.get("/{capture_id}/report.json", summary="Deterministic JSON forensic report")
def get_json_report(capture_id: str, request: Request) -> Response:
    _require_capture_id(capture_id)
    document = _build_report_document(capture_id, request)
    return Response(
        content=report_to_json(document),
        media_type="application/json",
        headers={
            "Content-Disposition": (
                f'attachment; filename="{_report_filename(capture_id, "json")}"'
            )
        },
    )


@router.get("/{capture_id}/report.html", summary="Standalone HTML forensic report")
def get_html_report(capture_id: str, request: Request) -> Response:
    _require_capture_id(capture_id)
    document = _build_report_document(capture_id, request)
    return Response(
        content=render_html_report(document),
        media_type="text/html; charset=utf-8",
        headers={
            "Content-Disposition": (
                f'attachment; filename="{_report_filename(capture_id, "html")}"'
            )
        },
    )


@router.get("/{capture_id}/report.pdf", summary="PDF forensic report")
def get_pdf_report(capture_id: str, request: Request) -> Response:
    _require_capture_id(capture_id)
    document = _build_report_document(capture_id, request)
    return Response(
        content=render_pdf_report(document),
        media_type="application/pdf",
        headers={
            "Content-Disposition": (f'attachment; filename="{_report_filename(capture_id, "pdf")}"')
        },
    )
