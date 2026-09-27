"""Public API response models.

These models define exactly what leaves the server: capture metadata,
analysis results, and inspection capability state — never internal
storage paths, raw payloads, or credential values.
"""

from datetime import datetime

from engine.core.capture import Capture, CaptureStatus
from engine.core.events import SessionEvent
from engine.core.session import (
    Confidence,
    EmailProtocol,
    Orientation,
    Session,
)
from engine.ingestion.inspector import InspectionStatus
from pydantic import BaseModel, Field

from app.services.ingestion import IngestionResult
from app.store import AnalysisRecord


class InspectionInfo(BaseModel):
    """Packet-inspection capability state for one capture."""

    status: InspectionStatus
    tool: str | None = None
    tool_version: str | None = None
    message: str | None = None
    warnings: list[str] = Field(default_factory=list)


class AnalysisInfo(BaseModel):
    """Session-analysis status for one capture."""

    status: str  # not_analyzed | completed | failed
    analyzed_at: datetime | None = None
    session_count: int = 0
    error_code: str | None = None
    error_message: str | None = None
    warnings: list[str] = Field(default_factory=list)

    @classmethod
    def from_record(cls, record: AnalysisRecord) -> "AnalysisInfo":
        return cls(
            status=record.status,
            analyzed_at=record.analyzed_at,
            session_count=record.session_count,
            error_code=record.error_code,
            error_message=record.error_message,
            warnings=record.warnings,
        )


class CaptureResponse(BaseModel):
    """A registered capture as exposed by the API."""

    id: str
    filename: str
    format: str
    size_bytes: int
    sha256: str
    status: str
    duplicate: bool = False
    packet_count: int | None = None
    started_at: datetime | None = None
    ended_at: datetime | None = None
    duration_seconds: float | None = None
    link_type: str | None = None
    ingested_at: datetime
    inspection: InspectionInfo
    analysis: AnalysisInfo | None = None

    @classmethod
    def from_capture(
        cls,
        capture: Capture,
        *,
        duplicate: bool = False,
        analysis: AnalysisInfo | None = None,
    ) -> "CaptureResponse":
        inspected = capture.status is CaptureStatus.READY
        return cls(
            id=capture.id,
            filename=capture.filename,
            format=capture.format.value,
            size_bytes=capture.size_bytes,
            sha256=capture.sha256,
            status=capture.status,
            duplicate=duplicate,
            packet_count=capture.packet_count,
            started_at=capture.capture_started_at,
            ended_at=capture.capture_ended_at,
            duration_seconds=capture.duration_seconds,
            link_type=capture.link_type,
            ingested_at=capture.ingested_at,
            inspection=InspectionInfo(
                status=InspectionStatus.INSPECTED if inspected else InspectionStatus.UNAVAILABLE,
                tool=capture.inspector_tool,
                tool_version=capture.inspector_version,
                message=None if inspected else "packet metadata not available for this capture",
                warnings=capture.warnings,
            ),
            analysis=analysis,
        )

    @classmethod
    def from_result(cls, result: IngestionResult) -> "CaptureResponse":
        """Build the response for a fresh ingestion, preserving live inspection info."""
        response = cls.from_capture(result.capture, duplicate=result.duplicate)
        return response.model_copy(
            update={
                "inspection": InspectionInfo(
                    status=result.inspection.status,
                    tool=result.inspection.tool,
                    tool_version=result.inspection.tool_version,
                    message=result.inspection.message,
                    warnings=result.inspection.warnings,
                )
            }
        )


class AnalysisResultResponse(BaseModel):
    """Result of requesting analysis for one capture."""

    capture_id: str
    status: str  # completed | failed
    sessions_found: int
    error_code: str | None = None
    error_message: str | None = None


class StarttlsInfo(BaseModel):
    advertised: bool = False
    requested: bool = False
    response_seen: bool = False
    packet_number: int | None = None
    timestamp: datetime | None = None


class SessionEventOut(BaseModel):
    seq: int
    type: str
    direction: str
    timestamp: datetime | None = None
    packet_numbers: list[int] = Field(default_factory=list)
    detail: dict[str, str] = Field(default_factory=dict)


class SessionResponse(BaseModel):
    """A reconstructed session (detail view includes the event timeline)."""

    id: str
    capture_id: str
    protocol: EmailProtocol | None = None
    confidence: Confidence
    orientation: Orientation
    client_ip: str
    client_port: int
    server_ip: str
    server_port: int
    implicit_tls: bool | None = None
    started_at: datetime | None = None
    ended_at: datetime | None = None
    duration_seconds: float | None = None
    packet_count: int
    bytes_client_to_server: int
    bytes_server_to_client: int
    complete: bool
    completeness_reason: str | None = None
    retransmissions: int
    gap_count: int
    gap_bytes: int
    starttls: StarttlsInfo | None = None
    warnings: list[str] = Field(default_factory=list)
    events: list[SessionEventOut] = Field(default_factory=list)

    @classmethod
    def from_session(cls, session: Session, *, include_events: bool = True) -> "SessionResponse":
        starttls = session.starttls
        return cls(
            id=session.id,
            capture_id=session.capture_id,
            protocol=session.protocol,
            confidence=session.confidence,
            orientation=session.orientation,
            client_ip=str(session.client_ip),
            client_port=session.client_port,
            server_ip=str(session.server_ip),
            server_port=session.server_port,
            implicit_tls=session.implicit_tls,
            started_at=session.started_at,
            ended_at=session.ended_at,
            duration_seconds=session.duration_seconds,
            packet_count=session.packet_count,
            bytes_client_to_server=session.bytes_client_to_server,
            bytes_server_to_client=session.bytes_server_to_client,
            complete=session.complete,
            completeness_reason=session.completeness_reason,
            retransmissions=session.retransmissions,
            gap_count=session.gap_count,
            gap_bytes=session.gap_bytes,
            starttls=StarttlsInfo(
                advertised=starttls.advertised,
                requested=starttls.requested,
                response_seen=starttls.response_seen,
                packet_number=starttls.packet_number,
                timestamp=starttls.timestamp,
            )
            if starttls
            else None,
            warnings=session.warnings,
            events=[_event_out(event) for event in session.events] if include_events else [],
        )


def _event_out(event: SessionEvent) -> SessionEventOut:
    return SessionEventOut(
        seq=event.seq,
        type=event.type.value,
        direction=event.direction.value,
        timestamp=event.timestamp,
        packet_numbers=event.packet_numbers,
        detail=event.detail,
    )
