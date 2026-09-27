"""Public API response models.

These models define exactly what leaves the server: capture metadata and
inspection capability state, never internal storage paths or tool internals.
"""

from datetime import datetime

from engine.core.capture import Capture, CaptureStatus
from engine.ingestion.inspector import InspectionStatus
from pydantic import BaseModel, Field

from app.services.ingestion import IngestionResult


class InspectionInfo(BaseModel):
    """Packet-inspection capability state for one capture."""

    status: InspectionStatus
    tool: str | None = None
    tool_version: str | None = None
    message: str | None = None
    warnings: list[str] = Field(default_factory=list)


class CaptureResponse(BaseModel):
    """A registered capture as exposed by the API."""

    id: str
    filename: str
    format: str
    size_bytes: int
    sha256: str
    status: CaptureStatus
    duplicate: bool = False
    packet_count: int | None = None
    started_at: datetime | None = None
    ended_at: datetime | None = None
    duration_seconds: float | None = None
    link_type: str | None = None
    ingested_at: datetime
    inspection: InspectionInfo

    @classmethod
    def from_capture(cls, capture: Capture, *, duplicate: bool = False) -> "CaptureResponse":
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
