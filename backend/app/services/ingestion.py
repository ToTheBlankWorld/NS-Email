"""Capture evidence ingestion orchestration.

Pipeline: validate display filename → stream to staging (hash + size
enforcement in one pass) → sniff container magic → derive deterministic
capture id → duplicate check by SHA-256 → atomic move into evidence
storage → optional packet inspection → registry registration.

The service never constructs filesystem paths from the upload filename
and never invokes subprocesses itself.
"""

import hashlib
import json
import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from engine.core.capture import Capture, CaptureStatus
from engine.ingestion.errors import (
    CaptureIngestionError,
    CaptureStorageError,
    CaptureTooLargeError,
    DuplicateCaptureError,
    InvalidCaptureError,
)
from engine.ingestion.evidence import derive_capture_id
from engine.ingestion.formats import SNIFF_HEADER_BYTES, sniff_capture_format
from engine.ingestion.inspector import (
    CaptureInspection,
    CaptureInspector,
    InspectionStatus,
)
from engine.ingestion.validation import validate_display_filename

from app.registry import CaptureRegistry
from app.storage import CaptureStorage

logger = logging.getLogger("ns_email.ingestion")

_HASH_CHUNK_SIZE = 1024 * 1024


@dataclass(frozen=True)
class IngestionResult:
    """Outcome of one ingestion request."""

    capture: Capture
    inspection: CaptureInspection
    duplicate: bool


def _copy_hash_and_header(
    staged: BinaryIO, source: BinaryIO, max_capture_bytes: int
) -> tuple[str, int, bytes]:
    """Stream the upload to staging while hashing and sniffing.

    Single pass: constant memory, size enforced during the copy so an
    oversized upload is aborted before it finishes writing.
    """
    digest = hashlib.sha256()
    size = 0
    header = b""
    while chunk := source.read(_HASH_CHUNK_SIZE):
        size += len(chunk)
        if size > max_capture_bytes:
            raise CaptureTooLargeError(
                f"capture exceeds the configured limit of {max_capture_bytes} bytes"
            )
        if len(header) < SNIFF_HEADER_BYTES:
            header += chunk[: SNIFF_HEADER_BYTES - len(header)]
        digest.update(chunk)
        staged.write(chunk)
    return digest.hexdigest(), size, header


class CaptureIngestionService:
    """Registers capture evidence: validate → hash → store → inspect → record."""

    def __init__(
        self,
        storage: CaptureStorage,
        registry: CaptureRegistry,
        inspector: CaptureInspector | None,
        max_capture_bytes: int,
    ) -> None:
        self._storage = storage
        self._registry = registry
        self._inspector = inspector
        self._max_capture_bytes = max_capture_bytes

    def ingest(self, filename: str, source: BinaryIO) -> IngestionResult:
        """Ingest one upload; raises CaptureIngestionError subclasses on failure."""
        display_name = validate_display_filename(filename)
        fd, staging_path = self._storage.create_staging_file()
        try:
            with os.fdopen(fd, "wb") as staged:
                sha256, size, header = _copy_hash_and_header(
                    staged, source, self._max_capture_bytes
                )
            if size == 0:
                raise InvalidCaptureError("uploaded capture is empty")
            detected_format = sniff_capture_format(header)
            if detected_format is None:
                raise InvalidCaptureError(
                    "file is not a pcap/pcapng capture (unrecognized magic bytes)"
                )

            existing = self._registry.get_by_sha256(sha256)
            if existing is not None:
                self._storage.discard_staging(staging_path)
                logger.info("duplicate evidence accepted: %s", existing.id)
                return IngestionResult(
                    capture=existing,
                    inspection=_inspection_from_capture(existing),
                    duplicate=True,
                )

            capture_id = derive_capture_id(sha256)
            evidence_path = self._storage.store_evidence(
                staging_path, capture_id, detected_format.value
            )
            try:
                inspection = self._run_inspection(evidence_path)
            except InvalidCaptureError:
                self._storage.discard_capture(capture_id)
                raise

            capture = Capture(
                id=capture_id,
                filename=display_name,
                size_bytes=size,
                sha256=sha256,
                format=detected_format,
                status=(
                    CaptureStatus.READY
                    if inspection.status is InspectionStatus.INSPECTED
                    else CaptureStatus.REGISTERED
                ),
                packet_count=inspection.packet_count,
                capture_started_at=inspection.first_packet_at,
                capture_ended_at=inspection.last_packet_at,
                duration_seconds=inspection.duration_seconds,
                link_type=inspection.link_type,
                inspector_tool=inspection.tool,
                inspector_version=inspection.tool_version,
                warnings=inspection.warnings,
            )
            try:
                self._registry.add(capture)
            except DuplicateCaptureError:
                # Concurrent ingestion of identical evidence: keep one copy.
                self._storage.discard_capture(capture_id)
                winner = self._registry.get_by_sha256(sha256)
                if winner is None:  # pragma: no cover - defensive
                    raise
                return IngestionResult(
                    capture=winner,
                    inspection=_inspection_from_capture(winner),
                    duplicate=True,
                )
            _write_metadata_file(self._storage.metadata_path(capture_id), capture, inspection)
            logger.info("capture registered: %s (%d bytes)", capture_id, size)
            return IngestionResult(capture=capture, inspection=inspection, duplicate=False)
        except CaptureIngestionError:
            self._storage.discard_staging(staging_path)
            raise

    def get_capture(self, capture_id: str) -> Capture | None:
        return self._registry.get(capture_id)

    def list_captures(self) -> list[Capture]:
        return self._registry.list_all()

    def _run_inspection(self, evidence_path: Path) -> CaptureInspection:
        """Inspect evidence, degrading honestly instead of failing ingestion.

        - inspector not configured → UNAVAILABLE (no packet metadata claimed)
        - invalid bytes → InvalidCaptureError propagates (upload rejected)
        - tool crash/timeout → ERROR (evidence stays registered for re-analysis)
        - unexpected internal error → logged, reported as ERROR, never a fake result
        """
        if self._inspector is None:
            return CaptureInspection(
                status=InspectionStatus.UNAVAILABLE,
                message=(
                    "packet inspector unavailable: tshark is not installed "
                    "and NS_EMAIL_TSHARK_PATH is not configured"
                ),
            )
        try:
            return self._inspector.inspect(evidence_path)
        except InvalidCaptureError:
            raise
        except Exception:
            logger.exception("packet inspection failed unexpectedly")
            return CaptureInspection(
                status=InspectionStatus.ERROR,
                tool=self._inspector.tool_name,
                message="packet inspection failed; capture registered without metadata",
            )


def _inspection_from_capture(capture: Capture) -> CaptureInspection:
    """Rebuild the reported inspection state from a stored capture record."""
    inspected = capture.status is CaptureStatus.READY
    return CaptureInspection(
        status=InspectionStatus.INSPECTED if inspected else InspectionStatus.UNAVAILABLE,
        tool=capture.inspector_tool,
        tool_version=capture.inspector_version,
        packet_count=capture.packet_count,
        first_packet_at=capture.capture_started_at,
        last_packet_at=capture.capture_ended_at,
        duration_seconds=capture.duration_seconds,
        message=None if inspected else "packet metadata not available for this capture",
        warnings=capture.warnings,
    )


def _write_metadata_file(
    metadata_path: Path, capture: Capture, inspection: CaptureInspection
) -> None:
    """Write the human-portable metadata.json next to the evidence bytes."""
    payload = {
        "capture": json.loads(capture.model_dump_json()),
        "inspection": json.loads(inspection.model_dump_json()),
    }
    try:
        metadata_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    except OSError as error:
        raise CaptureStorageError(f"cannot write capture metadata: {error}") from error
