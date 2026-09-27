"""Capture analysis orchestration: registered capture → session evidence.

Runs the engine pipeline synchronously (captures are size-capped) and
persists results atomically. Failures are recorded as structured analysis
status — a failed analysis is a result, not a crash.
"""

import logging

from engine.analysis import analyze_capture_packets
from engine.core.session import Session
from engine.ingestion.errors import CaptureStorageError
from engine.transport.packets import PacketSourceError, PcapPacketSource

from app.registry import CaptureRegistry
from app.storage import CaptureStorage
from app.store import AnalysisRecord, SessionStore

logger = logging.getLogger("ns_email.analysis")

# Kept in memory during analysis: bounded by the configured capture size
# limit. Streaming between the packet source and flow builder is deferred
# together with asynchronous execution (ADR 002).
MAX_PACKETS_FOR_ANALYSIS = 2_000_000


class CaptureNotFoundError(Exception):
    """The requested capture id is not registered."""

    def __init__(self, capture_id: str) -> None:
        super().__init__(f"no capture exists with id {capture_id}")
        self.capture_id = capture_id


class CaptureAnalysisService:
    """Analyzes registered captures and stores reconstructed sessions."""

    def __init__(
        self,
        storage: CaptureStorage,
        registry: CaptureRegistry,
        store: SessionStore,
    ) -> None:
        self._storage = storage
        self._registry = registry
        self._store = store

    def analyze(self, capture_id: str) -> tuple[str, int]:
        """Run analysis for one capture; returns (status, session_count).

        Raises ``CaptureNotFoundError`` when the capture is unknown and
        ``CaptureStorageError`` on storage faults. Packet-source failures
        are recorded as a failed analysis and returned as ``("failed", 0)``.
        """
        capture = self._registry.get(capture_id)
        if capture is None:
            raise CaptureNotFoundError(capture_id)

        evidence_path = self._storage.evidence_path(capture.id, capture.format.value)
        if not evidence_path.is_file():
            raise CaptureStorageError("evidence file is missing from storage")

        try:
            source = PcapPacketSource(evidence_path)
            packets = []
            for packet in source.packets():
                packets.append(packet)
                if len(packets) > MAX_PACKETS_FOR_ANALYSIS:  # pragma: no cover - guard
                    raise PacketSourceError("capture exceeds the analysis packet limit")
            coverage_warnings = list(source.stats().skip_reasons())
            result = analyze_capture_packets(
                capture.id, packets, coverage_warnings=coverage_warnings
            )
        except PacketSourceError as error:
            logger.warning("analysis of %s failed: %s", capture_id, error)
            self._store.record_failed(capture_id, "capture_processing_error", str(error))
            return ("failed", 0)

        self._store.replace_for_capture(capture.id, result.sessions)
        self._store.record_completed(capture.id, len(result.sessions), result.coverage_warnings)
        logger.info("analyzed %s: %d session(s)", capture.id, len(result.sessions))
        return ("completed", len(result.sessions))

    def sessions_for(self, capture_id: str) -> list[Session]:
        return self._store.list_for_capture(capture_id)

    def session(self, session_id: str) -> Session | None:
        return self._store.get(session_id)

    def analysis_status(self, capture_id: str) -> AnalysisRecord:
        return self._store.analysis_status(capture_id)
