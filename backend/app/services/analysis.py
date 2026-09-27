"""Capture analysis orchestration: registered capture → session evidence.

Runs the engine pipeline synchronously (captures are size-capped) and
persists results atomically. Failures are recorded as structured analysis
status — a failed analysis is a result, not a crash.
"""

import logging
from typing import Any

from engine.analysis import analyze_capture_packets
from engine.core.findings import SecurityFinding
from engine.core.session import Session
from engine.detection import evaluate_sessions
from engine.detection.policy import Policy
from engine.detection.posture import build_posture
from engine.graph.builder import EvidenceGraphBuilder
from engine.ingestion.errors import CaptureStorageError
from engine.ml.anomaly import AnomalyEngine, AnomalyReport
from engine.transport.packets import PacketSourceError, PcapPacketSource

from app.registry import CaptureRegistry
from app.services.graph_serializer import graph_to_rows
from app.services.posture_serializer import posture_to_payload
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


def _anomaly_report_to_payload(report: AnomalyReport) -> dict[str, Any]:
    """Serialize the anomaly report into a JSON-safe document."""
    return {
        "capture_id": report.capture_id,
        "analysis_version": report.analysis_version,
        "feature_schema_version": report.feature_schema_version,
        "model_id": report.model_id,
        "model_version": report.model_version,
        "status": report.status,
        "training_session_count": report.training_session_count,
        "anomalies": [
            {
                "anomaly_id": a.anomaly_id,
                "session_id": a.session_id,
                "protocol": a.protocol,
                "status": a.status,
                "score": a.score,
                "band": a.band,
                "model_id": a.model_id,
                "model_version": a.model_version,
                "feature_schema_version": a.feature_schema_version,
                "top_deviations": [
                    {
                        "feature": deviation["feature"],
                        "observed": deviation["observed"],
                        "baseline": deviation["baseline"],
                        "deviation": deviation["deviation"],
                    }
                    for deviation in a.top_deviations
                ],
                "baseline_summary": a.baseline_summary,
                "evidence_refs": [
                    {
                        "source": ref.source,
                        "packet_numbers": ref.packet_numbers,
                        "detail": ref.detail,
                    }
                    for ref in a.evidence_refs
                ],
                "generated_at": a.generated_at.isoformat(),
            }
            for a in report.anomalies
        ],
        "summary": report.summary,
        "generated_at": report.generated_at.isoformat(),
    }


class CaptureAnalysisService:
    """Analyzes registered captures: sessions → TLS evidence → findings → posture."""

    def __init__(
        self,
        storage: CaptureStorage,
        registry: CaptureRegistry,
        store: SessionStore,
        policy: Policy,
        anomaly_engine: AnomalyEngine | None = None,
    ) -> None:
        self._storage = storage
        self._registry = registry
        self._store = store
        self._policy = policy
        self._anomaly_engine = anomaly_engine or AnomalyEngine()

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
        findings = evaluate_sessions(result.sessions, self._policy)
        self._store.replace_findings_for_capture(capture.id, findings)
        posture = build_posture(capture.id, result.sessions, findings, self._policy)
        self._store.replace_posture_snapshot(posture_to_payload(posture))
        anomaly_report = self._anomaly_engine.analyze(result.sessions)
        anomaly_payload = _anomaly_report_to_payload(anomaly_report)
        self._store.replace_anomaly_results(capture.id, anomaly_payload)
        graph = EvidenceGraphBuilder(capture.id).build(
            result.sessions, findings, anomaly_payload["anomalies"], posture
        )
        graph_nodes, graph_edges = graph_to_rows(graph)
        self._store.replace_graph(capture.id, graph_nodes, graph_edges)
        self._store.record_completed(capture.id, len(result.sessions), result.coverage_warnings)
        logger.info(
            "analyzed %s: %d session(s), %d finding(s)",
            capture.id,
            len(result.sessions),
            len(findings),
        )
        return ("completed", len(result.sessions))

    def sessions_for(self, capture_id: str) -> list[Session]:
        return self._store.list_for_capture(capture_id)

    def session(self, session_id: str) -> Session | None:
        return self._store.get(session_id)

    def analysis_status(self, capture_id: str) -> AnalysisRecord:
        return self._store.analysis_status(capture_id)

    def findings_for_capture(self, capture_id: str) -> list[SecurityFinding]:
        return self._store.list_findings_for_capture(capture_id)

    def findings_for_session(self, session_id: str) -> list[SecurityFinding]:
        return self._store.list_findings_for_session(session_id)

    def finding(self, finding_id: str) -> SecurityFinding | None:
        return self._store.get_finding(finding_id)

    def posture_snapshot(self, capture_id: str) -> dict[str, Any] | None:
        return self._store.get_posture_snapshot(capture_id)

    def anomalies_for_capture(self, capture_id: str) -> list[dict[str, Any]]:
        return self._store.list_anomaly_results(capture_id)

    def anomaly_result(self, anomaly_id: str) -> dict[str, Any] | None:
        return self._store.get_anomaly_result(anomaly_id)

    def anomaly_summary(self, capture_id: str) -> dict[str, int] | None:
        return self._store.get_anomaly_summary(capture_id)

    def anomaly_for_session(self, session_id: str) -> dict[str, Any] | None:
        return self._store.get_anomaly_for_session(session_id)

    def graph(self, capture_id: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]] | None:
        return self._store.get_graph(capture_id)
