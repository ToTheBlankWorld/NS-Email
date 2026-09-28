"""Case-scoped multi-capture correlation service (Stage 12).

``CorrelationService`` derives investigation intelligence from the
structured evidence already held by a case's captures. The data flow is
strictly one-way and read-only: sessions, findings, and anomaly results
are fed to the index-based engine, which returns deterministic
correlations. Nothing is persisted — correlations are a pure function
of case attachments plus evidence state, so they can never go stale and
can never mutate forensic truth.

Neutral language only: shared evidence, repeated observations,
correlated sessions. No attribution, no intent, no compromise claims,
no scores.
"""

import re
from typing import Any

from engine.core.session import Session
from engine.correlation import (
    AnomalyView,
    CaptureCorrelationInput,
    Correlation,
    CorrelationReport,
    CorrelationType,
    correlate_case,
)
from engine.graph.model import (
    anomaly_node_id,
    certificate_node_id,
    endpoint_node_id,
    finding_node_id,
    host_node_id,
    protocol_node_id,
    session_graph_id,
    tls_config_node_id,
)

from app.case_store import CASE_ID_PATTERN, CaseStore
from app.registry import CaptureRegistry
from app.services.analysis import CaptureAnalysisService
from app.services.cases import CaseNotFoundError, CaseValidationError

CORRELATION_ID_PATTERN = re.compile(r"^corr_[0-9a-f]{16}$")

ERROR_CORRELATION_NOT_FOUND = "correlation_not_found"

#: Bounded API output.
DEFAULT_LIST_LIMIT = 100
MAX_LIST_LIMIT = 500
MAX_RELATED_IDS = 100
MAX_GRAPH_SESSIONS = 500


class CorrelationNotFoundError(Exception):
    """The requested correlation id is unknown (covers malformed ids)."""

    def __init__(self, correlation_id: str) -> None:
        super().__init__("no correlation exists with this id")
        self.correlation_id = correlation_id


def _require_case_id(case_id: str) -> str:
    cleaned = case_id.strip()
    if not CASE_ID_PATTERN.fullmatch(cleaned):
        raise CaseNotFoundError(case_id)
    return cleaned


def _require_correlation_id(correlation_id: str) -> str:
    cleaned = correlation_id.strip()
    if not CORRELATION_ID_PATTERN.fullmatch(cleaned):
        raise CorrelationNotFoundError(correlation_id)
    return cleaned


class CorrelationService:
    """Derive and serve deterministic case correlations (read-only)."""

    def __init__(
        self,
        case_store: CaseStore,
        registry: CaptureRegistry,
        analysis: CaptureAnalysisService,
    ) -> None:
        self._cases = case_store
        self._registry = registry
        self._analysis = analysis

    # -- evidence assembly -------------------------------------------------

    def _capture_inputs(self, case_id: str) -> tuple[str, list[CaptureCorrelationInput]]:
        """Assemble engine inputs for every capture attached to the case."""
        cleaned = _require_case_id(case_id)
        if self._cases.get_case(cleaned) is None:
            raise CaseNotFoundError(case_id)
        attachments = self._cases.list_attachments(cleaned)
        inputs: list[CaptureCorrelationInput] = []
        for attachment in attachments:
            if self._registry.get(attachment.capture_id) is None:
                continue
            anomalies: list[AnomalyView] = []
            for row in self._analysis.anomalies_for_capture(attachment.capture_id):
                anomalies.append(
                    {
                        "anomaly_id": str(row.get("anomaly_id", "")),
                        "session_id": str(row.get("session_id", "")),
                        "band": row.get("band"),
                        "status": str(row.get("status", "")),
                    }
                )
            inputs.append(
                CaptureCorrelationInput(
                    capture_id=attachment.capture_id,
                    sessions=self._analysis.sessions_for(attachment.capture_id),
                    findings=self._analysis.findings_for_capture(attachment.capture_id),
                    anomalies=anomalies,
                )
            )
        return cleaned, inputs

    def compute(self, case_id: str) -> CorrelationReport:
        """Run the correlation engine over the case's current evidence."""
        cleaned, inputs = self._capture_inputs(case_id)
        return correlate_case(cleaned, inputs)

    # -- list / get / summary -----------------------------------------------

    def list_correlations(
        self,
        case_id: str,
        *,
        type_filter: str | None = None,
        capture_id: str | None = None,
        protocol: str | None = None,
        endpoint: str | None = None,
        certificate: str | None = None,
        finding: str | None = None,
        search: str | None = None,
        sort: str = "occurrences",
        limit: int = DEFAULT_LIST_LIMIT,
        offset: int = 0,
    ) -> tuple[int, list[dict[str, Any]]]:
        """Filtered, sorted, paginated correlations (bounded output).

        Text filters match the normalized evidence key (substring,
        case-insensitive); ``type_filter`` is an exact correlation type.
        """
        report = self.compute(case_id)
        wanted: CorrelationType | None = None
        if type_filter is not None:
            try:
                wanted = CorrelationType(type_filter.strip().lower())
            except ValueError as error:
                raise CaseValidationError(
                    "type must be one of " + ", ".join(sorted(t.value for t in CorrelationType))
                ) from error
        if sort not in ("occurrences", "type", "first_observed", "last_observed"):
            raise CaseValidationError(
                "sort must be one of occurrences, type, first_observed, last_observed"
            )
        if limit < 1 or limit > MAX_LIST_LIMIT:
            raise CaseValidationError(f"limit must be between 1 and {MAX_LIST_LIMIT}")
        if offset < 0:
            raise CaseValidationError("offset must not be negative")

        needles = {
            name: value.strip().lower()
            for name, value in (
                ("protocol", protocol),
                ("endpoint", endpoint),
                ("certificate", certificate),
                ("finding", finding),
                ("search", search),
            )
            if value and value.strip()
        }
        items = []
        for correlation in report.correlations:
            if wanted is not None and correlation.correlation_type is not wanted:
                continue
            if capture_id is not None and capture_id.strip() not in correlation.source_capture_ids:
                continue
            key = correlation.evidence_key.lower()
            if any(needle not in key for needle in needles.values()):
                continue
            items.append(correlation.to_dict())

        if sort == "occurrences":
            items.sort(key=lambda c: (-c["occurrence_count"], c["correlation_id"]))
        elif sort == "type":
            items.sort(
                key=lambda c: (c["correlation_type"], c["evidence_key"], c["correlation_id"])
            )
        elif sort == "first_observed":
            items.sort(
                key=lambda c: (
                    c["first_observed_at"] is None,
                    c["first_observed_at"] or "",
                    c["correlation_id"],
                )
            )
        else:
            items.sort(
                key=lambda c: (
                    c["last_observed_at"] is None,
                    c["last_observed_at"] or "",
                    c["correlation_id"],
                )
            )
        total = len(items)
        return total, items[offset : offset + limit]

    def get_correlation(self, case_id: str, correlation_id: str) -> dict[str, Any]:
        """One correlation by its deterministic id."""
        cleaned_id = _require_correlation_id(correlation_id)
        for correlation in self.compute(case_id).correlations:
            if correlation.correlation_id == cleaned_id:
                return correlation.to_dict()
        raise CorrelationNotFoundError(correlation_id)

    def correlation_summary(self, case_id: str) -> dict[str, Any]:
        """Counts only — never a score."""
        return self.compute(case_id).to_summary()

    # -- context ---------------------------------------------------------------

    def correlation_context(self, case_id: str, correlation_id: str) -> dict[str, Any]:
        """Full investigation context for one correlation.

        Bundles the correlation with related finding/anomaly ids,
        derived graph-node references, and case-timeline references —
        all as references to existing records, never copies.
        """
        cleaned = _require_case_id(case_id)
        record = self.get_correlation(cleaned, correlation_id)
        finding_ids = sorted(
            {str(o["finding_id"]) for o in record["occurrences"] if o.get("finding_id")}
        )[:MAX_RELATED_IDS]
        anomaly_ids = sorted(
            {str(o["anomaly_id"]) for o in record["occurrences"] if o.get("anomaly_id")}
        )[:MAX_RELATED_IDS]
        nodes = self._graph_nodes_for(record)
        timeline_refs = []
        involved = set(record["source_capture_ids"])
        for entry in self._cases.list_timeline(cleaned):
            if involved.intersection(set(entry.detail.values())):
                timeline_refs.append(
                    {
                        "entry_id": entry.entry_id,
                        "event_type": entry.event_type,
                        "created_at": entry.created_at.isoformat() if entry.created_at else None,
                    }
                )
        return {
            "correlation": record,
            "related_finding_ids": finding_ids,
            "related_anomaly_ids": anomaly_ids,
            "graph_nodes": nodes,
            "timeline_refs": timeline_refs[:MAX_RELATED_IDS],
        }

    def _graph_nodes_for(self, record: dict[str, Any]) -> list[dict[str, Any]]:
        """Deterministic graph-node references for the correlation evidence."""
        nodes: dict[str, dict[str, Any]] = {}
        correlation_type = record["correlation_type"]
        evidence = record.get("evidence", {})
        key = record["evidence_key"]

        def add(node_id: str, node_type: str, label: str) -> None:
            nodes.setdefault(node_id, {"node_id": node_id, "node_type": node_type, "label": label})

        for session_id in record.get("source_session_ids", []):
            add(session_graph_id(str(session_id)), "session", str(session_id))
        for capture_id in record.get("source_capture_ids", []):
            add(f"capture_{capture_id!s}", "capture", str(capture_id))
        if correlation_type == "shared_certificate":
            fingerprint = str(evidence.get("fingerprint_sha256", key.split("|", 1)[-1]))
            add(certificate_node_id(fingerprint), "certificate", fingerprint[:16])
        elif correlation_type == "shared_certificate_subject":
            add(
                certificate_node_id(key.split("|", 1)[-1]),
                "certificate",
                str(evidence.get("subject", key))[:64],
            )
        elif correlation_type == "shared_tls_configuration":
            config_fp = str(evidence.get("config_fingerprint", key.split("|", 1)[-1]))
            add(tls_config_node_id(config_fp), "tls_configuration", config_fp)
        elif correlation_type == "shared_host":
            ip = str(evidence.get("ip", key.split("|", 1)[-1]))
            add(host_node_id(ip), "host", ip)
        elif correlation_type == "shared_endpoint":
            ip = str(evidence.get("ip", ""))
            port = evidence.get("port", "")
            if ip and port != "":
                add(endpoint_node_id(ip, int(port)), "endpoint", f"{ip}:{port}")
        elif correlation_type == "shared_protocol":
            protocol = str(evidence.get("protocol", key.split("|", 1)[-1]))
            add(protocol_node_id(protocol), "protocol", protocol)
        elif correlation_type == "shared_finding":
            for occurrence in record.get("occurrences", []):
                finding_id = occurrence.get("finding_id")
                if finding_id:
                    add(finding_node_id(str(finding_id)), "finding", str(finding_id))
        elif correlation_type == "shared_anomaly_pattern":
            for occurrence in record.get("occurrences", []):
                anomaly_id = occurrence.get("anomaly_id")
                if anomaly_id:
                    add(anomaly_node_id(str(anomaly_id)), "anomaly", str(anomaly_id))
        return sorted(nodes.values(), key=lambda n: (n["node_type"], n["node_id"]))

    # -- session related observations -----------------------------------------------

    def related_for_session(self, case_id: str, session_id: str) -> dict[str, Any] | None:
        """Related observations for one session within the case.

        Returns ``None`` when the session is unknown; an empty related
        list when the session exists but shares no case evidence.
        Existing session semantics are untouched — this is additive.
        """
        cleaned = _require_case_id(case_id)
        session = self._analysis.session(session_id.strip())
        if session is None:
            return None
        related = []
        for correlation in self.compute(cleaned).correlations:
            if session_id.strip() not in correlation.source_session_ids:
                continue
            others = [s for s in correlation.source_session_ids if s != session_id.strip()]
            related.append(
                {
                    "correlation_id": correlation.correlation_id,
                    "correlation_type": correlation.correlation_type.value,
                    "evidence_key": correlation.evidence_key,
                    "other_session_count": len(others),
                    "other_session_ids": sorted(others)[:MAX_RELATED_IDS],
                    "other_capture_ids": sorted(
                        set(correlation.source_capture_ids) - {session.capture_id}
                    ),
                }
            )
        related.sort(key=lambda r: (r["correlation_type"], r["correlation_id"]))
        return {
            "case_id": cleaned,
            "session_id": session_id.strip(),
            "capture_id": session.capture_id,
            "related": related,
        }

    # -- investigation graph ---------------------------------------------------------------

    def investigation_graph(self, case_id: str) -> dict[str, Any]:
        """Derived case investigation view (separate from Stage 7 graphs).

        Forensic nodes/edges (case, capture, session, evidence) carry
        ``layer: "forensic"``; correlation groupings carry
        ``layer: "correlation"``. Sessions are bounded; truncation is
        reported explicitly instead of silently dropping data.
        """
        cleaned = _require_case_id(case_id)
        report = self.compute(cleaned)
        nodes: dict[str, dict[str, Any]] = {}
        edges: list[dict[str, Any]] = []

        def add_node(node_id: str, node_type: str, label: str, layer: str) -> None:
            nodes.setdefault(
                node_id,
                {"node_id": node_id, "node_type": node_type, "label": label, "layer": layer},
            )

        def add_edge(source: str, target: str, edge_type: str, layer: str, basis: str) -> None:
            edge = {
                "source_node_id": source,
                "target_node_id": target,
                "edge_type": edge_type,
                "layer": layer,
                "basis": basis,
            }
            if edge not in edges:
                edges.append(edge)

        case_node = f"case_{cleaned}"
        add_node(case_node, "case", cleaned, "forensic")
        for capture_id in report.capture_ids:
            capture_node = f"capture_{capture_id}"
            add_node(capture_node, "capture", capture_id, "forensic")
            add_edge(
                case_node,
                capture_node,
                "case_contains_capture",
                "correlation",
                "case attachment reference",
            )

        session_budget = MAX_GRAPH_SESSIONS
        truncated = False
        for correlation in report.correlations:
            correlation_node = f"correlation_{correlation.correlation_id}"
            add_node(
                correlation_node,
                "correlation",
                f"{correlation.correlation_type.value}: {correlation.evidence_key[:64]}",
                "correlation",
            )
            add_edge(
                case_node,
                correlation_node,
                "case_groups_correlation",
                "correlation",
                "shared evidence observation",
            )
            for session_id in correlation.source_session_ids:
                session_node = session_graph_id(session_id)
                if session_node not in nodes:
                    if session_budget <= 0:
                        truncated = True
                        continue
                    session_budget -= 1
                    add_node(session_node, "session", session_id, "forensic")
                    for capture_id in correlation.source_capture_ids:
                        session = self._session_if_in(session_id, capture_id)
                        if session is not None:
                            add_edge(
                                f"capture_{capture_id}",
                                session_node,
                                "capture_contains_session",
                                "forensic",
                                "analysis record",
                            )
                            break
                add_edge(
                    correlation_node,
                    session_node,
                    "correlation_involves_session",
                    "correlation",
                    "shared evidence observation",
                )
            for node in self._graph_nodes_for(correlation.to_dict()):
                if node["node_type"] in ("session", "capture"):
                    continue
                add_node(node["node_id"], node["node_type"], node["label"], "forensic")
                add_edge(
                    correlation_node,
                    node["node_id"],
                    "correlation_explained_by_evidence",
                    "correlation",
                    "shared evidence observation",
                )

        node_list = sorted(nodes.values(), key=lambda n: (n["layer"], n["node_type"], n["node_id"]))
        edge_list = sorted(
            edges,
            key=lambda e: (e["layer"], e["edge_type"], e["source_node_id"], e["target_node_id"]),
        )
        return {
            "case_id": cleaned,
            "nodes": node_list,
            "edges": edge_list,
            "node_count": len(node_list),
            "edge_count": len(edge_list),
            "sessions_truncated": truncated,
            "correlation_count": len(report.correlations),
        }

    def _session_if_in(self, session_id: str, capture_id: str) -> Session | None:
        """Return the session when it belongs to the capture, else None."""
        session = self._analysis.session(session_id)
        if session is not None and session.capture_id == capture_id:
            return session
        return None

    # -- minimized AI context ---------------------------------------------------------------

    def correlation_for_ai(self, case_id: str, correlation_id: str) -> Correlation:
        """Resolve one correlation for an explicit analyst AI question.

        Returns the engine record only; the AI layer builds its own
        minimized, bounded context from it. Never called automatically.
        """
        cleaned = _require_case_id(case_id)
        wanted = _require_correlation_id(correlation_id)
        for correlation in self.compute(cleaned).correlations:
            if correlation.correlation_id == wanted:
                return correlation
        raise CorrelationNotFoundError(correlation_id)


__all__ = [
    "CORRELATION_ID_PATTERN",
    "ERROR_CORRELATION_NOT_FOUND",
    "CorrelationNotFoundError",
    "CorrelationService",
]
