"""Graph persistence: nodes and edges in SQLite, one snapshot per capture."""

import json
from typing import Any

from engine.graph.builder import InvestigationContext
from engine.graph.model import EvidenceGraph


def graph_to_rows(graph: EvidenceGraph) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    nodes = [
        {
            "node_id": n.node_id,
            "capture_id": n.capture_id,
            "node_type": n.node_type.value,
            "label": n.label,
            "source_id": n.source_id,
            "metadata": json.dumps(n.metadata),
        }
        for n in graph.nodes
    ]
    edges = [
        {
            "source_node_id": e.source_node_id,
            "target_node_id": e.target_node_id,
            "edge_type": e.edge_type.value,
            "basis": e.basis,
        }
        for e in graph.edges
    ]
    return nodes, edges


def context_to_payload(context: InvestigationContext) -> dict[str, Any]:
    return {
        "capture_id": context.capture_id,
        "session_id": context.session_id,
        "hosts": context.hosts,
        "endpoints": context.endpoints,
        "protocol": context.protocol,
        "tls_version": context.tls_version,
        "cipher_suite": context.cipher_suite,
        "key_exchange": context.key_exchange,
        "certificate_ids": context.certificate_ids,
        "finding_ids": context.finding_ids,
        "anomaly_id": context.anomaly_id,
        "anomaly_score": context.anomaly_score,
        "posture_factors": context.posture_factors,
        "related_session_ids": context.related_session_ids,
        "related_certificate_ids": context.related_certificate_ids,
        "related_tls_config_ids": context.related_tls_config_ids,
        "timeline_events": context.timeline_events,
        "evidence_refs": context.evidence_refs,
    }
