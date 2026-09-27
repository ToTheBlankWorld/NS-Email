"""Forensic evidence graph model and builder (Stage 7).

Constructs a directed, typed evidence graph connecting all forensic
observations for one capture. Every node traces back to actual observed
evidence or a deterministic derived object; every edge carries its basis.

All node and edge ids are deterministic — the same evidence, policy
version, and analysis version always produce the same graph.
"""

import hashlib
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Final

GRAPH_SCHEMA_VERSION: Final[str] = "1.0"
ANALYSIS_VERSION: Final[str] = "0.5.0"


class NodeType(StrEnum):
    """Typed graph node categories."""

    CAPTURE = "capture"
    HOST = "host"
    ENDPOINT = "endpoint"
    SESSION = "session"
    PROTOCOL = "protocol"
    TLS_HANDSHAKE = "tls_handshake"
    CERTIFICATE = "certificate"
    TLS_CONFIGURATION = "tls_configuration"
    FINDING = "finding"
    ANOMALY = "anomaly"
    POSTURE_FACTOR = "posture_factor"
    TIMELINE_EVENT = "timeline_event"


class EdgeType(StrEnum):
    """Typed directed edge relationships."""

    CAPTURE_CONTAINS_HOST = "capture_contains_host"
    HOST_OWNS_ENDPOINT = "host_owns_endpoint"
    ENDPOINT_PARTICIPATES_IN_SESSION = "endpoint_participates_in_session"
    SESSION_CONNECTS_TO_ENDPOINT = "session_connects_to_endpoint"
    SESSION_USES_PROTOCOL = "session_uses_protocol"
    SESSION_HAS_TLS_HANDSHAKE = "session_has_tls_handshake"
    TLS_CONTAINS_CERTIFICATE = "tls_contains_certificate"
    SESSION_PRODUCED_FINDING = "session_produced_finding"
    SESSION_HAS_ANOMALY = "session_has_anomaly"
    CAPTURE_HAS_POSTURE_FACTOR = "capture_has_posture_factor"
    FINDING_AFFECTS_HOST = "finding_affects_host"
    FINDING_AFFECTS_SESSION = "finding_affects_session"
    ANOMALY_AFFECTS_SESSION = "anomaly_affects_session"
    EVENT_BELONGS_TO_SESSION = "event_belongs_to_session"
    FINDING_SUPPORTED_BY_PACKET = "finding_supported_by_packet"
    SESSION_USES_TLS_CONFIG = "session_uses_tls_config"
    TLS_CONFIG_SEEN_IN_HOST = "tls_config_seen_in_host"


@dataclass(frozen=True, slots=True)
class GraphNode:
    """A lightweight, typed node in the evidence graph."""

    node_id: str
    node_type: NodeType
    label: str
    source_id: str  # id of the underlying evidence object
    capture_id: str
    metadata: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class GraphEdge:
    """A typed, directed edge with an explicit basis."""

    source_node_id: str
    target_node_id: str
    edge_type: EdgeType
    basis: str


@dataclass(frozen=True, slots=True)
class EvidenceGraph:
    """The complete evidence graph for one capture."""

    capture_id: str
    graph_schema_version: str
    analysis_version: str
    nodes: list[GraphNode] = field(default_factory=list)
    edges: list[GraphEdge] = field(default_factory=list)

    def get_node(self, node_id: str) -> GraphNode | None:
        return next((n for n in self.nodes if n.node_id == node_id), None)

    def edges_from(self, node_id: str) -> list[GraphEdge]:
        return [e for e in self.edges if e.source_node_id == node_id]

    def edges_to(self, node_id: str) -> list[GraphEdge]:
        return [e for e in self.edges if e.target_node_id == node_id]

    def neighbors(self, node_id: str) -> list[GraphNode]:
        ids = {e.target_node_id for e in self.edges_from(node_id)}
        ids |= {e.source_node_id for e in self.edges_to(node_id)}
        return [n for n in self.nodes if n.node_id in ids]


def _digest(*parts: str) -> str:
    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:12]


def capture_node_id(capture_id: str) -> str:
    return f"capture_{_digest(capture_id)}"


def host_node_id(ip: str) -> str:
    return f"host_{_digest(ip)}"


def endpoint_node_id(ip: str, port: int) -> str:
    return f"endpoint_{_digest(ip, str(port))}"


def session_graph_id(session_id: str) -> str:
    return f"snode_{_digest(session_id)}"


def protocol_node_id(protocol: str) -> str:
    return f"protocol_{_digest(protocol)}"


def handshake_node_id(session_id: str) -> str:
    return f"tlshk_{_digest(session_id)}"


def certificate_node_id(fingerprint: str) -> str:
    return f"gcert_{_digest(fingerprint)}"


def tls_config_node_id(config_fingerprint: str) -> str:
    return f"tlscfg_{_digest(config_fingerprint)}"


def finding_node_id(finding_id: str) -> str:
    return f"fnode_{_digest(finding_id)}"


def anomaly_node_id(anomaly_id: str) -> str:
    return f"anode_{_digest(anomaly_id)}"


def posture_node_id(factor: str, capture_id: str) -> str:
    return f"pfactor_{_digest(factor, capture_id)}"


def event_node_id(session_id: str, seq: int) -> str:
    return f"event_{_digest(session_id, str(seq))}"


def tls_config_fingerprint(
    tls_version: str,
    cipher_suite: str,
    key_exchange: str,
) -> str:
    """Deterministic fingerprint of the negotiated TLS configuration.

    Components: negotiated version + selected cipher suite + key exchange
    family. Raw key material is never included.
    """
    canonical = f"{tls_version}|{cipher_suite}|{key_exchange}"
    return f"tlscfg_{hashlib.sha256(canonical.encode()).hexdigest()[:12]}"
