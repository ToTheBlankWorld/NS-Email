"""Deterministic evidence graph builder for one capture.

Constructs the graph from structured Stage 2-5 evidence using indexed
identity lookups (host IP, certificate fingerprint, TLS configuration
fingerprint) rather than O(N²) session-to-session comparisons.
"""

import hashlib
from collections import defaultdict
from dataclasses import dataclass

from engine.core.findings import SecurityFinding
from engine.core.session import Session
from engine.detection.posture import SecurityPosture
from engine.graph.model import (
    ANALYSIS_VERSION,
    GRAPH_SCHEMA_VERSION,
    EdgeType,
    EvidenceGraph,
    GraphEdge,
    GraphNode,
    NodeType,
    capture_node_id,
    certificate_node_id,
    endpoint_node_id,
    event_node_id,
    finding_node_id,
    handshake_node_id,
    host_node_id,
    posture_node_id,
    protocol_node_id,
    session_graph_id,
    tls_config_fingerprint,
    tls_config_node_id,
)


def _digest(*parts: str) -> str:
    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:12]


@dataclass(frozen=True, slots=True)
class TLSConfigCluster:
    """A deterministic cluster of sessions sharing one TLS configuration."""

    fingerprint: str
    tls_version: str
    cipher_suite: str
    key_exchange: str
    session_ids: list[str]
    host_ips: list[str]
    protocol_values: list[str]


@dataclass(frozen=True, slots=True)
class CertificatePivot:
    """A certificate appearing across multiple sessions (correlation pivot)."""

    fingerprint: str
    session_ids: list[str]
    host_ips: list[str]
    protocol_values: list[str]
    session_count: int
    host_count: int
    protocol_count: int


@dataclass(frozen=True, slots=True)
class InvestigationContext:
    """Combined per-session investigation context for the future AI layer."""

    capture_id: str
    session_id: str
    hosts: list[str]
    endpoints: list[str]
    protocol: str | None
    tls_version: str | None
    cipher_suite: str | None
    key_exchange: str | None
    certificate_ids: list[str]
    finding_ids: list[str]
    anomaly_id: str | None
    anomaly_score: int | None
    posture_factors: list[str]
    related_session_ids: list[str]
    related_certificate_ids: list[str]
    related_tls_config_ids: list[str]
    timeline_events: list[dict[str, str]]
    evidence_refs: list[dict[str, object]]


class EvidenceGraphBuilder:
    """Builds the evidence graph from structured Stage 2-5 evidence."""

    def __init__(self, capture_id: str) -> None:
        self._capture_id = capture_id
        self._nodes: list[GraphNode] = []
        self._edges: list[GraphEdge] = []
        self._node_ids: set[str] = set()

    def _add_node(
        self,
        node_id: str,
        node_type: NodeType,
        label: str,
        source_id: str,
        metadata: dict[str, str] | None = None,
    ) -> None:
        if node_id in self._node_ids:
            return
        self._node_ids.add(node_id)
        self._nodes.append(
            GraphNode(
                node_id=node_id,
                node_type=node_type,
                label=label,
                source_id=source_id,
                capture_id=self._capture_id,
                metadata=metadata or {},
            )
        )

    def _add_edge(self, source_id: str, target_id: str, edge_type: EdgeType, basis: str) -> None:
        self._edges.append(
            GraphEdge(
                source_node_id=source_id,
                target_node_id=target_id,
                edge_type=edge_type,
                basis=basis,
            )
        )

    def build(
        self,
        sessions: list[Session],
        findings: list[SecurityFinding],
        anomalies: list[dict[str, object]],
        posture: SecurityPosture | None,
    ) -> EvidenceGraph:
        """Build the evidence graph from structured evidence."""
        cap_nid = capture_node_id(self._capture_id)
        self._add_node(cap_nid, NodeType.CAPTURE, f"Capture {self._capture_id}", self._capture_id)

        # TLS configuration fingerprints
        config_by_session: dict[str, str] = {}
        config_versions: dict[str, str] = {}
        config_ciphers: dict[str, str] = {}
        config_kex: dict[str, str] = {}
        for session in sessions:
            hs = session.handshake
            if hs is None:
                continue
            fp = tls_config_fingerprint(
                hs.tls_version.value, hs.cipher_suite or "", hs.key_exchange.value
            )
            config_by_session[session.id] = fp
            config_versions[fp] = hs.tls_version.value
            config_ciphers[fp] = hs.cipher_suite or ""
            config_kex[fp] = hs.key_exchange.value

        # Certificate fingerprints
        cert_by_fp: dict[str, list[Session]] = defaultdict(list)
        for session in sessions:
            for cert in session.certificates:
                cert_by_fp[cert.fingerprint_sha256 or cert.id].append(session)

        # Hosts and endpoints
        hosts_seen: dict[str, list[Session]] = defaultdict(list)
        for session in sessions:
            hosts_seen[str(session.server_ip)].append(session)

        for ip in sorted(hosts_seen):
            host_nid = host_node_id(ip)
            ip_sessions = hosts_seen[ip]
            protocols = sorted({s.protocol.value for s in ip_sessions if s.protocol is not None})
            self._add_node(
                host_nid,
                NodeType.HOST,
                ip,
                ip,
                {"observed_ip": ip, "protocols": ", ".join(protocols)},
            )
            self._add_edge(
                cap_nid, host_nid, EdgeType.CAPTURE_CONTAINS_HOST, "host observed in capture"
            )
            for session in ip_sessions:
                ep_nid = endpoint_node_id(str(session.server_ip), session.server_port)
                self._add_node(
                    ep_nid,
                    NodeType.ENDPOINT,
                    f"{ip}:{session.server_port}",
                    f"{ip}:{session.server_port}",
                    {"ip": ip, "port": str(session.server_port), "transport": "tcp"},
                )
                self._add_edge(
                    host_nid, ep_nid, EdgeType.HOST_OWNS_ENDPOINT, "server endpoint on host"
                )
                break  # one endpoint per host is enough for the graph topology

        # Sessions
        for session in sessions:
            s_nid = session_graph_id(session.id)
            self._add_node(
                s_nid,
                NodeType.SESSION,
                session.id,
                session.id,
                {
                    "protocol": session.protocol.value if session.protocol else "",
                    "server_ip": str(session.server_ip),
                    "server_port": str(session.server_port),
                },
            )
            c_ep = endpoint_node_id(str(session.client_ip), session.client_port)
            self._add_node(
                c_ep,
                NodeType.ENDPOINT,
                f"{session.client_ip}:{session.client_port}",
                f"{session.client_ip}:{session.client_port}",
                {"ip": str(session.client_ip), "port": str(session.client_port)},
            )
            self._add_edge(
                c_ep, s_nid, EdgeType.ENDPOINT_PARTICIPATES_IN_SESSION, "client endpoint"
            )
            s_ep = endpoint_node_id(str(session.server_ip), session.server_port)
            self._add_edge(
                s_ep, s_nid, EdgeType.ENDPOINT_PARTICIPATES_IN_SESSION, "server endpoint"
            )
            self._add_edge(s_nid, c_ep, EdgeType.SESSION_CONNECTS_TO_ENDPOINT, "client endpoint")
            self._add_edge(s_nid, s_ep, EdgeType.SESSION_CONNECTS_TO_ENDPOINT, "server endpoint")

            if session.protocol is not None:
                p_nid = protocol_node_id(session.protocol.value)
                self._add_node(
                    p_nid,
                    NodeType.PROTOCOL,
                    session.protocol.value.upper(),
                    session.protocol.value,
                )
                self._add_edge(s_nid, p_nid, EdgeType.SESSION_USES_PROTOCOL, "protocol identified")

            hs = session.handshake
            if hs is not None:
                hk_nid = handshake_node_id(session.id)
                self._add_node(
                    hk_nid,
                    NodeType.TLS_HANDSHAKE,
                    f"TLS {hs.tls_version.value}",
                    hs.id,
                    {"tls_version": hs.tls_version.value, "cipher_suite": hs.cipher_suite or ""},
                )
                self._add_edge(
                    s_nid, hk_nid, EdgeType.SESSION_HAS_TLS_HANDSHAKE, "TLS handshake reconstructed"
                )
                config_fp = config_by_session.get(session.id)
                if config_fp:
                    cfg_nid = tls_config_node_id(config_fp)
                    self._add_node(
                        cfg_nid,
                        NodeType.TLS_CONFIGURATION,
                        f"TLS {config_versions[config_fp]}",
                        config_fp,
                        {
                            "tls_version": config_versions[config_fp],
                            "cipher_suite": config_ciphers[config_fp],
                        },
                    )
                    self._add_edge(
                        s_nid, cfg_nid, EdgeType.SESSION_USES_TLS_CONFIG, "same TLS configuration"
                    )
                for cert in session.certificates:
                    cert_fp = cert.fingerprint_sha256 or cert.id
                    c_nid = certificate_node_id(cert_fp)
                    self._add_node(
                        c_nid,
                        NodeType.CERTIFICATE,
                        cert.subject,
                        cert.id,
                        {"fingerprint": cert_fp, "subject": cert.subject, "issuer": cert.issuer},
                    )
                    self._add_edge(
                        hk_nid, c_nid, EdgeType.TLS_CONTAINS_CERTIFICATE, "certificate chain"
                    )

            session_findings = [f for f in findings if f.session_id == session.id]
            host_nid = host_node_id(str(session.server_ip))
            for finding in session_findings:
                f_nid = finding_node_id(finding.id)
                self._add_node(
                    f_nid,
                    NodeType.FINDING,
                    finding.title,
                    finding.id,
                    {"severity": finding.severity.value, "rule_id": finding.rule_id},
                )
                self._add_edge(
                    s_nid, f_nid, EdgeType.SESSION_PRODUCED_FINDING, "rule-based finding"
                )
                self._add_edge(
                    f_nid, s_nid, EdgeType.FINDING_AFFECTS_SESSION, "finding affects session"
                )
                self._add_edge(
                    f_nid, host_nid, EdgeType.FINDING_AFFECTS_HOST, "finding affects host"
                )

            for event in session.events:
                e_nid = event_node_id(session.id, event.seq)
                self._add_node(
                    e_nid,
                    NodeType.TIMELINE_EVENT,
                    event.type.value,
                    f"{session.id}#{event.seq}",
                    {"event_type": event.type.value, "direction": event.direction.value},
                )
                self._add_edge(e_nid, s_nid, EdgeType.EVENT_BELONGS_TO_SESSION, "timeline event")

        # Certificate correlation (shared fingerprints)
        for _fingerprint, cert_sessions in cert_by_fp.items():
            if len(cert_sessions) < 2:
                continue
            first = cert_sessions[0].certificates[0]
            c_nid = certificate_node_id(first.fingerprint_sha256 or first.id)
            for session in cert_sessions:
                s_nid = session_graph_id(session.id)
                self._add_edge(
                    s_nid, c_nid, EdgeType.TLS_CONTAINS_CERTIFICATE, "certificate fingerprint match"
                )

        # TLS configuration seen on hosts
        config_host_ips: dict[str, set[str]] = {}
        for sid, fp in config_by_session.items():
            for s in sessions:
                if s.id == sid:
                    config_host_ips.setdefault(fp, set()).add(str(s.server_ip))
        for fp, host_ips in sorted(config_host_ips.items()):
            cfg_nid = tls_config_node_id(fp)
            for ip in sorted(host_ips):
                host_nid = host_node_id(ip)
                self._add_edge(
                    cfg_nid,
                    host_nid,
                    EdgeType.TLS_CONFIG_SEEN_IN_HOST,
                    "same TLS configuration on host",
                )

        # Posture factors
        if posture is not None:
            for factor in posture.factors:
                if factor.score_contribution <= 0:
                    continue
                pf_nid = posture_node_id(factor.factor, self._capture_id)
                self._add_node(
                    pf_nid,
                    NodeType.POSTURE_FACTOR,
                    f"{factor.label}: {factor.status}",
                    factor.factor,
                    {"status": factor.status, "contribution": f"{factor.score_contribution:g}"},
                )
                self._add_edge(
                    cap_nid, pf_nid, EdgeType.CAPTURE_HAS_POSTURE_FACTOR, "posture factor"
                )

        return EvidenceGraph(
            capture_id=self._capture_id,
            graph_schema_version=GRAPH_SCHEMA_VERSION,
            analysis_version=ANALYSIS_VERSION,
            nodes=sorted(self._nodes, key=lambda n: (n.node_type.value, n.node_id)),
            edges=sorted(
                self._edges,
                key=lambda e: (e.source_node_id, e.target_node_id, e.edge_type.value),
            ),
        )


def build_certificate_pivots(sessions: list[Session]) -> list[CertificatePivot]:
    """Group sessions by certificate fingerprint for correlation pivots."""
    by_fp: dict[str, list[Session]] = defaultdict(list)
    for session in sessions:
        for cert in session.certificates:
            by_fp[cert.fingerprint_sha256 or cert.id].append(session)

    pivots: list[CertificatePivot] = []
    for fingerprint, cert_sessions in sorted(by_fp.items()):
        if len(cert_sessions) < 2:
            continue
        protocols = sorted({s.protocol.value for s in cert_sessions if s.protocol is not None})
        host_ips = sorted({str(s.server_ip) for s in cert_sessions})
        pivots.append(
            CertificatePivot(
                fingerprint=fingerprint,
                session_ids=[s.id for s in cert_sessions],
                host_ips=host_ips,
                protocol_values=protocols,
                session_count=len(cert_sessions),
                host_count=len(set(host_ips)),
                protocol_count=len(protocols),
            )
        )
    return pivots


def build_config_clusters(sessions: list[Session]) -> list[TLSConfigCluster]:
    """Group sessions by TLS configuration fingerprint."""
    clusters: dict[str, TLSConfigCluster] = {}
    for session in sessions:
        hs = session.handshake
        if hs is None:
            continue
        fp = tls_config_fingerprint(
            hs.tls_version.value, hs.cipher_suite or "", hs.key_exchange.value
        )
        cluster = clusters.setdefault(
            fp,
            TLSConfigCluster(
                fingerprint=fp,
                tls_version=hs.tls_version.value,
                cipher_suite=hs.cipher_suite or "",
                key_exchange=hs.key_exchange.value,
                session_ids=[],
                host_ips=[],
                protocol_values=[],
            ),
        )
        cluster.session_ids.append(session.id)
        cluster.host_ips.append(str(session.server_ip))
        if session.protocol:
            cluster.protocol_values.append(session.protocol.value)
    return sorted(clusters.values(), key=lambda c: c.fingerprint)


def build_investigation_context(
    session: Session,
    findings: list[SecurityFinding],
    anomalies: list[dict[str, object]],
    posture_factors: list[str],
    all_sessions: list[Session],
    all_findings: list[SecurityFinding],
) -> InvestigationContext:
    """Build the combined investigation context for one session."""
    session_findings = [f for f in findings if f.session_id == session.id]
    session_anomaly = next((a for a in anomalies if a.get("session_id") == session.id), None)

    host_ip = str(session.server_ip)
    related_sessions = sorted(
        s.id for s in all_sessions if str(s.server_ip) == host_ip and s.id != session.id
    )
    related_certs = sorted({cert.fingerprint_sha256 or cert.id for cert in session.certificates})

    tls_version = session.handshake.tls_version.value if session.handshake else None
    cipher_suite = session.handshake.cipher_suite if session.handshake else None
    key_exchange = session.handshake.key_exchange.value if session.handshake else None
    config_id = (
        tls_config_fingerprint(tls_version, cipher_suite or "", key_exchange or "")
        if tls_version
        else None
    )

    timeline = [
        {
            "event_type": event.type.value,
            "direction": event.direction.value,
            "timestamp": event.timestamp.isoformat() if event.timestamp else "",
            "packet_numbers": ",".join(str(p) for p in event.packet_numbers),
        }
        for event in session.events
    ]

    evidence_refs: list[dict[str, object]] = []
    for finding in session_findings:
        for ref in finding.evidence_refs:
            evidence_refs.append(
                {
                    "source": ref.source,
                    "packet_numbers": ref.packet_numbers,
                    "detail": ref.detail,
                }
            )

    anomaly_score = None
    anomaly_id = None
    if session_anomaly:
        raw_score = session_anomaly.get("score")
        anomaly_score = int(raw_score) if isinstance(raw_score, (int, float)) else None
        anomaly_id = str(session_anomaly.get("anomaly_id", "")) or None

    return InvestigationContext(
        capture_id=session.capture_id,
        session_id=session.id,
        hosts=[host_ip],
        endpoints=[
            f"{session.client_ip}:{session.client_port}",
            f"{host_ip}:{session.server_port}",
        ],
        protocol=session.protocol.value if session.protocol else None,
        tls_version=tls_version,
        cipher_suite=cipher_suite,
        key_exchange=key_exchange,
        certificate_ids=related_certs,
        finding_ids=[f.id for f in session_findings],
        anomaly_id=anomaly_id,
        anomaly_score=anomaly_score,
        posture_factors=list(posture_factors),
        related_session_ids=related_sessions,
        related_certificate_ids=related_certs,
        related_tls_config_ids=[config_id] if config_id else [],
        timeline_events=timeline,
        evidence_refs=evidence_refs,
    )
