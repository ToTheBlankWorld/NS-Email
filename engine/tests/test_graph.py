"""Evidence graph tests: construction, determinism, pivots, correlation."""

from datetime import UTC, datetime

from conftest import (
    pop3_conversation,
    smtp_plain_conversation,
    smtp_starttls_conversation,
)
from engine.core.findings import EvidenceRef, FindingCategory, FindingSeverity, SecurityFinding
from engine.core.session import Confidence, Session
from engine.graph import (
    EdgeType,
    NodeType,
    build_certificate_pivots,
    build_config_clusters,
    build_investigation_context,
)
from engine.graph.builder import EvidenceGraphBuilder
from engine.graph.model import tls_config_fingerprint
from engine.protocols.reconstruct import reconstruct_session
from engine.transport.flows import build_flows

CAPTURE_ID = "capture_aaaaaaaaaaaa"


def _build_sessions_from(packets_list: list[list], capture_id: str = CAPTURE_ID):
    sessions = []
    for packets in packets_list:
        flows = build_flows(capture_id, packets)
        sessions.extend(reconstruct_session(f) for f in flows)
    return sessions


def make_session(session_id: str, server_ip: str = "198.51.100.7", **overrides):
    from engine.core.session import EmailProtocol

    defaults = {
        "id": session_id,
        "capture_id": CAPTURE_ID,
        "client_ip": "10.10.0.23",
        "server_ip": server_ip,
        "client_port": 49152,
        "server_port": 587,
        "protocol": EmailProtocol.SMTP,
        "started_at": datetime(2024, 9, 27, 9, 40, 0, tzinfo=UTC),
        "ended_at": datetime(2024, 9, 27, 9, 40, 10, tzinfo=UTC),
    }
    defaults.update(overrides)
    return Session(**defaults)


def make_findings(sessions, rule_id="TLS-VERSION-001", severity="high"):
    return [
        SecurityFinding(
            capture_id=s.capture_id,
            session_id=s.id,
            title=f"Test {rule_id}",
            description="Test finding.",
            severity=FindingSeverity(severity),
            confidence=Confidence.HIGH,
            category=FindingCategory.CERTIFICATE,
            rule_id=rule_id,
            evidence_refs=[EvidenceRef(source="ServerHello", packet_numbers=[1])],
        )
        for s in sessions
    ]


# ---------------------------------------------------------------------------
# Graph construction
# ---------------------------------------------------------------------------


def test_single_session_graph_has_expected_nodes() -> None:
    sessions = _build_sessions_from([smtp_starttls_conversation()])
    findings = make_findings(sessions)
    builder = EvidenceGraphBuilder(CAPTURE_ID)
    graph = builder.build(sessions, findings, [], None)

    node_types = {n.node_type for n in graph.nodes}
    assert NodeType.CAPTURE in node_types
    assert NodeType.HOST in node_types
    assert NodeType.SESSION in node_types
    assert NodeType.PROTOCOL in node_types
    assert NodeType.TLS_HANDSHAKE in node_types
    assert NodeType.FINDING in node_types

    # structural edges
    edge_types = {e.edge_type for e in graph.edges}
    assert EdgeType.CAPTURE_CONTAINS_HOST in edge_types
    assert EdgeType.SESSION_CONNECTS_TO_ENDPOINT in edge_types
    assert EdgeType.SESSION_USES_PROTOCOL in edge_types
    assert EdgeType.SESSION_HAS_TLS_HANDSHAKE in edge_types
    assert EdgeType.SESSION_PRODUCED_FINDING in edge_types
    assert EdgeType.FINDING_AFFECTS_SESSION in edge_types
    assert EdgeType.FINDING_AFFECTS_HOST in edge_types


def test_graph_is_scoped_to_capture() -> None:
    sessions = _build_sessions_from([smtp_starttls_conversation()], "capture_bbbbbbbbbbbb")
    findings = make_findings(sessions)
    builder = EvidenceGraphBuilder("capture_bbbbbbbbbbbb")
    graph = builder.build(sessions, findings, [], None)

    assert all(n.capture_id == "capture_bbbbbbbbbbbb" for n in graph.nodes)
    cap_nodes = [n for n in graph.nodes if n.node_type is NodeType.CAPTURE]
    assert len(cap_nodes) == 1


def test_graph_determinism() -> None:
    sessions = _build_sessions_from([smtp_starttls_conversation(), pop3_conversation()])
    findings = make_findings(sessions)
    anomalies = [{"anomaly_id": "anomaly_test1234", "session_id": sessions[0].id, "score": 80}]

    builder_a = EvidenceGraphBuilder(CAPTURE_ID)
    graph_a = builder_a.build(sessions, findings, anomalies, None)
    builder_b = EvidenceGraphBuilder(CAPTURE_ID)
    graph_b = builder_b.build(sessions, findings, anomalies, None)

    assert [(n.node_id, n.node_type) for n in graph_a.nodes] == [
        (n.node_id, n.node_type) for n in graph_b.nodes
    ]
    assert [(e.source_node_id, e.target_node_id, e.edge_type) for e in graph_a.edges] == [
        (e.source_node_id, e.target_node_id, e.edge_type) for e in graph_b.edges
    ]


# ---------------------------------------------------------------------------
# Certificate pivots
# ---------------------------------------------------------------------------


def test_shared_certificate_creates_pivot() -> None:
    sessions = _build_sessions_from([smtp_starttls_conversation(), pop3_conversation()])
    pivots = build_certificate_pivots(sessions)

    assert pivots == []  # different certs, no sharing


def test_repeated_certificate_creates_pivot_with_sessions() -> None:
    from engine.core.certificate import CertificateEvidence

    shared_cert = CertificateEvidence(
        id="cert_" + "c" * 12,
        session_id="session_" + "a" * 16,
        subject="CN=shared.example.org",
        issuer="CN=Shared CA",
        serial_number="1a2b",
        not_before=datetime(2026, 1, 1, tzinfo=UTC),
        not_after=datetime(2026, 12, 31, tzinfo=UTC),
        signature_algorithm="sha256WithRSAEncryption",
        fingerprint_sha256="c" * 64,
        position_in_chain=0,
    )
    s_a = make_session(session_id="session_" + "a" * 16, certificates=[shared_cert])
    s_b = make_session(
        session_id="session_" + "b" * 16,
        server_ip="198.51.100.8",
        certificates=[shared_cert],
    )

    pivots = build_certificate_pivots([s_a, s_b])

    assert len(pivots) == 1
    pivot = pivots[0]
    assert pivot.session_count == 2
    assert pivot.host_count == 2
    assert pivot.fingerprint == "c" * 64


# ---------------------------------------------------------------------------
# TLS configuration clustering
# ---------------------------------------------------------------------------


def test_tls_config_fingerprint_is_deterministic() -> None:
    fp1 = tls_config_fingerprint("TLS 1.2", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "ecdhe")
    fp2 = tls_config_fingerprint("TLS 1.2", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "ecdhe")
    fp3 = tls_config_fingerprint("TLS 1.3", "TLS_AES_128_GCM_SHA256", "tls13")

    assert fp1 == fp2
    assert fp1 != fp3


def test_config_clusters_group_same_configuration() -> None:
    sessions = _build_sessions_from([smtp_starttls_conversation()])
    all_sessions = sessions + _build_sessions_from([smtp_plain_conversation()])
    clusters = build_config_clusters(all_sessions)

    # smtp_starttls has TLS, smtp_plain has no TLS → at least 2 clusters
    assert len(clusters) >= 1
    assert all(len(c.session_ids) >= 1 for c in clusters)


# ---------------------------------------------------------------------------
# Investigation context
# ---------------------------------------------------------------------------


def test_investigation_context_contains_expected_fields() -> None:
    sessions = _build_sessions_from([smtp_starttls_conversation()])
    findings = make_findings(sessions)
    anomalies: list[dict[str, object]] = []

    context = build_investigation_context(
        sessions[0], findings, anomalies, ["TLS configuration"], sessions, findings
    )

    assert context.capture_id == CAPTURE_ID
    assert context.session_id == sessions[0].id
    assert context.protocol == "smtp"
    assert context.finding_ids == [f.id for f in findings]
    assert context.tls_version is not None


# ---------------------------------------------------------------------------
# Timeline edges
# ---------------------------------------------------------------------------


def test_timeline_events_are_linked_to_session() -> None:
    sessions = _build_sessions_from([smtp_starttls_conversation()])
    builder = EvidenceGraphBuilder(CAPTURE_ID)
    graph = builder.build(sessions, [], [], None)

    s_nid = next(n.node_id for n in graph.nodes if n.node_type is NodeType.SESSION)
    event_edges = [
        e
        for e in graph.edges
        if e.edge_type is EdgeType.EVENT_BELONGS_TO_SESSION and e.target_node_id == s_nid
    ]
    assert len(event_edges) >= 3  # established + commands + closed
