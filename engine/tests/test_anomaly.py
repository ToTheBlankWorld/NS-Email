"""Anomaly engine tests: features, baseline, scoring, determinism."""

from datetime import UTC, datetime, timedelta
from typing import Any

from engine.core.session import EmailProtocol, Session
from engine.core.tls import KeyExchange, TlsExtension, TLSHandshake, TLSVersion
from engine.ml.anomaly import (
    AnomalyEngine,
    anomaly_band,
)
from engine.ml.features import (
    FEATURE_NAMES,
    FEATURE_SCHEMA_VERSION,
    SessionFeatures,
    extract_features,
)

CAPTURE_ID = "capture_aaaaaaaaaaaa"
T0 = datetime(2024, 9, 27, 9, 40, 0, tzinfo=UTC)


def make_session(**overrides: Any) -> Session:
    handshake = overrides.pop("handshake", make_handshake())
    if "session_id" in overrides:
        overrides["id"] = overrides.pop("session_id")
    defaults: dict[str, Any] = {
        "id": "session_" + "a" * 16,
        "capture_id": CAPTURE_ID,
        "client_ip": "10.10.0.23",
        "server_ip": "198.51.100.7",
        "client_port": 49152,
        "server_port": 587,
        "protocol": EmailProtocol.SMTP,
        "implicit_tls": False,
        "started_at": T0,
        "ended_at": T0 + timedelta(seconds=10),
        "packet_count": 12,
        "bytes_client_to_server": 200,
        "bytes_server_to_client": 300,
        "complete": True,
        "handshake": handshake,
    }
    defaults.update(overrides)
    return Session(**defaults)


def make_handshake(**overrides: Any) -> TLSHandshake:
    defaults: dict[str, Any] = {
        "session_id": "session_" + "a" * 16,
        "tls_version": TLSVersion.TLS_1_2,
        "cipher_suite": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        "cipher_suite_code": 0xC02F,
        "key_exchange": KeyExchange.ECDHE,
        "sni_server_name": "mail.example.org",
        "handshake_complete": True,
        "cipher_suites_offered": [
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_RSA_WITH_AES_128_GCM_SHA256",
        ],
        "extensions": [
            TlsExtension(type_code=0, name="server_name", length=21, value="mail.example.org"),
            TlsExtension(
                type_code=16, name="application_layer_protocol_negotiation", length=7, value="smtp"
            ),
        ],
        "client_hello_packets": [6],
        "server_hello_packets": [8],
    }
    defaults.update(overrides)
    return TLSHandshake(**defaults)


# ---------------------------------------------------------------------------
# Feature extraction
# ---------------------------------------------------------------------------


def test_feature_extraction_from_session() -> None:
    session = make_session()
    features = extract_features(session)

    assert features.feature_schema_version == FEATURE_SCHEMA_VERSION
    assert features.protocol > 0  # smtp in the vocabulary
    assert features.server_port == 587
    assert features.duration_seconds == 10.0
    assert features.packet_count == 12
    assert features.complete == 1
    assert features.has_tls == 1
    assert features.tls_version > 0  # TLS 1.2 in the vocabulary
    assert features.cipher_class > 0  # modern_aead
    assert features.offered_cipher_count == 2
    assert features.key_exchange > 0  # ecdhe
    assert features.extension_count == 2
    assert features.has_sni == 1
    assert features.alpn_count == 1
    assert features.certificate_count == 0
    assert features.has_implicit_tls == 0


def test_plaintext_session_has_zero_tls_features() -> None:
    session = make_session(handshake=None, protocol=EmailProtocol.SMTP)
    features = extract_features(session)

    assert features.has_tls == 0
    assert features.tls_version == 0  # "unknown" is index 0
    assert features.cipher_class == 0  # "unknown" is index 0
    assert features.offered_cipher_count == 0


def test_feature_vector_is_sanitized() -> None:
    features = SessionFeatures(
        protocol=0,
        server_port=587,
        duration_seconds=1e15,
        packet_count=5,
        bytes_client_to_server=1,
        bytes_server_to_client=1,
        complete=1,
        has_tls=0,
        tls_version=0,
        cipher_class=0,
        offered_cipher_count=0,
        key_exchange=0,
        extension_count=0,
        has_sni=0,
        alpn_count=0,
        certificate_count=0,
        certificate_max_key_bits=0,
        certificate_min_validity_days=0,
        has_implicit_tls=0,
    )
    vector = features.numeric_vector()
    assert all(abs(v) <= 1e12 for v in vector)


def test_feature_vector_is_reproducible() -> None:
    session = make_session()
    first = extract_features(session).numeric_vector()
    second = extract_features(session).numeric_vector()

    assert first == second


# ---------------------------------------------------------------------------
# Baseline and scoring
# ---------------------------------------------------------------------------


def _build_sessions(count: int, **handshake_overrides: Any) -> list[Session]:
    sessions = []
    for i in range(count):
        session_id = f"session_{i:04x}{'a' * 12}"
        handshake = make_handshake(**handshake_overrides)
        sessions.append(
            make_session(
                session_id=session_id,
                handshake=handshake,
                packet_count=12 + i,  # natural variation
                duration_seconds=10.0 + i * 0.5,
            )
        )
    return sessions


def test_insufficient_baseline_returns_status_not_scores() -> None:
    sessions = _build_sessions(3)
    engine = AnomalyEngine(min_baseline_sessions=8)

    report = engine.analyze(sessions)

    assert report.status == "completed"  # per-group insufficient, not global error
    assert all(a.status == "insufficient_evidence" for a in report.anomalies)
    assert all(a.score is None for a in report.anomalies)


def test_homogeneous_sessions_are_mostly_normal() -> None:
    """Homogeneous sessions with natural variation: most should look normal.

    The boundary point may score slightly elevated (edge of the cluster),
    but no session should reach highly_anomalous territory.
    """
    sessions = _build_sessions(12)
    engine = AnomalyEngine(min_baseline_sessions=8)

    report = engine.analyze(sessions)

    assert report.status == "completed"
    assert report.summary["total_evaluated"] == 12
    assert report.summary.get("highly_anomalous", 0) == 0
    unusual_or_worse = (
        report.summary.get("unusual", 0)
        + report.summary.get("anomalous", 0)
        + report.summary.get("highly_anomalous", 0)
    )
    assert unusual_or_worse <= 3  # at most 25% flagged with tight data


def test_unusual_session_scores_higher_than_baseline() -> None:
    normal_sessions = _build_sessions(15)
    unusual_session = make_session(
        session_id="session_" + "f" * 16,
        handshake=make_handshake(
            tls_version=TLSVersion.TLS_1_0,
            cipher_suite="TLS_RSA_WITH_RC4_128_SHA",
            cipher_suite_code=0x0005,
            key_exchange=KeyExchange.RSA,
            sni_server_name=None,
        ),
    )
    all_sessions = [*normal_sessions, unusual_session]
    engine = AnomalyEngine(min_baseline_sessions=8)

    report = engine.analyze(all_sessions)

    assert report.status == "completed"
    unusual_result = next(a for a in report.anomalies if a.session_id == unusual_session.id)
    normal_avg = sum(a.score for a in report.anomalies if a.session_id != unusual_session.id) / len(
        normal_sessions
    )
    assert unusual_result.score is not None
    assert unusual_result.score > normal_avg, "unusual session must score above baseline"


def test_anomaly_bands_are_bounded_and_documented() -> None:
    assert anomaly_band(0) == "normal"
    assert anomaly_band(30) == "normal"
    assert anomaly_band(50) == "unusual"
    assert anomaly_band(70) == "anomalous"
    assert anomaly_band(85) == "highly_anomalous"
    assert anomaly_band(100) == "highly_anomalous"


def test_anomaly_scores_are_bounded() -> None:
    sessions = _build_sessions(15)
    engine = AnomalyEngine(min_baseline_sessions=8)

    report = engine.analyze(sessions)

    for anomaly in report.anomalies:
        if anomaly.score is not None:
            assert 0 <= anomaly.score <= 100


def test_deterministic_repeated_analysis() -> None:
    sessions = _build_sessions(15)
    sessions.append(
        make_session(
            session_id="session_" + "f" * 16,
            handshake=make_handshake(tls_version=TLSVersion.TLS_1_0, cipher_suite_code=0xC013),
        )
    )
    engine = AnomalyEngine(min_baseline_sessions=8)

    first = engine.analyze(sessions)
    second = engine.analyze(sessions)

    assert [(a.session_id, a.status, a.score) for a in first.anomalies] == [
        (a.session_id, a.status, a.score) for a in second.anomalies
    ]


def test_protocol_grouping_separates_smtp_and_pop3() -> None:
    smtp_sessions = _build_sessions(10)
    pop3_sessions = [
        make_session(
            session_id=f"session_{i:02x}{'p' * 0}{'a' * 14}",
            server_port=110,
            protocol=EmailProtocol.POP3,
            handshake=None,  # plaintext POP3: separate group
        )
        for i in range(3)
    ]

    engine = AnomalyEngine(min_baseline_sessions=8)
    report = engine.analyze(smtp_sessions + pop3_sessions)

    assert report.status == "completed"
    # pop3 group has 3 < 8 baseline → insufficient_evidence
    pop3_anomalies = [a for a in report.anomalies if a.protocol == "pop3"]
    assert all(a.status == "insufficient_evidence" for a in pop3_anomalies)
    # smtp group has enough → normal scoring
    smtp_anomalies = [a for a in report.anomalies if a.protocol == "smtp"]
    assert all(a.status != "insufficient_evidence" for a in smtp_anomalies)


# ---------------------------------------------------------------------------
# NaN / Infinity handling
# ---------------------------------------------------------------------------


def test_nan_and_infinity_features_are_sanitized() -> None:
    session = make_session(
        started_at=T0,
        ended_at=None,  # no duration → 0
    )
    features = extract_features(session)
    vector = features.numeric_vector()

    assert all(v == v for v in vector), "NaN must not leak into feature vectors"
    assert all(abs(v) != float("inf") for v in vector), "Infinity must not leak"


# ---------------------------------------------------------------------------
# Evidence refs
# ---------------------------------------------------------------------------


def test_anomalies_carry_evidence_refs() -> None:
    sessions = _build_sessions(12)
    engine = AnomalyEngine(min_baseline_sessions=8)

    report = engine.analyze(sessions)

    scored = [a for a in report.anomalies if a.score is not None]
    for anomaly in scored:
        assert anomaly.anomaly_id.startswith("anomaly_")
        assert anomaly.evidence_refs  # non-empty for TLS sessions


# ---------------------------------------------------------------------------
# Engine test infrastructure validation
# ---------------------------------------------------------------------------


def test_feature_names_match_vector_length() -> None:
    session = make_session()
    features = extract_features(session)

    assert len(features.numeric_vector()) == len(FEATURE_NAMES)
