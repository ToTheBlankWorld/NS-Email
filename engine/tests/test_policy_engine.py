"""Deterministic policy-engine tests: rules, unknowns, IDs, dedupe."""

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from engine.core.certificate import CertificateEvidence
from engine.core.events import EventDirection, EventType, SessionEvent
from engine.core.findings import FindingSeverity, SecurityFinding
from engine.core.session import Confidence, EmailProtocol, Session
from engine.core.tls import KeyExchange, TLSHandshake, TLSVersion
from engine.detection import (
    evaluate_session,
    evaluate_sessions,
    load_builtin_policy,
    load_policy_from_file,
)

CAPTURE_ID = "capture_aaaaaaaaaaaa"
SESSION_ID = "session_" + "a" * 16
CAPTURE_TIME = datetime(2026, 9, 1, 12, 0, 0, tzinfo=UTC)
POLICY = load_builtin_policy()


def make_session(**overrides: Any) -> Session:
    defaults: dict[str, Any] = {
        "id": SESSION_ID,
        "capture_id": CAPTURE_ID,
        "client_ip": "10.10.0.23",
        "server_ip": "198.51.100.7",
        "client_port": 49152,
        "server_port": 587,
        "protocol": EmailProtocol.SMTP,
        "started_at": CAPTURE_TIME,
        "ended_at": CAPTURE_TIME + timedelta(seconds=30),
    }
    defaults.update(overrides)
    return Session(**defaults)


def make_handshake(**overrides: Any) -> TLSHandshake:
    defaults: dict[str, Any] = {
        "session_id": SESSION_ID,
        "tls_version": TLSVersion.TLS_1_2,
        "cipher_suite": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        "cipher_suite_code": 0xC02F,
        "key_exchange": KeyExchange.ECDHE,
        "sni_server_name": "mail.example.org",
        "handshake_complete": True,
        "server_hello_packets": [7],
        "client_hello_packets": [6],
    }
    defaults.update(overrides)
    return TLSHandshake(**defaults)


def make_certificate(**overrides: Any) -> CertificateEvidence:
    defaults: dict[str, Any] = {
        "id": "cert_" + "c" * 12,
        "session_id": SESSION_ID,
        "subject": "CN=mail.example.org",
        "issuer": "CN=Test CA",
        "serial_number": "1a2b",
        "not_before": CAPTURE_TIME - timedelta(days=30),
        "not_after": CAPTURE_TIME + timedelta(days=30),
        "signature_algorithm": "sha256WithRSAEncryption",
        "public_key_algorithm": "RSA",
        "public_key_size_bits": 2048,
        "subject_alternative_names": ["mail.example.org"],
        "fingerprint_sha256": "c" * 64,
        "position_in_chain": 0,
    }
    defaults.update(overrides)
    return CertificateEvidence(**defaults)


def make_auth_event(**overrides: Any) -> SessionEvent:
    defaults: dict[str, Any] = {
        "seq": 2,
        "type": EventType.AUTHENTICATION,
        "direction": EventDirection.CLIENT_TO_SERVER,
        "timestamp": CAPTURE_TIME,
        "packet_numbers": [11, 12],
        "detail": {"command": "AUTH", "mechanism": "LOGIN", "credential_data": "redacted"},
    }
    defaults.update(overrides)
    return SessionEvent(**defaults)


def severities(findings: list[SecurityFinding]) -> set[FindingSeverity]:
    return {finding.severity for finding in findings}


def rule_findings(findings: list[SecurityFinding], rule_id: str) -> list[SecurityFinding]:
    return [finding for finding in findings if finding.rule_id == rule_id]


# ---------------------------------------------------------------------------
# Policy loading and validation
# ---------------------------------------------------------------------------


def test_builtin_policy_loads_with_identity_and_controls() -> None:
    policy = load_builtin_policy()

    assert policy.id == "securemailscope-baseline"
    assert policy.version == "1.0"
    assert policy.tls.minimum_version == "TLS 1.2"
    assert policy.forward_secrecy.required is True


def test_policy_loader_rejects_invalid_json(tmp_path) -> None:
    bad = tmp_path / "policy.json"
    bad.write_text("{not json", encoding="utf-8")

    with pytest.raises(ValueError, match="not valid JSON"):
        load_policy_from_file(bad)


def test_policy_loader_rejects_unknown_keys(tmp_path) -> None:
    bad = tmp_path / "policy.json"
    bad.write_text('{"id": "x", "totally_unknown": 1}', encoding="utf-8")

    with pytest.raises(ValueError, match="failed validation"):
        load_policy_from_file(bad)


def test_policy_loader_rejects_oversized_documents(tmp_path, monkeypatch) -> None:
    import engine.detection.policy as policy_module

    big = tmp_path / "policy.json"
    big.write_text('{"id": "oversized-policy-document"}', encoding="utf-8")
    monkeypatch.setattr(policy_module, "MAX_POLICY_FILE_BYTES", 4)

    with pytest.raises(ValueError, match="exceeds"):
        load_policy_from_file(big)


def test_custom_valid_policy_is_accepted(tmp_path) -> None:
    custom = tmp_path / "policy.json"
    custom.write_text('{"id": "acme-mail", "version": "2.0"}', encoding="utf-8")

    policy = load_policy_from_file(custom)

    assert policy.id == "acme-mail"
    assert policy.tls.minimum_version == "TLS 1.2"  # defaults fill the rest


# ---------------------------------------------------------------------------
# TLS version rule: negotiated version only
# ---------------------------------------------------------------------------


def test_tls10_negotiated_produces_high_finding() -> None:
    session = make_session(handshake=make_handshake(tls_version=TLSVersion.TLS_1_0))

    findings = evaluate_session(session, POLICY)

    version_findings = rule_findings(findings, "TLS-VERSION-001")
    assert len(version_findings) == 1
    assert version_findings[0].severity is FindingSeverity.HIGH
    assert version_findings[0].observed_value == "TLS 1.0"
    assert version_findings[0].evidence_refs[0].packet_numbers == [7]


def test_offered_versions_alone_never_produce_a_finding() -> None:
    # Server picked TLS 1.2 — even if the client offered 1.3 first.
    session = make_session(handshake=make_handshake(tls_version=TLSVersion.TLS_1_2))

    findings = evaluate_session(session, POLICY)

    assert rule_findings(findings, "TLS-VERSION-001") == []


def test_tls13_and_tls12_modern_sessions_are_clean() -> None:
    for version in (TLSVersion.TLS_1_2, TLSVersion.TLS_1_3):
        session = make_session(handshake=make_handshake(tls_version=version))
        assert rule_findings(evaluate_session(session, POLICY), "TLS-VERSION-001") == []


def test_ssl3_negotiated_is_critical() -> None:
    session = make_session(handshake=make_handshake(tls_version=TLSVersion.SSL_3_0))

    findings = evaluate_session(session, POLICY)

    assert severities(rule_findings(findings, "TLS-VERSION-001")) == {FindingSeverity.CRITICAL}


def test_unknown_tls_version_is_not_judged() -> None:
    session = make_session(handshake=make_handshake(tls_version=TLSVersion.UNKNOWN))

    assert rule_findings(evaluate_session(session, POLICY), "TLS-VERSION-001") == []


# ---------------------------------------------------------------------------
# Cipher suite rules: classification-driven, unknown is informational
# ---------------------------------------------------------------------------


def test_prohibited_cipher_produces_critical_finding() -> None:
    session = make_session(
        handshake=make_handshake(
            cipher_suite="TLS_RSA_WITH_RC4_128_SHA",
            cipher_suite_code=0x0005,
            key_exchange=KeyExchange.RSA,
        )
    )

    findings = rule_findings(evaluate_session(session, POLICY), "CIPHER-SELECTED-001")

    assert severities(findings) == {FindingSeverity.CRITICAL}


def test_legacy_cipher_produces_low_finding() -> None:
    session = make_session(
        handshake=make_handshake(
            cipher_suite="TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
            cipher_suite_code=0xC013,
        )
    )

    findings = rule_findings(evaluate_session(session, POLICY), "CIPHER-SELECTED-001")

    assert severities(findings) == {FindingSeverity.LOW}


def test_unknown_cipher_is_informational_not_weak() -> None:
    session = make_session(
        handshake=make_handshake(cipher_suite="0xAAAA", cipher_suite_code=0xAAAA)
    )

    findings = evaluate_session(session, POLICY)

    selected = rule_findings(findings, "CIPHER-SELECTED-001")
    assert selected == []  # no weakness claim
    unknown = rule_findings(findings, "CIPHER-UNKNOWN-001")
    assert len(unknown) == 1
    assert unknown[0].severity is FindingSeverity.INFO
    assert "not in the local registry" in unknown[0].description


def test_modern_aead_cipher_produces_no_finding() -> None:
    session = make_session(handshake=make_handshake())

    assert rule_findings(evaluate_session(session, POLICY), "CIPHER-SELECTED-001") == []


# ---------------------------------------------------------------------------
# Key exchange and forward secrecy
# ---------------------------------------------------------------------------


def test_static_rsa_key_exchange_produces_medium_finding() -> None:
    session = make_session(
        handshake=make_handshake(
            cipher_suite="TLS_RSA_WITH_AES_128_GCM_SHA256",
            cipher_suite_code=0x009C,
            key_exchange=KeyExchange.RSA,
        )
    )

    findings = rule_findings(evaluate_session(session, POLICY), "KEYEX-001")

    assert severities(findings) == {FindingSeverity.MEDIUM}
    assert "forward secrecy" in findings[0].description


def test_undeterminable_key_exchange_is_informational_only() -> None:
    session = make_session(
        handshake=make_handshake(key_exchange=KeyExchange.UNKNOWN, cipher_suite=None)
    )

    findings = evaluate_session(session, POLICY)

    assert rule_findings(findings, "KEYEX-001") == []
    fs = rule_findings(findings, "FS-001")
    assert len(fs) == 1
    assert fs[0].severity is FindingSeverity.INFO


def test_tls13_key_exchange_produces_no_fs_finding() -> None:
    session = make_session(handshake=make_handshake(tls_version=TLSVersion.TLS_1_3))

    findings = evaluate_session(session, POLICY)

    assert rule_findings(findings, "KEYEX-001") == []
    assert rule_findings(findings, "FS-001") == []


# ---------------------------------------------------------------------------
# Certificate rules
# ---------------------------------------------------------------------------


def test_expired_certificate_measured_against_capture_time() -> None:
    session = make_session(
        certificates=[make_certificate(not_after=CAPTURE_TIME - timedelta(days=15))]
    )

    findings = rule_findings(evaluate_session(session, POLICY), "CERT-VALIDITY-001")

    assert len(findings) == 1
    assert findings[0].severity is FindingSeverity.HIGH
    assert findings[0].observed_value.startswith("valid until 2026-08-")
    # the reference time is the capture time, not the analysis date
    assert "2026-09-01" in findings[0].description


def test_not_yet_valid_certificate_produces_medium_finding() -> None:
    session = make_session(
        certificates=[make_certificate(not_before=CAPTURE_TIME + timedelta(days=15))]
    )

    findings = rule_findings(evaluate_session(session, POLICY), "CERT-VALIDITY-001")

    assert severities(findings) == {FindingSeverity.MEDIUM}


def test_valid_certificate_produces_no_validity_finding() -> None:
    session = make_session(certificates=[make_certificate()])

    assert rule_findings(evaluate_session(session, POLICY), "CERT-VALIDITY-001") == []


def test_weak_public_key_produces_high_finding() -> None:
    session = make_session(certificates=[make_certificate(public_key_size_bits=1024)])

    findings = rule_findings(evaluate_session(session, POLICY), "CERT-KEY-001")

    assert severities(findings) == {FindingSeverity.HIGH}
    assert findings[0].observed_value == "RSA 1024 bits"


def test_unknown_key_algorithm_is_informational_only() -> None:
    session = make_session(
        certificates=[make_certificate(public_key_algorithm="McEliece", public_key_size_bits=None)]
    )

    findings = evaluate_session(session, POLICY)

    key_findings = rule_findings(findings, "CERT-KEY-001")
    assert severities(key_findings) == {FindingSeverity.INFO}


def test_sha1_signature_produces_high_finding() -> None:
    session = make_session(
        certificates=[make_certificate(signature_algorithm="sha1WithRSAEncryption")]
    )

    findings = rule_findings(evaluate_session(session, POLICY), "CERT-SIG-001")

    assert severities(findings) == {FindingSeverity.HIGH}


def test_md5_signature_produces_critical_finding() -> None:
    session = make_session(
        certificates=[make_certificate(signature_algorithm="md5WithRSAEncryption")]
    )

    findings = rule_findings(evaluate_session(session, POLICY), "CERT-SIG-001")

    assert severities(findings) == {FindingSeverity.CRITICAL}


def test_sha256_signature_produces_no_finding() -> None:
    session = make_session(certificates=[make_certificate()])

    assert rule_findings(evaluate_session(session, POLICY), "CERT-SIG-001") == []


def test_hostname_mismatch_with_full_evidence() -> None:
    session = make_session(
        handshake=make_handshake(),
        certificates=[make_certificate(subject_alternative_names=["other.example.org"])],
    )

    findings = rule_findings(evaluate_session(session, POLICY), "CERT-IDENTITY-001")

    assert len(findings) == 1
    assert findings[0].severity is FindingSeverity.HIGH
    assert "mail.example.org" in findings[0].observed_value


def test_wildcard_san_matches_requested_hostname() -> None:
    session = make_session(
        certificates=[make_certificate(subject_alternative_names=["*.example.org"])]
    )

    assert rule_findings(evaluate_session(session, POLICY), "CERT-IDENTITY-001") == []


def test_missing_sni_never_claims_mismatch() -> None:
    session = make_session(
        handshake=make_handshake(sni_server_name=None),
        certificates=[make_certificate(subject_alternative_names=["other.example.org"])],
    )

    assert rule_findings(evaluate_session(session, POLICY), "CERT-IDENTITY-001") == []


def test_missing_san_never_claims_mismatch() -> None:
    session = make_session(certificates=[make_certificate(subject_alternative_names=[])])

    assert rule_findings(evaluate_session(session, POLICY), "CERT-IDENTITY-001") == []


def test_chain_missing_issuer_is_informational_not_invalid() -> None:
    session = make_session(certificates=[make_certificate()])  # issuer 'CN=Test CA' absent

    findings = rule_findings(evaluate_session(session, POLICY), "CERT-CHAIN-001")

    assert len(findings) == 1
    assert findings[0].severity is FindingSeverity.INFO
    assert "not a validation failure" in findings[0].description


def test_self_signed_leaf_is_low_observation() -> None:
    session = make_session(
        certificates=[make_certificate(issuer="CN=mail.example.org", subject="CN=mail.example.org")]
    )

    findings = rule_findings(evaluate_session(session, POLICY), "CERT-SELF-SIGNED-001")

    assert severities(findings) == {FindingSeverity.LOW}


# ---------------------------------------------------------------------------
# STARTTLS, plaintext authentication, handshake failure, plaintext sessions
# ---------------------------------------------------------------------------


def starttls_session(**starttls_overrides: Any) -> Session:
    from engine.core.session import StarttlsObservation

    handshake = starttls_overrides.pop("handshake", make_handshake())
    defaults: dict[str, Any] = {"advertised": True, "requested": True, "response_seen": True}
    defaults.update(starttls_overrides)
    starttls = StarttlsObservation(**defaults)
    return make_session(starttls=starttls, handshake=handshake)


def test_starttls_advertised_but_never_requested() -> None:
    session = starttls_session(requested=False, response_seen=False, handshake=None)

    findings = rule_findings(evaluate_session(session, POLICY), "STARTTLS-001")

    assert len(findings) == 1
    assert findings[0].observed_value == "STARTTLS advertised; no request observed"


def test_starttls_requested_but_not_accepted() -> None:
    session = starttls_session(response_seen=False, handshake=None)

    findings = rule_findings(evaluate_session(session, POLICY), "STARTTLS-001")

    assert findings[0].observed_value == "STARTTLS requested; no acceptance observed"


def test_starttls_accepted_but_no_tls_handshake() -> None:
    session = starttls_session(handshake=None)

    findings = rule_findings(evaluate_session(session, POLICY), "STARTTLS-001")

    assert findings[0].observed_value == "no TLS handshake after acceptance"
    assert findings[0].confidence is Confidence.MEDIUM


def test_successful_starttls_with_tls_produces_no_starttls_finding() -> None:
    session = starttls_session()

    assert rule_findings(evaluate_session(session, POLICY), "STARTTLS-001") == []


def test_plaintext_authentication_produces_high_finding_with_redaction() -> None:
    session = make_session(handshake=None, events=[make_auth_event()])

    findings = rule_findings(evaluate_session(session, POLICY), "AUTH-PLAINTEXT-001")

    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity is FindingSeverity.HIGH
    assert finding.evidence_refs[0].packet_numbers == [11, 12]
    assert finding.observed_value == "AUTH"
    # credential values were already redacted at the event layer; the
    # finding must not reintroduce them
    assert "hunter2" not in finding.model_dump_json()


def test_no_plaintext_auth_finding_when_authentication_stays_clean() -> None:
    session = make_session(handshake=make_handshake())

    assert rule_findings(evaluate_session(session, POLICY), "AUTH-PLAINTEXT-001") == []


def test_incomplete_tls_handshake_is_informational() -> None:
    session = make_session(
        handshake=make_handshake(
            handshake_complete=False,
            completeness_reason="no ServerHello observed",
            cipher_suite=None,
            cipher_suite_code=None,
            key_exchange=KeyExchange.UNKNOWN,
        )
    )

    findings = rule_findings(evaluate_session(session, POLICY), "TLS-FAILURE-001")

    assert severities(findings) == {FindingSeverity.INFO}
    assert "terminated before completion" in findings[0].title


def test_plaintext_email_session_produces_medium_finding() -> None:
    session = make_session(handshake=None)

    findings = rule_findings(evaluate_session(session, POLICY), "PLAINTEXT-001")

    assert severities(findings) == {FindingSeverity.MEDIUM}


def test_implicit_tls_session_is_exempt_from_starttls_findings() -> None:
    session = make_session(implicit_tls=True, handshake=make_handshake(), starttls=None)

    findings = evaluate_session(session, POLICY)

    assert rule_findings(findings, "STARTTLS-001") == []
    assert rule_findings(findings, "PLAINTEXT-001") == []


def test_unknown_protocol_sessions_are_skipped() -> None:
    session = make_session(protocol=None, handshake=None)

    findings = evaluate_session(session, POLICY)

    assert rule_findings(findings, "PLAINTEXT-001") == []


# ---------------------------------------------------------------------------
# Determinism, duplicates, multi-session isolation
# ---------------------------------------------------------------------------


def test_finding_ids_are_deterministic() -> None:
    session_a = make_session(handshake=make_handshake(tls_version=TLSVersion.TLS_1_0))
    session_b = make_session(handshake=make_handshake(tls_version=TLSVersion.TLS_1_0))

    first = rule_findings(evaluate_session(session_a, POLICY), "TLS-VERSION-001")[0]
    second = rule_findings(evaluate_session(session_b, POLICY), "TLS-VERSION-001")[0]

    assert first.id == second.id
    assert first.id.startswith("finding_")
    int(first.id.split("_")[1], 16)


def test_different_observed_values_produce_different_ids() -> None:
    session_a = make_session(handshake=make_handshake(tls_version=TLSVersion.TLS_1_0))
    session_b = make_session(handshake=make_handshake(tls_version=TLSVersion.TLS_1_1))

    id_a = rule_findings(evaluate_session(session_a, POLICY), "TLS-VERSION-001")[0].id
    id_b = rule_findings(evaluate_session(session_b, POLICY), "TLS-VERSION-001")[0].id

    assert id_a != id_b


def test_duplicate_findings_collapse_within_one_evaluation() -> None:
    session = make_session(handshake=make_handshake(tls_version=TLSVersion.TLS_1_0))

    findings = evaluate_session(session, POLICY)

    assert len({finding.id for finding in findings}) == len(findings)


def test_multiple_sessions_keep_their_own_scope() -> None:
    session_a = make_session(handshake=make_handshake(tls_version=TLSVersion.TLS_1_0))
    session_b = make_session(
        id="session_" + "b" * 16,
        handshake=make_handshake(tls_version=TLSVersion.TLS_1_0),
    )

    findings = evaluate_sessions([session_a, session_b], POLICY)

    version_findings = rule_findings(findings, "TLS-VERSION-001")
    assert {f.session_id for f in version_findings} == {session_a.id, session_b.id}


def test_every_finding_carries_evidence_refs() -> None:
    from conftest import (
        imap_conversation,
        pop3_conversation,
        smtp_plain_conversation,
        smtp_starttls_conversation,
    )
    from engine.analysis import analyze_capture_packets

    packets = [
        *smtp_plain_conversation(),
        *smtp_starttls_conversation(),
        *imap_conversation(),
        *pop3_conversation(),
    ]
    result = analyze_capture_packets(CAPTURE_ID, packets)
    findings = evaluate_sessions(result.sessions, POLICY)

    assert findings, "the mixed conversations must produce findings"
    for finding in findings:
        assert finding.capture_id == CAPTURE_ID
        assert finding.session_id
        assert finding.evidence_refs or finding.rule_id == "PLAINTEXT-001"
