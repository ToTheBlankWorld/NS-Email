"""Cross-cutting evidence model guarantees.

Forensic evidence must survive a JSON round trip unchanged (the canonical
persistence format) and must remain immutable once recorded.
"""

from datetime import UTC, datetime
from ipaddress import ip_address
from typing import Any

import pytest
from engine.core.capture import Capture, CaptureFormat, CaptureStatus
from engine.core.certificate import CertificateEvidence
from engine.core.findings import (
    EvidenceRef,
    FindingCategory,
    FindingSeverity,
    SecurityFinding,
)
from engine.core.session import Confidence, EmailProtocol, Orientation, Session
from engine.core.tls import KeyExchange, TLSHandshake, TLSVersion
from pydantic import ValidationError

T0 = datetime(2026, 1, 1, tzinfo=UTC)
T1 = datetime(2026, 6, 1, tzinfo=UTC)
T2 = datetime(2026, 9, 27, 12, 30, 0, tzinfo=UTC)


def sample_evidence() -> dict[str, Any]:
    capture = Capture(
        id="capture_" + "b" * 12,
        filename="hq-mail.pcapng",
        size_bytes=8192,
        sha256="b" * 64,
        format=CaptureFormat.PCAPNG,
        status=CaptureStatus.READY,
        packet_count=12,
        ingested_at=T2,
        capture_started_at=T0,
        capture_ended_at=T1,
        duration_seconds=1.5,
        link_type="Ethernet",
    )
    session = Session(
        id="session_" + "0a1b" * 4,
        capture_id=capture.id,
        client_ip=ip_address("10.10.0.23"),
        server_ip=ip_address("198.51.100.7"),
        client_port=51520,
        server_port=993,
        protocol=EmailProtocol.IMAP,
        confidence=Confidence.HIGH,
        orientation=Orientation.CLIENT_SERVER,
        implicit_tls=True,
        started_at=T0,
        ended_at=T1,
        duration_seconds=1.5,
        packet_count=18,
        bytes_client_to_server=256,
        bytes_server_to_client=512,
        complete=True,
    )
    handshake = TLSHandshake(
        session_id=session.id,
        tls_version=TLSVersion.TLS_1_2,
        cipher_suite="TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        key_exchange=KeyExchange.ECDHE,
        sni_server_name="mail.example.com",
        started_at=T0,
    )
    certificate = CertificateEvidence(
        session_id=session.id,
        subject="CN=mail.example.com",
        issuer="CN=Example Root CA, O=Example Authority",
        serial_number="0A:1B:2C",
        not_before=T0,
        not_after=T1,
        signature_algorithm="sha256WithRSAEncryption",
        public_key_algorithm="RSA",
        public_key_size_bits=2048,
        subject_alternative_names=["mail.example.com", "smtp.example.com"],
        fingerprint_sha256="c" * 64,
    )
    finding = SecurityFinding(
        capture_id=capture.id,
        session_id=session.id,
        title="Server certificate is self-signed",
        description="The observed certificate was issued by itself, not a known authority.",
        severity=FindingSeverity.MEDIUM,
        confidence=Confidence.HIGH,
        category=FindingCategory.CERTIFICATE,
        rule_id="certificate.self-signed",
        evidence_refs=[
            EvidenceRef(source="ServerHello", packet_numbers=[9]),
            EvidenceRef(source="Certificate(0)", packet_numbers=[10]),
        ],
        observed_value="self-signed certificate",
        expected_value="certificate issued by a known authority",
        details={"subject": certificate.subject},
        detected_at=T2,
    )
    return {
        "capture": capture,
        "session": session,
        "handshake": handshake,
        "certificate": certificate,
        "finding": finding,
    }


@pytest.mark.parametrize(
    "model_name", ["capture", "session", "handshake", "certificate", "finding"]
)
def test_evidence_survives_json_round_trip(model_name: str) -> None:
    model = sample_evidence()[model_name]

    restored = type(model).model_validate_json(model.model_dump_json())

    assert restored == model


def test_evidence_is_immutable_once_recorded() -> None:
    capture = sample_evidence()["capture"]

    with pytest.raises(ValidationError, match="frozen"):
        capture.sha256 = "d" * 64


def test_every_evidence_model_extends_forensic_base() -> None:
    from engine.core.base import ForensicBase

    for model in sample_evidence().values():
        assert isinstance(model, ForensicBase)
