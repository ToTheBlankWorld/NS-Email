"""Tests for X.509 certificate evidence."""

from datetime import UTC, datetime
from typing import Any

import pytest
from engine.core.certificate import CertificateEvidence
from pydantic import ValidationError

NOT_BEFORE = datetime(2025, 1, 1, tzinfo=UTC)
NOT_AFTER = datetime(2026, 1, 1, tzinfo=UTC)


def build_certificate(**overrides: Any) -> CertificateEvidence:
    defaults: dict[str, Any] = {
        "session_id": "session123",
        "subject": "CN=mail.example.com",
        "issuer": "CN=Example Root CA, O=Example Authority",
        "serial_number": "0A:1B:2C",
        "not_before": NOT_BEFORE,
        "not_after": NOT_AFTER,
        "signature_algorithm": "sha256WithRSAEncryption",
        "public_key_algorithm": "RSA",
        "public_key_size_bits": 2048,
        "subject_alternative_names": ["mail.example.com"],
        "fingerprint_sha256": "C" * 64,
    }
    defaults.update(overrides)
    return CertificateEvidence(**defaults)


def test_hex_fields_are_normalized() -> None:
    certificate = build_certificate()

    assert certificate.serial_number == "0a1b2c"
    assert certificate.fingerprint_sha256 == "c" * 64


def test_fingerprint_is_optional() -> None:
    certificate = build_certificate(fingerprint_sha256=None)

    assert certificate.fingerprint_sha256 is None


@pytest.mark.parametrize("serial", ["", "xyz", "0x1g"])
def test_rejects_non_hex_serial_numbers(serial: str) -> None:
    with pytest.raises(ValidationError):
        build_certificate(serial_number=serial)


def test_rejects_negative_key_size() -> None:
    with pytest.raises(ValidationError):
        build_certificate(public_key_size_bits=-2048)


def test_expiry_is_checked_against_not_after() -> None:
    certificate = build_certificate()

    assert certificate.is_expired(datetime(2026, 6, 1, tzinfo=UTC)) is True
    assert certificate.is_expired(datetime(2025, 6, 1, tzinfo=UTC)) is False


def test_expiry_boundary_is_exclusive() -> None:
    certificate = build_certificate()

    assert certificate.is_expired(NOT_AFTER) is False
