"""Tests for TLS protocol taxonomy and handshake evidence."""

from datetime import UTC, datetime
from typing import Any

import pytest
from engine.core.tls import KeyExchange, TLSHandshake, TLSVersion
from pydantic import ValidationError

STARTED_AT = datetime(2026, 9, 27, 12, 0, 0, tzinfo=UTC)


def build_handshake(**overrides: Any) -> TLSHandshake:
    defaults: dict[str, Any] = {"session_id": "session123"}
    defaults.update(overrides)
    return TLSHandshake(**defaults)


@pytest.mark.parametrize(
    ("tls_version", "deprecated"),
    [
        (TLSVersion.SSL_2_0, True),
        (TLSVersion.SSL_3_0, True),
        (TLSVersion.TLS_1_0, True),
        (TLSVersion.TLS_1_1, True),
        (TLSVersion.TLS_1_2, False),
        (TLSVersion.TLS_1_3, False),
        (TLSVersion.UNKNOWN, False),
    ],
)
def test_deprecated_protocol_versions(tls_version: TLSVersion, deprecated: bool) -> None:
    assert tls_version.is_deprecated is deprecated


@pytest.mark.parametrize(
    ("key_exchange", "forward_secrecy"),
    [
        (KeyExchange.RSA, False),
        (KeyExchange.DH, False),
        (KeyExchange.ECDH, False),
        (KeyExchange.DHE, True),
        (KeyExchange.ECDHE, True),
        (KeyExchange.TLS_1_3, True),
        (KeyExchange.UNKNOWN, False),
    ],
)
def test_forward_secrecy_by_key_exchange(key_exchange: KeyExchange, forward_secrecy: bool) -> None:
    assert key_exchange.provides_forward_secrecy is forward_secrecy


def test_handshake_defaults_are_undetermined() -> None:
    handshake = build_handshake()

    assert handshake.tls_version is TLSVersion.UNKNOWN
    assert handshake.key_exchange is KeyExchange.UNKNOWN
    assert handshake.cipher_suite is None
    assert handshake.sni_server_name is None


def test_handshake_records_observed_parameters() -> None:
    handshake = build_handshake(
        tls_version=TLSVersion.TLS_1_2,
        cipher_suite="TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        key_exchange=KeyExchange.ECDHE,
        sni_server_name="mail.example.com",
        started_at=STARTED_AT,
    )

    assert handshake.tls_version is TLSVersion.TLS_1_2
    assert handshake.cipher_suite == "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
    assert handshake.started_at == STARTED_AT


def test_rejects_unknown_fields() -> None:
    with pytest.raises(ValidationError):
        build_handshake(client_random="00" * 32)
