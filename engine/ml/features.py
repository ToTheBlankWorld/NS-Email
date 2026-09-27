"""Typed feature extraction for TLS behavioral anomaly detection (Stage 6).

Features are derived ONLY from the structured evidence produced by
Stages 2-3 — never from raw packet payloads, credentials, message
bodies, or certificate bytes. The schema is versioned: the same evidence
plus the same ``FEATURE_SCHEMA_VERSION`` always produces the identical
feature vector, so anomaly results are reproducible.

Numeric features are sanitized defensively: non-finite values
(NaN/Infinity from malformed evidence) are rejected at construction, and
categorical values are encoded deterministically through a fixed
vocabulary (persisted with the model), never through randomized hashing.
"""

import math
from dataclasses import dataclass
from typing import Final

from engine.core.session import Session
from engine.core.tls import KeyExchange, TLSVersion
from engine.crypto.cipher_suites import CipherClass, classify_cipher_suite

FEATURE_SCHEMA_VERSION: Final[str] = "1.0"

# Fixed categorical vocabularies (sorted, stable across runs). Values
# outside the vocabulary map to the last entry ("other").
PROTOCOL_VOCABULARY: Final[tuple[str, ...]] = ("imap", "pop3", "smtp", "other")
TLS_VERSION_VOCABULARY: Final[tuple[str, ...]] = (
    "unknown",
    "SSL 2.0",
    "SSL 3.0",
    "TLS 1.0",
    "TLS 1.1",
    "TLS 1.2",
    "TLS 1.3",
)
KEY_EXCHANGE_VOCABULARY: Final[tuple[str, ...]] = (
    "unknown",
    "rsa",
    "dh",
    "dhe",
    "ecdh",
    "ecdhe",
    "tls13",
)
PUBLIC_KEY_VOCABULARY: Final[tuple[str, ...]] = (
    "unknown",
    "RSA",
    "EC",
    "DSA",
    "Ed25519",
    "Ed448",
    "other",
)
CIPHER_CLASS_VOCABULARY: Final[tuple[str, ...]] = (
    "unknown",
    "modern_aead",
    "legacy",
    "deprecated",
    "prohibited",
)
BOOLEAN_VOCABULARY: Final[tuple[str, ...]] = ("false", "true")

MAX_NUMERIC: Final[float] = 1e12  # bound absurd values from malformed evidence


def _safe_number(value: float | int | None) -> float:
    """Sanitize a numeric feature: reject NaN/Infinity, bound absurd values."""
    if value is None:
        return 0.0
    number = float(value)
    if math.isnan(number) or math.isinf(number):
        return 0.0
    return max(-MAX_NUMERIC, min(MAX_NUMERIC, number))


def _index_in(vocabulary: tuple[str, ...], value: str | None) -> int:
    if value is None:
        return len(vocabulary) - 1
    try:
        return vocabulary.index(value)
    except ValueError:
        return len(vocabulary) - 1


@dataclass(frozen=True, slots=True)
class SessionFeatures:
    """The typed feature vector extracted from one session's evidence.

    Field order defines the numeric vector layout and is part of the
    feature schema contract for ``FEATURE_SCHEMA_VERSION`` 1.0.
    """

    # session-level
    protocol: int
    server_port: int
    duration_seconds: float
    packet_count: int
    bytes_client_to_server: int
    bytes_server_to_client: int
    complete: int  # 0/1
    # TLS-level (0 when no TLS evidence exists)
    has_tls: int
    tls_version: int
    cipher_class: int
    offered_cipher_count: int
    key_exchange: int
    extension_count: int
    has_sni: int
    alpn_count: int
    certificate_count: int
    certificate_max_key_bits: int
    certificate_min_validity_days: float
    has_implicit_tls: int
    # schema bookkeeping
    feature_schema_version: str = FEATURE_SCHEMA_VERSION

    def numeric_vector(self) -> list[float]:
        """The sanitized numeric vector used by the anomaly model."""
        return [
            _safe_number(value)
            for value in (
                self.protocol,
                self.server_port,
                self.duration_seconds,
                self.packet_count,
                self.bytes_client_to_server,
                self.bytes_server_to_client,
                self.complete,
                self.has_tls,
                self.tls_version,
                self.cipher_class,
                self.offered_cipher_count,
                self.key_exchange,
                self.extension_count,
                self.has_sni,
                self.alpn_count,
                self.certificate_count,
                self.certificate_max_key_bits,
                self.certificate_min_validity_days,
                self.has_implicit_tls,
            )
        ]


FEATURE_NAMES: Final[tuple[str, ...]] = (
    "protocol",
    "server_port",
    "duration_seconds",
    "packet_count",
    "bytes_client_to_server",
    "bytes_server_to_client",
    "tcp_complete",
    "has_tls",
    "tls_version",
    "cipher_class",
    "offered_cipher_count",
    "key_exchange",
    "extension_count",
    "has_sni",
    "alpn_count",
    "certificate_count",
    "certificate_max_key_bits",
    "certificate_min_validity_days",
    "has_implicit_tls",
)

# Categorical feature name → its vocabulary (for human-readable baselines).
CATEGORICAL_FEATURES: Final[dict[str, tuple[str, ...]]] = {
    "protocol": PROTOCOL_VOCABULARY,
    "tls_version": TLS_VERSION_VOCABULARY,
    "cipher_class": CIPHER_CLASS_VOCABULARY,
    "key_exchange": KEY_EXCHANGE_VOCABULARY,
}


def _decode(vocabulary: tuple[str, ...], index: float) -> str:
    index_int = int(index)
    if 0 <= index_int < len(vocabulary):
        return vocabulary[index_int]
    return "other"


def extract_features(session: Session) -> SessionFeatures:
    """Extract the typed feature vector from one reconstructed session.

    All values come from the structured evidence on the session model
    (Stages 2-3). Missing TLS evidence yields zeros for TLS features and
    ``has_tls = 0`` so the model can treat plaintext sessions separately.
    """
    handshake = session.handshake
    certificates = session.certificates

    protocol_index = _index_in(
        PROTOCOL_VOCABULARY, session.protocol.value if session.protocol else None
    )
    duration = 0.0
    if session.started_at is not None and session.ended_at is not None:
        duration = (session.ended_at - session.started_at).total_seconds()

    cipher_class = (
        classify_cipher_suite(handshake.cipher_suite_code)
        if handshake is not None and handshake.cipher_suite_code is not None
        else CipherClass.UNKNOWN
    )
    key_exchange = handshake.key_exchange if handshake is not None else KeyExchange.UNKNOWN
    tls_version = handshake.tls_version if handshake is not None else TLSVersion.UNKNOWN

    alpn_count = 0
    if handshake is not None:
        for extension in handshake.extensions:
            if extension.name == "application_layer_protocol_negotiation":
                alpn_count = len((extension.value or "").split(", ")) if extension.value else 0

    max_key_bits = 0
    min_validity_days = 0.0
    if certificates and session.started_at is not None:
        max_key_bits = max((c.public_key_size_bits or 0) for c in certificates)
        validity_spans = [
            (c.not_after - session.started_at).total_seconds() / 86400 for c in certificates
        ]
        min_validity_days = _safe_number(min(validity_spans))

    return SessionFeatures(
        protocol=protocol_index,
        server_port=session.server_port,
        duration_seconds=_safe_number(duration),
        packet_count=session.packet_count,
        bytes_client_to_server=session.bytes_client_to_server,
        bytes_server_to_client=session.bytes_server_to_client,
        complete=1 if session.complete else 0,
        has_tls=1 if handshake is not None else 0,
        tls_version=_index_in(TLS_VERSION_VOCABULARY, tls_version.value),
        cipher_class=_index_in(CIPHER_CLASS_VOCABULARY, cipher_class.value),
        offered_cipher_count=len(handshake.cipher_suites_offered) if handshake else 0,
        key_exchange=_index_in(KEY_EXCHANGE_VOCABULARY, key_exchange.value),
        extension_count=len(handshake.extensions) if handshake else 0,
        has_sni=1 if handshake is not None and handshake.sni_server_name else 0,
        alpn_count=alpn_count,
        has_implicit_tls=1 if session.implicit_tls else 0,
        certificate_count=len(certificates),
        certificate_max_key_bits=max_key_bits,
        certificate_min_validity_days=min_validity_days,
    )


def decode_feature(name: str, value: float) -> str:
    """Human-readable rendering of one feature value (for explanations)."""
    vocabulary = CATEGORICAL_FEATURES.get(name)
    if vocabulary is not None:
        return _decode(vocabulary, value)
    return str(round(value, 4))
