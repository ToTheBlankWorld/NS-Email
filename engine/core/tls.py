"""TLS handshake evidence."""

from enum import StrEnum
from typing import Final

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field

from engine.core.base import ForensicBase


class TLSVersion(StrEnum):
    """TLS/SSL protocol versions observable on the wire."""

    SSL_2_0 = "SSL 2.0"
    SSL_3_0 = "SSL 3.0"
    TLS_1_0 = "TLS 1.0"
    TLS_1_1 = "TLS 1.1"
    TLS_1_2 = "TLS 1.2"
    TLS_1_3 = "TLS 1.3"
    UNKNOWN = "unknown"

    @property
    def is_deprecated(self) -> bool:
        """True for versions with known practical cryptographic breaks.

        SSLv2/v3 (POODLE, DROWN) and TLS 1.0/1.1 (officially deprecated by
        RFC 8996) should always surface as findings when observed.
        """
        return self in _DEPRECATED_VERSIONS


_DEPRECATED_VERSIONS: Final[frozenset[TLSVersion]] = frozenset(
    {TLSVersion.SSL_2_0, TLSVersion.SSL_3_0, TLSVersion.TLS_1_0, TLSVersion.TLS_1_1}
)


class KeyExchange(StrEnum):
    """Key exchange mechanisms observable in TLS handshakes."""

    RSA = "rsa"
    DH = "dh"
    DHE = "dhe"
    ECDH = "ecdh"
    ECDHE = "ecdhe"
    TLS_1_3 = "tls13"
    UNKNOWN = "unknown"

    @property
    def provides_forward_secrecy(self) -> bool:
        """True when the exchange uses ephemeral keys (or TLS 1.3 semantics).

        ``UNKNOWN`` is reported conservatively as ``False`` so that
        undetermined handshakes are treated as lacking forward secrecy
        until analysis proves otherwise.
        """
        return self in _EPHEMERAL_KEY_EXCHANGES


_EPHEMERAL_KEY_EXCHANGES: Final[frozenset[KeyExchange]] = frozenset(
    {KeyExchange.DHE, KeyExchange.ECDHE, KeyExchange.TLS_1_3}
)


class TlsExtension(BaseModel):
    """One TLS hello extension, recorded as structured evidence.

    ``value`` is a bounded, human-readable summary of well-understood
    extensions (server name, ALPN, supported versions, ...); unknown
    extensions keep only their type code and length.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    type_code: int = Field(ge=0, le=65535)
    name: str
    length: int = Field(ge=0)
    value: str | None = None


class TLSHandshake(ForensicBase):
    """Structured evidence from one reconstructed TLS handshake.

    Records facts only — versions, cipher suites, key exchange, hello
    extensions — never security verdicts. ``tls_version`` is the
    negotiated version; ``cipher_suite``/``cipher_suite_code`` describe
    the server's selection; ``cipher_suites_offered`` lists the client's
    proposals in offer order. Certificates live on the session as
    ``CertificateEvidence`` and are referenced by ``certificate_ids``.
    """

    session_id: str
    tls_version: TLSVersion = TLSVersion.UNKNOWN
    cipher_suite: str | None = None
    cipher_suite_code: int | None = Field(default=None, ge=0, le=65535)
    key_exchange: KeyExchange = KeyExchange.UNKNOWN
    cipher_suites_offered: list[str] = Field(default_factory=list)
    extensions: list[TlsExtension] = Field(default_factory=list)
    sni_server_name: str | None = None
    started_at: AwareDatetime | None = None
    handshake_complete: bool | None = None
    completeness_reason: str | None = None
    certificate_ids: list[str] = Field(default_factory=list)
    client_hello_packets: list[int] = Field(default_factory=list)
    server_hello_packets: list[int] = Field(default_factory=list)
    certificate_packets: list[int] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
