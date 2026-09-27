"""TLS handshake evidence."""

from enum import StrEnum
from typing import Final

from pydantic import AwareDatetime

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


class TLSHandshake(ForensicBase):
    """A TLS handshake observed within a session.

    Cipher suite is recorded as the standard name string (e.g.
    ``TLS_AES_128_GCM_SHA256``); suite code mapping happens during
    handshake reconstruction in a later stage.
    """

    session_id: str
    tls_version: TLSVersion = TLSVersion.UNKNOWN
    cipher_suite: str | None = None
    key_exchange: KeyExchange = KeyExchange.UNKNOWN
    sni_server_name: str | None = None
    started_at: AwareDatetime | None = None
