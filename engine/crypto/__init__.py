"""TLS reconstruction: records, hello messages, and X.509 certificate chains.

Stage 3 turns the ciphertext byte stream that follows a STARTTLS boundary
(or an implicit-TLS session) into structured, fact-only TLS evidence.
Cryptographic scoring and findings belong to later stages.
"""

from engine.crypto.certificates import (
    CertificateParseError,
    extract_der_chain,
    parse_certificate_chain,
)
from engine.crypto.cipher_suites import (
    CIPHER_SUITE_NAMES,
    VERSION_NAMES,
    cipher_suite_name,
    key_exchange_for_suite,
)
from engine.crypto.hello import (
    HelloExtension,
    HelloParseError,
    parse_client_hello,
    parse_server_hello,
)
from engine.crypto.records import (
    TlsHandshakeMessage,
    TlsParseError,
    TlsRecord,
    parse_tls_stream,
)
from engine.crypto.tls import TlsEvidenceResult, parse_tls_evidence

__all__ = [
    "CIPHER_SUITE_NAMES",
    "VERSION_NAMES",
    "CertificateParseError",
    "HelloExtension",
    "HelloParseError",
    "TlsEvidenceResult",
    "TlsHandshakeMessage",
    "TlsParseError",
    "TlsRecord",
    "cipher_suite_name",
    "extract_der_chain",
    "key_exchange_for_suite",
    "parse_certificate_chain",
    "parse_client_hello",
    "parse_server_hello",
    "parse_tls_evidence",
    "parse_tls_stream",
]
