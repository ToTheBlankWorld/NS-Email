"""Stage 4 fixtures: captures exercising specific policy rules."""

import struct
from datetime import UTC, datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

from tests.tcp_fixtures import FrameConversation
from tests.tls_fixtures import (
    _client_hello_record,
    _handshake_message,
    _tls_record,
)


def _legacy_client_hello_record() -> bytes:
    """TLS 1.0-era ClientHello: no supported_versions extension."""
    body = struct.pack(">H", 0x0301) + b"\x42" * 32 + bytes([0])
    suites = (0xC013,)
    suites_blob = b"".join(struct.pack(">H", s) for s in suites)
    body += struct.pack(">H", len(suites_blob)) + suites_blob + bytes([1, 0])
    return _tls_record(22, 0x0301, _handshake_message(1, body))


def _server_hello_record(suite: int, version: int) -> bytes:
    body = struct.pack(">H", version) + b"\x43" * 32 + bytes([0])
    body += struct.pack(">H", suite) + bytes([0])
    return _tls_record(22, version, _handshake_message(2, body))


def _leaf_certificate_der(*, expired: bool = False) -> bytes:
    """Certificate validity is anchored to the fixture's capture timestamp.

    The synthetic conversation starts at 1727430000 (2024-09-27); an
    "expired" certificate must therefore have expired before that moment,
    not before the analysis date.
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "mail.example.org")])
    capture_time = datetime.fromtimestamp(1727430000, tz=UTC)
    not_before = capture_time - timedelta(days=60) if expired else capture_time - timedelta(days=1)
    not_after = capture_time - timedelta(days=30) if expired else capture_time + timedelta(days=30)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("mail.example.org")]), critical=False
        )
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(Encoding.DER)


def _certificate_record(der: bytes) -> bytes:
    entry = len(der).to_bytes(3, "big") + der
    body = len(entry).to_bytes(3, "big") + entry
    return _tls_record(22, 0x0303, _handshake_message(11, body))


def _ccs_record() -> bytes:
    return _tls_record(20, 0x0303, b"\x01")


def smtp_tls10_pcap() -> bytes:
    """Server negotiates deprecated TLS 1.0 with a legacy CBC suite."""
    der = _leaf_certificate_der()

    b = FrameConversation()
    (
        b.syn()
        .synack()
        .ack()
        .s(b"220 mail.example.org ESMTP\r\n")
        .c(b"EHLO client.example.net\r\n")
        .s(b"250-STARTTLS\r\n250 8BITMIME\r\n")
        .c(b"STARTTLS\r\n")
        .s(b"220 2.0.0 Ready to start TLS\r\n")
    )
    b.c(_legacy_client_hello_record())
    b.s(
        _server_hello_record(suite=0xC013, version=0x0301)
        + _certificate_record(der)
        + _ccs_record()
    )
    b.fin_c().fin_s()
    return b.to_pcap()


def smtp_expired_certificate_pcap() -> bytes:
    """Valid TLS 1.2 handshake where the certificate expired before the capture."""
    der = _leaf_certificate_der(expired=True)

    b = FrameConversation()
    (
        b.syn()
        .synack()
        .ack()
        .s(b"220 mail.example.org ESMTP\r\n")
        .c(b"EHLO client.example.net\r\n")
        .s(b"250-STARTTLS\r\n250 8BITMIME\r\n")
        .c(b"STARTTLS\r\n")
        .s(b"220 2.0.0 Ready to start TLS\r\n")
    )
    b.c(_client_hello_record())
    b.s(
        _server_hello_record(suite=0xC02F, version=0x0303)
        + _certificate_record(der)
        + _ccs_record()
    )
    b.fin_c().fin_s()
    return b.to_pcap()


def smtp_starttls_never_accepted_pcap() -> bytes:
    """Client requests STARTTLS; the server never accepts it in the capture."""
    b = FrameConversation()
    (
        b.syn()
        .synack()
        .ack()
        .s(b"220 mail.example.org ESMTP\r\n")
        .c(b"EHLO client.example.net\r\n")
        .s(b"250-STARTTLS\r\n250 8BITMIME\r\n")
        .c(b"STARTTLS\r\n")
    )
    b.fin_c().fin_s()
    return b.to_pcap()
