"""Stage 3 TLS conversation fixture: STARTTLS with a real TLS 1.2 handshake."""

import struct
from datetime import UTC, datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

from tests.tcp_fixtures import FrameConversation

TLS_CONTENT_CHANGE_CIPHER_SPEC = 20
TLS_CONTENT_HANDSHAKE = 22


def _tls_record(content_type: int, version: int, payload: bytes) -> bytes:
    return struct.pack(">BHH", content_type, version, len(payload)) + payload


def _handshake_message(message_type: int, body: bytes) -> bytes:
    return bytes([message_type]) + len(body).to_bytes(3, "big") + body


def _client_hello_record(sni: bytes = b"mail.example.org") -> bytes:
    body = struct.pack(">H", 0x0303) + b"\x42" * 32 + bytes([0])
    suites = (0xC02F, 0x009C)
    suites_blob = b"".join(struct.pack(">H", s) for s in suites)
    body += struct.pack(">H", len(suites_blob)) + suites_blob + bytes([1, 0])
    name_entry = bytes([0]) + struct.pack(">H", len(sni)) + sni
    sni_ext = (
        struct.pack(">HH", 0, len(name_entry) + 2) + struct.pack(">H", len(name_entry)) + name_entry
    )
    versions_ext = (
        struct.pack(">HH", 43, 5)
        + bytes([4])
        + struct.pack(">H", 0x0304)
        + struct.pack(">H", 0x0303)
    )
    exts = sni_ext + versions_ext
    body += struct.pack(">H", len(exts)) + exts
    return _tls_record(22, 0x0301, _handshake_message(1, body))


def _server_hello_record(suite: int = 0xC02F) -> bytes:
    body = struct.pack(">H", 0x0303) + b"\x43" * 32 + bytes([0])
    body += struct.pack(">H", suite) + bytes([0])
    return _tls_record(22, 0x0303, _handshake_message(2, body))


def _certificate_record(der: bytes) -> bytes:
    entry = len(der).to_bytes(3, "big") + der
    body = len(entry).to_bytes(3, "big") + entry
    return _tls_record(22, 0x0303, _handshake_message(11, body))


def _ccs_record() -> bytes:
    return _tls_record(20, 0x0303, b"\x01")


def _leaf_certificate_der(cn: str = "mail.example.org") -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(cn)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(Encoding.DER)


def smtp_starttls_tls_pcap() -> bytes:
    """STARTTLS negotiation followed by a real TLS 1.2 handshake + certificate."""
    der = _leaf_certificate_der()

    b = FrameConversation()
    (
        b.syn()
        .synack()
        .ack()
        .s(b"220 mail.example.org ESMTP\r\n")
        .c(b"EHLO client.example.net\r\n")
        .s(b"250-mail.example.org\r\n250-STARTTLS\r\n250 8BITMIME\r\n")
        .c(b"STARTTLS\r\n")
        .s(b"220 2.0.0 Ready to start TLS\r\n")
    )
    b.c(_client_hello_record())
    b.s(_server_hello_record() + _certificate_record(der) + _ccs_record())
    b.fin_c().fin_s()
    return b.to_pcap()


def imaps_tls_pcap() -> bytes:
    """IMAPS session: TLS from the first byte, no plaintext at all."""
    b = FrameConversation(server=("198.51.100.7", 993))
    (
        b.syn()
        .synack()
        .ack()
        .c(_client_hello_record())
        .s(_server_hello_record() + _ccs_record())
        .fin_c()
        .fin_s()
    )
    return b.to_pcap()
