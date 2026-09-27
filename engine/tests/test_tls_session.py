"""Stage 3 integration: TLS evidence attached to reconstructed sessions."""

import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID
from engine.core.events import EventType
from engine.core.session import Confidence, EmailProtocol
from engine.core.tls import KeyExchange, TLSVersion
from engine.protocols.reconstruct import reconstruct_session
from engine.transport.flows import build_flows
from tls_bytes import (
    ccs_record,
    certificate_record,
    client_hello_record,
    implicit_tls_conversation,
    server_hello_record,
    smtp_starttls_client_hello_only_conversation,
    smtp_starttls_full_tls_conversation,
    smtp_starttls_tls13_conversation,
)

LEAF_CN = "mail.example.org"


def _leaf_certificate() -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, LEAF_CN)])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)  # self-signed leaf: chain of one
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(LEAF_CN)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(Encoding.DER)


def reconstruct_one(packets):
    flows = build_flows("capture_aaaaaaaaaaaa", packets)
    assert len(flows) == 1
    return reconstruct_session(flows[0])


def test_starttls_session_with_fake_bytes_has_no_real_tls_evidence() -> None:
    from conftest import smtp_starttls_conversation

    session = reconstruct_one(smtp_starttls_conversation())

    # the Stage 2 fixture's "ciphertext" is not valid TLS: evidence stays empty
    assert session.handshake is None or session.handshake.handshake_complete is not True


def test_starttls_with_real_tls_handshake() -> None:
    session = reconstruct_one(smtp_starttls_full_tls_conversation())

    handshake = session.handshake
    assert handshake is not None
    assert handshake.tls_version is TLSVersion.TLS_1_2
    assert handshake.cipher_suite == "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
    assert handshake.cipher_suite_code == 0xC02F
    assert handshake.key_exchange is KeyExchange.ECDHE
    assert handshake.sni_server_name == "mail.example.org"
    assert "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" in handshake.cipher_suites_offered
    assert "TLS_AES_128_GCM_SHA256" in handshake.cipher_suites_offered  # TLS 1.3 offered too
    assert handshake.handshake_complete is True
    extension_names = {e.name for e in handshake.extensions}
    assert "server_name" in extension_names
    assert "application_layer_protocol_negotiation" in extension_names
    assert session.protocol is EmailProtocol.SMTP
    assert session.certificates == []


def test_certificate_chain_extracted_from_starttls_session() -> None:
    from conftest import ConversationBuilder

    der = _leaf_certificate()
    b = ConversationBuilder()
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
    b.c(client_hello_record())
    b.s(server_hello_record() + certificate_record([der]) + ccs_record())
    b.fin_c().fin_s()

    flows = build_flows("capture_aaaaaaaaaaaa", b.build())
    session = reconstruct_session(flows[0])

    assert session.handshake is not None
    assert session.certificates, "certificate must be extracted when present"
    leaf = session.certificates[0]
    assert leaf.position_in_chain == 0
    assert LEAF_CN in leaf.subject
    assert leaf.id == f"cert_{leaf.fingerprint_sha256[:12]}"
    assert session.handshake.certificate_ids == [leaf.id]
    assert session.handshake.handshake_complete is True


def test_tls13_certificate_is_honestly_unavailable() -> None:
    session = reconstruct_one(smtp_starttls_tls13_conversation())

    handshake = session.handshake
    assert handshake is not None
    assert handshake.tls_version is TLSVersion.TLS_1_3
    assert handshake.cipher_suite == "TLS_AES_128_GCM_SHA256"
    assert handshake.key_exchange is KeyExchange.TLS_1_3
    assert handshake.handshake_complete is True
    assert session.certificates == []
    assert any("no plaintext Certificate message" in w for w in handshake.warnings)


def test_client_hello_only_capture_is_incomplete() -> None:
    session = reconstruct_one(smtp_starttls_client_hello_only_conversation())

    handshake = session.handshake
    assert handshake is not None
    assert handshake.tls_version is TLSVersion.TLS_1_3  # client's highest offered version
    assert handshake.cipher_suite is None  # server never chose one
    assert handshake.handshake_complete is False
    assert "no ServerHello" in (handshake.completeness_reason or "")


def test_implicit_tls_session_parses_whole_stream() -> None:
    session = reconstruct_one(implicit_tls_conversation())

    handshake = session.handshake
    assert handshake is not None
    assert handshake.tls_version is TLSVersion.TLS_1_2
    assert handshake.sni_server_name == "mail.example.org"
    assert session.implicit_tls is True
    # protocol attributed from the implicit-TLS service port + valid handshake
    assert session.protocol is EmailProtocol.IMAP
    assert session.confidence is Confidence.MEDIUM
    assert any("implicit-TLS" in warning for warning in session.warnings)


def test_plain_session_without_starttls_has_no_tls_evidence() -> None:
    from conftest import smtp_plain_conversation

    session = reconstruct_one(smtp_plain_conversation())

    assert session.handshake is None
    assert session.certificates == []
    assert not any(e.type is EventType.TLS_TRANSITION for e in session.events)
