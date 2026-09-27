"""Tests for X.509 certificate chain extraction (cryptography-backed)."""

import datetime

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID
from engine.crypto.certificates import parse_certificate_chain
from engine.crypto.records import TlsHandshakeMessage
from tls_bytes import certificate_message_bytes

NOW = datetime.datetime.now(datetime.UTC)
LEAF_CN = "mail.example.org"
CA_CN = "Test Root CA"


def _make_name(cn: str) -> x509.Name:
    return x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "NS-Email Test"),
        ]
    )


@pytest.fixture(name="chain_der")
def chain_der_fixture() -> list[bytes]:
    """A root CA plus a server leaf signed by it (DER-encoded)."""
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(_make_name(CA_CN))
        .issuer_name(_make_name(CA_CN))
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - datetime.timedelta(days=30))
        .not_valid_after(NOW + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf_cert = (
        x509.CertificateBuilder()
        .subject_name(_make_name(LEAF_CN))
        .issuer_name(ca_cert.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - datetime.timedelta(days=1))
        .not_valid_after(NOW + datetime.timedelta(days=90))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(LEAF_CN), x509.DNSName("smtp.example.org")]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    return [
        leaf_cert.public_bytes(Encoding.DER),
        ca_cert.public_bytes(Encoding.DER),
    ]


def test_certificate_chain_extraction_round_trip(chain_der) -> None:
    message = TlsHandshakeMessage(
        message_type=11, body=certificate_message_bytes(chain_der), offset=0
    )

    certificates, warnings = parse_certificate_chain(message, session_id="session_test")

    assert warnings == []
    assert len(certificates) == 2
    leaf, ca = certificates
    assert leaf.position_in_chain == 0
    assert LEAF_CN in leaf.subject
    assert leaf.subject != leaf.issuer  # leaf signed by the CA
    assert CA_CN in ca.issuer
    assert ca.subject == ca.issuer  # self-signed root
    assert "smtp.example.org" in leaf.subject_alternative_names
    assert leaf.public_key_algorithm == "RSA"
    assert leaf.public_key_size_bits == 2048
    assert len(leaf.fingerprint_sha256) == 64
    assert leaf.id.startswith("cert_")
    assert leaf.id == f"cert_{leaf.fingerprint_sha256[:12]}"
    assert leaf.not_before < leaf.not_after
    assert leaf.signature_algorithm  # e.g. sha256WithRSAEncryption


def test_malformed_der_is_skipped_with_warning(chain_der) -> None:
    bad_entry = b"\x00\x01\x02"  # 3-byte length prefix, garbage DER
    message = TlsHandshakeMessage(
        message_type=11,
        body=certificate_message_bytes([bad_entry, chain_der[0]]),
        offset=0,
    )

    certificates, warnings = parse_certificate_chain(message, session_id="session_test")

    assert len(certificates) == 1
    assert any("could not be parsed" in warning for warning in warnings)


def test_truncated_certificate_body_is_reported() -> None:
    message = TlsHandshakeMessage(message_type=11, body=b"\x00\x01", offset=0)

    certificates, warnings = parse_certificate_chain(message, session_id="session_test")

    assert certificates == []
    assert any("truncated" in warning for warning in warnings)
