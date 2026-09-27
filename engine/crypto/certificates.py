"""X.509 certificate chain extraction from TLS Certificate messages.

Parses the (TLS 1.2) Certificate handshake message into DER entries and
turns each into ``CertificateEvidence`` via the ``cryptography`` library —
facts only: subject, issuer, validity, key material, fingerprint. TLS 1.3
encrypts the server certificate, so passive captures simply cannot see it;
that limitation is reported, never papered over.
"""

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa

from engine.core.certificate import CertificateEvidence
from engine.crypto.records import TlsHandshakeMessage


class CertificateParseError(ValueError):
    """The Certificate handshake message body is malformed."""


def extract_der_chain(certificate_message: TlsHandshakeMessage) -> tuple[list[bytes], list[str]]:
    """Split a Certificate handshake body into DER entries.

    Returns ``(der_entries, warnings)``.
    """
    warnings: list[str] = []
    body = certificate_message.body
    if len(body) < 3:
        return [], ["certificate message body is truncated"]
    total_length = int.from_bytes(body[0:3], "big")
    if total_length > len(body) - 3:
        warnings.append("certificate list length exceeds message body")
    end = min(3 + total_length, len(body))
    entries: list[bytes] = []
    offset = 3
    while offset + 3 <= end:
        entry_length = int.from_bytes(body[offset : offset + 3], "big")
        offset += 3
        if entry_length > end - offset:
            warnings.append("truncated certificate entry")
            break
        entries.append(body[offset : offset + entry_length])
        offset += entry_length
    return entries, warnings


def _public_key_evidence(public_key: object) -> tuple[str, int | None]:
    """(algorithm name, key size) for a supported public key type."""
    if isinstance(public_key, rsa.RSAPublicKey):
        return ("RSA", public_key.key_size)
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        return ("EC", public_key.curve.key_size)
    if isinstance(public_key, ed25519.Ed25519PublicKey):
        return ("Ed25519", 256)
    if isinstance(public_key, ed448.Ed448PublicKey):
        return ("Ed448", 456)
    if isinstance(public_key, dsa.DSAPublicKey):
        return ("DSA", public_key.key_size)
    return ("unknown", None)


def _certificate_to_evidence(
    der: bytes,
    session_id: str,
    position: int,
) -> CertificateEvidence:
    cert = x509.load_der_x509_certificate(der)
    public_key = cert.public_key()
    algorithm_name, key_size = _public_key_evidence(public_key)

    san_names: list[str] = []
    try:
        san_extension = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        san_names = san_extension.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        pass

    fingerprint = cert.fingerprint(hashes.SHA256()).hex()
    not_before = cert.not_valid_before_utc
    not_after = cert.not_valid_after_utc

    return CertificateEvidence(
        id=f"cert_{fingerprint[:12]}",
        session_id=session_id,
        subject=cert.subject.rfc4514_string(),
        issuer=cert.issuer.rfc4514_string(),
        serial_number=f"{cert.serial_number:x}",
        not_before=not_before,
        not_after=not_after,
        signature_algorithm=cert.signature_algorithm_oid._name,
        public_key_algorithm=algorithm_name,
        public_key_size_bits=key_size,
        subject_alternative_names=san_names,
        fingerprint_sha256=fingerprint,
        position_in_chain=position,
    )


def parse_certificate_chain(
    message: TlsHandshakeMessage,
    session_id: str,
) -> tuple[list[CertificateEvidence], list[str]]:
    """Extract and parse the certificate chain from a Certificate message.

    Returns ``(certificates, warnings)``. Entries whose DER cannot be
    parsed are skipped with a warning — partial chains stay partial
    instead of failing the whole session.
    """
    der_entries, warnings = extract_der_chain(message)
    certificates: list[CertificateEvidence] = []
    for position, der in enumerate(der_entries):
        try:
            certificates.append(_certificate_to_evidence(der, session_id, position))
        except Exception as error:
            warnings.append(f"certificate {position} could not be parsed: {error}")
    return certificates, warnings
