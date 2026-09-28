"""Deterministic forensic evaluation fixtures (Stage 10).

Synthetic, fully deterministic email/TLS scenarios with ground truth
defined BEFORE running the system. Ground truth was derived by hand from
the documented Stage 4 policy semantics (rule identifiers, trigger
conditions, severities) and the documented Stage 5 scoring formula —
never from observed engine output.

All key material below is throwaway, synthetic, and used ONLY to build
self-signed/synthetic test certificates; it is not a credential and
guards nothing. RSA key generation is randomized, so fixed keys are
embedded as PEM constants to keep certificate DER — and therefore
certificate fingerprints, finding IDs, and graph node IDs — byte-stable
across runs.

Capture timestamps are fixed (base 2024-09-27), so certificate-validity
findings are evaluated against a deterministic capture instant.
"""

import hashlib
import struct
from dataclasses import dataclass, field
from datetime import UTC, datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

# --------------------------------------------------------------------------
# Deterministic key material (synthetic, test-only)
# --------------------------------------------------------------------------

_RSA_2048_KEY_PEM = b"""-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC4ref4ObUiB+sY
fQDWVfMuMvv1xu5EBgxMJ8rxRSA4WsjrTPlNktTGSG4ORbcfop1/fga+ZLDJorbH
/jieDcjrqnEeBbev7yxZlIAJmbPsriVnbHZOShaOSCN6bnQjbZoX1TInZr9qRfQX
TBSUZ/St0VAU5yiQJ3sqLPCYBJPSzEPWKvMzCZoPsHMXGNZdNr9qJEN7gSdrVuGW
aeDCY7sUASR88vHttQBhUQ+ZTDei9sKEbETYfYuuJJnAUJueZUbnzMbs1tyrREUM
zUBYz50E7jU7DZe3rha/4lV8RL9hZ3p24nzsr8RD8A7ebxySodrjDQXn+JrrhN/8
6b+2FBgFAgMBAAECggEAJRGPDqVypIaHW0539Q2idqL4LPCFkbTPEhgopX31Biq+
ynAUWExBFh2irY2zwI9Q4q7Gpr+qNobI/mKaNatZqWf4NYj7Qj6VHdPvUT3/PeIE
kvpT0soPNfbn3CLAf/33YJJD82GtySSKZoS4WsN0+tCZLODrJOgv0hrcHf9JNpW/
PDFvpC5WVr3OPBTgdS4EOkGbryxQO5qSpUPNw8EsbTevl5CBlTyvcAIL/lkjqTNK
RJf1X+Wp+RFiDg4ygPDafigNB/Y46OnLttUXfYPM4ZYaetSohso5ryQ82HFU7yUH
MMDJtXS0rOUeiVkkiuW0RsT5ADF6Hijl6iACHK753wKBgQDaPLMsdQ0E9W3mxnl1
1TSzdk6nKLbPwrWrF+eSxwGYH+ivyinI5PYcydDjqEDNCmDK8lQYjLHewWN0rV8j
Y/YqBUxAaywIgDWn9tfq4P5s8odD8Qn1kFa3nJCLzXwJMD85wvs9++wha3BF6aQG
Ha/sA8MNkybYU0WVpuwIxC/PHwKBgQDYorBmwhLp342Pop6RlOlBUas+wlJRgrk0
FYwGWsNUwaGDiFRkK+WS+wFTHmBfkJQb8hJfz+zq3V+TGRuDlz8VljHNS7Tpfq1V
0ShdNiFq+Q3vr1NZOXlcXgttP8Zg9oMelQTiv7bgeg8O8E3WtiJ5qLSmbSfjeLDd
CtgGFFOIWwKBgQDMpb8fIWRkEgJNNjEP3i7dW0PGXNeRW/Ufy/rMGPHVxZZdwiYM
zSg9NsM7uLuLiv/ZUASsQMNLL+4jq7Bbb5GXNgCbJ+TS0+d86mzvRK1RXNybSZ0d
OY0YASlK8BYwR54CfGU9as+zRxyxcrbtRUmC+MQgJq12jh/ihfUxA0gR4QKBgDIl
/xXaiUxQbtG4QGLNCO4Q/MZLb4jk7QCMmFyEOEFvjXcIYRjLPJq4tkbKel7E9jQ9
5lj9pgd8dXp0znS412ak3SR8CQYgR/ncsC5bsIK14q8AdBfsgRaLwrNolwCtMA8t
SfM/lBMEzmWT5UD16qclEaSREjHLJ44Ty4wkum2PAoGAWLtqHk1FEtMfBG6LJmQu
s2eW3KrjQvGEQvQZfDz3bzRR1L6/4zNYEY5rBy83y8KhQJolKErmWILEwhCc99lk
ovy4KmhD/1eN7r3f8SgY2KB1XRROuWnL09/zGXv3kSt9ryjwjOF2I9f4aCBCbnUw
zk89riHalILroqOmyoU/0mk=
-----END PRIVATE KEY-----"""

_RSA_1024_KEY_PEM = b"""-----BEGIN PRIVATE KEY-----
MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAO30mPrDOaFRIVRC
wFhPEaAqoiZXV7+0Kc9tudeKjHIavF58IQCN3iZgiu8tEtFwlR/RBkvY/o0S8k21
5nniIy0CF3qWjkWiM77ipZB7lwToxVseZi2DPqIAN5WnTDL5ZfR/E1PthmspnY21
XKnhuNtTKGk/wnalqcrHDeU0sjZZAgMBAAECgYBwOeUQl5SNlZLvh4/p1ljMvm69
QIJdIp55exmkI277vcpLkaWK+l3kobHE/fAbIUrjt5SNnyjm5iGrLvglUdceUUI1
K25PPwqSer9dbgeQ154sD5q5jI7gv/4ZuKAWCm2CCcafiNsX2Tz/lCE6z2pDOpGe
szZGgJddtDCYu60DgQJBAPowQ4dl4SdJXcAHtkaq85SxA2mW6VuWa6hbmjtz2N9s
tD/094ems3mOvaZz+kOlERlgdZwniSNPc816IQjOZ+kCQQDze5cfB/g8Hrx+15h7
mH/jbCWRDm9FR5RIcnEwz1fvfSCdInmF6ch3D0+p7Gnf4VQP+y0NzVHzYBO1iPVb
tMTxAkEAgNB+xGTZM1Ab+/Y8jFASj/k/54qy5dwh3BIl6/xuqkKe39sx418aQzkS
PnSyY0fG8QjwJRFaE5sh5aa/AXi8mQJAfY8KS1JMzJP9GFwNog7uRFUMulT7RHq5
GPMLM+R4sGOSYfXZPRll6x/WMQZdQrpsIyGgBjIPRLYS89aA0J3TwQJBAOqQadFV
xzmbOEyR3EyL3Bu+hWPNqP5H3pX4h/sdsAjp1B2DVn8+FCTHwewnumANMGNPZS7g
S7Ch6pr6QDgfGY4=
-----END PRIVATE KEY-----"""


def _load_key(pem: bytes) -> rsa.RSAPrivateKey:
    return serialization.load_pem_private_key(pem, password=None)  # type: ignore[return-value]


_KEY_2048 = _load_key(_RSA_2048_KEY_PEM)
_KEY_1024 = _load_key(_RSA_1024_KEY_PEM)

# Fixed capture base instant: 2024-09-27T09:00:00Z (all scenarios).
CAPTURE_BASE_TS = 1727427600
# Validity windows chosen so "valid" certs always cover the capture instant
# and "expired" certs always end before it, regardless of run date.
VALIDITY_VALID = (datetime(2024, 1, 1, tzinfo=UTC), datetime(2040, 1, 1, tzinfo=UTC))
VALIDITY_EXPIRED = (datetime(2023, 1, 1, tzinfo=UTC), datetime(2024, 6, 1, tzinfo=UTC))

CLIENT_IP = "203.0.113.10"
SMTP_SERVER = ("198.51.100.20", 25)
IMAPS_SERVER = ("198.51.100.21", 993)
SNI = "mail.example.org"
LEAF_CN = "mail.example.org"
CA_CN = "Synthetic Mail CA"
OTHER_CN = "other.example.org"


# --------------------------------------------------------------------------
# Deterministic certificate builder
# --------------------------------------------------------------------------


def build_certificate(
    *,
    serial: int,
    subject: str,
    issuer: str,
    key: rsa.RSAPrivateKey,
    not_before: datetime,
    not_after: datetime,
    sans: list[str] | None = None,
    signature_hash: hashes.HashAlgorithm | None = None,
) -> bytes:
    """Build one DER certificate with fully deterministic content.

    The same arguments always produce byte-identical DER (PKCS#1 v1.5
    RSA signing is deterministic; names, serial, and validity are fixed),
    so certificate fingerprints and finding IDs stay stable across runs.
    """
    key_obj: rsa.RSAPrivateKey = serialization.load_pem_private_key(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
        password=None,
    )  # type: ignore[assignment]
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)])
    issuer_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(issuer_name)
        .public_key(key_obj.public_key())
        .serial_number(serial)
        .not_valid_before(not_before)
        .not_valid_after(not_after)
    )
    if sans:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]), critical=False
        )
    cert = builder.sign(key_obj, signature_hash or hashes.SHA256())
    return cert.public_bytes(serialization.Encoding.DER)


# --------------------------------------------------------------------------
# Ethernet/IPv4/TCP frame builder (fixed timestamps, deterministic)
# --------------------------------------------------------------------------

TCP_SYN, TCP_ACK, TCP_PSH, TCP_FIN = 0x02, 0x10, 0x08, 0x01


def _ip_bytes(ip: str) -> bytes:
    return bytes(int(octet) for octet in ip.split("."))


def _tcp_frame(
    src: tuple[str, int],
    dst: tuple[str, int],
    seq: int,
    flags: int,
    payload: bytes = b"",
) -> bytes:
    tcp_header = struct.pack(">HHIIBBHHH", src[1], dst[1], seq, 0, 5 << 4, flags, 8192, 0, 0)
    total_len = 20 + len(tcp_header) + len(payload)
    ip_header = (
        struct.pack(">BBHHHBBH", 0x45, 0, total_len, 0, 0, 64, 6, 0)
        + _ip_bytes(src[0])
        + _ip_bytes(dst[0])
    )
    return (
        b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb"
        + struct.pack(">H", 0x0800)
        + ip_header
        + tcp_header
        + payload
    )


class Conversation:
    """Builds a deterministic Ethernet/IPv4/TCP conversation as a pcap."""

    def __init__(self, server: tuple[str, int], client_port: int) -> None:
        self.client = (CLIENT_IP, client_port)
        self.server = server
        self.seq_c = 1000
        self.seq_s = 9000
        self.frames: list[bytes] = []

    def _add(
        self, src: tuple[str, int], dst: tuple[str, int], seq: int, flags: int, payload: bytes = b""
    ) -> "Conversation":
        self.frames.append(_tcp_frame(src, dst, seq, flags, payload))
        return self

    def syn(self) -> "Conversation":
        self._add(self.client, self.server, self.seq_c, TCP_SYN)
        self.seq_c += 1
        return self

    def synack(self) -> "Conversation":
        self._add(self.server, self.client, self.seq_s, TCP_SYN | TCP_ACK)
        self.seq_s += 1
        return self

    def ack(self) -> "Conversation":
        return self._add(self.client, self.server, self.seq_c, TCP_ACK)

    def c(self, payload: bytes) -> "Conversation":
        self._add(self.client, self.server, self.seq_c, TCP_ACK | TCP_PSH, payload)
        self.seq_c += len(payload)
        return self

    def s(self, payload: bytes) -> "Conversation":
        self._add(self.server, self.client, self.seq_s, TCP_ACK | TCP_PSH, payload)
        self.seq_s += len(payload)
        return self

    def fin_c(self) -> "Conversation":
        return self._add(self.client, self.server, self.seq_c, TCP_ACK | TCP_FIN)

    def fin_s(self) -> "Conversation":
        return self._add(self.server, self.client, self.seq_s, TCP_ACK | TCP_FIN)

    def to_pcap(self) -> bytes:
        out = struct.pack("<I", 0xA1B2C3D4) + struct.pack("<HHiIII", 2, 4, 0, 0, 65535, 1)
        for index, frame in enumerate(self.frames):
            out += struct.pack("<IIII", CAPTURE_BASE_TS + index, 0, len(frame), len(frame))
            out += frame
        return out


# --------------------------------------------------------------------------
# TLS record builders
# --------------------------------------------------------------------------

TLS_CONTENT_CCS = 20
TLS_CONTENT_HANDSHAKE = 22
TLS_CONTENT_APPDATA = 23


def _tls_record(content_type: int, version: int, payload: bytes) -> bytes:
    return struct.pack(">BHH", content_type, version, len(payload)) + payload


def _handshake_message(message_type: int, body: bytes) -> bytes:
    return bytes([message_type]) + len(body).to_bytes(3, "big") + body


def _ext(ext_type: int, data: bytes) -> bytes:
    return struct.pack(">HH", ext_type, len(data)) + data


def client_hello(
    *,
    client_version: int = 0x0303,
    suites: tuple[int, ...] = (0xC02F, 0x009C),
    sni: str = SNI,
    supported_versions: tuple[int, ...] | None = None,
) -> bytes:
    """Deterministic ClientHello with SNI and optional supported_versions."""
    body = struct.pack(">H", client_version) + b"\x42" * 32 + bytes([0])
    suites_blob = b"".join(struct.pack(">H", s) for s in suites)
    body += struct.pack(">H", len(suites_blob)) + suites_blob + bytes([1, 0])
    exts = b""
    if sni:
        name_entry = bytes([0]) + struct.pack(">H", len(sni.encode())) + sni.encode()
        exts += _ext(0, struct.pack(">H", len(name_entry)) + name_entry)
    if supported_versions:
        versions = b"".join(struct.pack(">H", v) for v in supported_versions)
        exts += _ext(43, bytes([len(versions)]) + versions)
    body += struct.pack(">H", len(exts)) + exts
    return _tls_record(22, client_version, _handshake_message(1, body))


def server_hello(
    *,
    server_version: int = 0x0303,
    suite: int = 0xC02F,
    negotiated_version: int | None = None,
    record_version: int = 0x0303,
) -> bytes:
    """Deterministic ServerHello; negotiated_version adds supported_versions."""
    body = struct.pack(">H", server_version) + b"\x43" * 32 + bytes([0])
    body += struct.pack(">H", suite) + bytes([0])
    exts = b""
    if negotiated_version is not None:
        exts += _ext(43, struct.pack(">H", negotiated_version))
    if exts:
        body += struct.pack(">H", len(exts)) + exts
    return _tls_record(22, record_version, _handshake_message(2, body))


def certificate_message(der_chain: list[bytes], record_version: int = 0x0303) -> bytes:
    entries = b"".join(len(der).to_bytes(3, "big") + der for der in der_chain)
    body = len(entries).to_bytes(3, "big") + entries
    return _tls_record(22, record_version, _handshake_message(11, body))


def ccs(record_version: int = 0x0303) -> bytes:
    return _tls_record(TLS_CONTENT_CCS, record_version, b"\x01")


def app_data(size: int, record_version: int = 0x0303, fill: bytes = b"\x61") -> bytes:
    return _tls_record(TLS_CONTENT_APPDATA, record_version, fill * size)


# --------------------------------------------------------------------------
# Common certificate sets
# --------------------------------------------------------------------------

_LEAF_SERIAL = 0x1000
_CA_SERIAL = 0x0001


def _leaf_der(
    *,
    serial: int = _LEAF_SERIAL,
    key: rsa.RSAPrivateKey = _KEY_2048,
    subject: str = LEAF_CN,
    issuer: str = CA_CN,
    sans: list[str] | None = None,
    validity: tuple[datetime, datetime] = VALIDITY_VALID,
    signature_hash: hashes.HashAlgorithm | None = None,
) -> bytes:
    return build_certificate(
        serial=serial,
        subject=subject,
        issuer=issuer,
        key=key,
        not_before=validity[0],
        not_after=validity[1],
        sans=sans if sans is not None else [LEAF_CN],
        signature_hash=signature_hash,
    )


# 1.2.840.113549.1.1.11 (sha256WithRSAEncryption) -> 1.2.840.113549.1.1.5
# (sha1WithRSAEncryption). Same DER length, so the patch is byte-stable.
_SHA256_SIG_OID = bytes.fromhex("2A864886F70D01010B")
_SHA1_SIG_OID = bytes.fromhex("2A864886F70D010105")


def _sha1_signed_leaf_der() -> bytes:
    """A leaf certificate presenting sha1WithRSAEncryption as its algorithm.

    Current cryptography releases refuse to CREATE SHA-1 signatures, so the
    fixture signs with SHA-256 and rewrites the signature-algorithm OID in
    the DER. The result is a structurally valid, parseable certificate that
    declares SHA-1 — exactly what the scenario needs. The engine classifies
    the declared algorithm; it never verifies signatures (passive capture).
    """
    der = _leaf_der()
    patched = der.replace(_SHA256_SIG_OID, _SHA1_SIG_OID)
    assert patched.count(_SHA1_SIG_OID) == 2, "expected TBS + outer signature OIDs"
    x509.load_der_x509_certificate(patched)  # parseability guard
    return patched


def _ca_der() -> bytes:
    """Self-issued CA certificate so the observed chain is complete."""
    return build_certificate(
        serial=_CA_SERIAL,
        subject=CA_CN,
        issuer=CA_CN,
        key=_KEY_2048,
        not_before=VALIDITY_VALID[0],
        not_after=VALIDITY_VALID[1],
        sans=None,
    )


def _smtp_starttls_tls_conversation(
    *,
    client_port: int,
    server_hello_flight: bytes,
) -> Conversation:
    """SMTP + STARTTLS + TLS handshake with the given server flight."""
    b = Conversation(server=SMTP_SERVER, client_port=client_port)
    (
        b.syn()
        .synack()
        .ack()
        .s(b"220 mail.example.org ESMTP Synthetic\r\n")
        .c(b"EHLO client.example.net\r\n")
        .s(b"250-mail.example.org\r\n250-STARTTLS\r\n250 8BITMIME\r\n")
        .c(b"STARTTLS\r\n")
        .s(b"220 2.0.0 Ready to start TLS\r\n")
        .c(client_hello())
        .s(server_hello_flight)
        .fin_c()
        .fin_s()
    )
    return b


def _plain_smtp_conversation(
    *, client_port: int, advertise_starttls: bool = False, with_auth: bool = False
) -> Conversation:
    b = Conversation(server=SMTP_SERVER, client_port=client_port)
    (
        b.syn()
        .synack()
        .ack()
        .s(b"220 mail.example.org ESMTP Synthetic\r\n")
        .c(b"EHLO client.example.net\r\n")
    )
    if advertise_starttls:
        b.s(b"250-mail.example.org\r\n250-STARTTLS\r\n250 8BITMIME\r\n")
    else:
        b.s(b"250-mail.example.org\r\n250 8BITMIME\r\n")
    if with_auth:
        (
            b.c(b"AUTH LOGIN\r\n")
            .s(b"334 VXNlcm5hbWU6\r\n")
            .c(b"dGVzdHVzZXI=\r\n")
            .s(b"334 UGFzc3dvcmQ6\r\n")
            .c(b"c3ludGhldGljLXBhc3N3b3Jk\r\n")
            .s(b"235 2.7.0 Authentication successful\r\n")
        )
    (b.c(b"QUIT\r\n").s(b"221 2.0.0 Bye\r\n").fin_c().fin_s())
    return b


# --------------------------------------------------------------------------
# Ground truth
# --------------------------------------------------------------------------

SEV_ORDER = ("critical", "high", "medium", "low", "info")


@dataclass(frozen=True, slots=True)
class GroundTruth:
    """Expected outcomes for one scenario, defined before execution.

    ``rule_severities`` is the exact expected set of fired rule IDs with
    their expected (highest) severity. ``posture_state`` follows from the
    documented Stage 5 scoring formula applied to those expectations
    (severity weights critical 40 / high 25 / medium 12 / low 5 / info 0,
    confidence high 1.0, single-session prevalence 1.0, factor breadth
    0.25 within a factor domain).
    """

    protocol: str
    session_count: int
    tls_version: str | None
    cipher_suite: str | None
    key_exchange: str | None
    handshake_complete: bool | None
    certificate_count: int
    rule_severities: dict[str, str]
    posture_state: str
    anomaly_expectation: str  # "none" | "insufficient_evidence" | "outlier_flagged"
    graph_node_types: tuple[str, ...] = field(default_factory=tuple)

    @property
    def rule_ids(self) -> frozenset[str]:
        return frozenset(self.rule_severities)


# Standard node types present in any session-bearing graph.
_BASIC_GRAPH_NODES = ("capture", "host", "endpoint", "session", "protocol")

SCENARIOS: list[dict[str, object]] = [
    # ---- 1. Secure TLS 1.3 (implicit TLS / IMAPS) --------------------------
    {
        "id": "secure-tls13",
        "title": "Secure TLS 1.3 session (IMAPS)",
        "description": (
            "Implicit-TLS IMAP session negotiating TLS 1.3 with an AEAD suite. "
            "Expected: no policy findings; posture healthy."
        ),
        "build": lambda: _imaps_tls13_conversation(50000).to_pcap(),
        "ground_truth": GroundTruth(
            protocol="imap",
            session_count=1,
            tls_version="TLS 1.3",
            cipher_suite="TLS_AES_128_GCM_SHA256",
            key_exchange="tls13",
            handshake_complete=True,
            certificate_count=0,
            rule_severities={},
            posture_state="healthy",
            anomaly_expectation="insufficient_evidence",
            graph_node_types=_BASIC_GRAPH_NODES,
        ),
    },
    # ---- 2. Secure TLS 1.2 (STARTTLS, complete chain) -----------------------
    {
        "id": "secure-tls12",
        "title": "TLS 1.2 secure configuration (STARTTLS)",
        "description": (
            "STARTTLS upgrade to TLS 1.2 with an ECDHE AEAD suite and an "
            "observed issuer. Expected: no policy findings; posture healthy."
        ),
        "build": lambda: _smtp_starttls_tls_conversation(
            client_port=50010,
            server_hello_flight=(
                server_hello(suite=0xC02F) + certificate_message([_leaf_der(), _ca_der()]) + ccs()
            ),
        ).to_pcap(),
        "ground_truth": GroundTruth(
            protocol="smtp",
            session_count=1,
            tls_version="TLS 1.2",
            cipher_suite="TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            key_exchange="ecdhe",
            handshake_complete=True,
            certificate_count=2,
            rule_severities={},
            posture_state="healthy",
            anomaly_expectation="insufficient_evidence",
            graph_node_types=_BASIC_GRAPH_NODES + ("tls_handshake", "certificate"),
        ),
    },
    # ---- 3. Deprecated TLS version ------------------------------------------
    {
        "id": "deprecated-tls10",
        "title": "Deprecated TLS 1.0 negotiation",
        "description": (
            "STARTTLS session negotiating TLS 1.0 with an ECDHE CBC suite. "
            "Expected: TLS-VERSION-001 (high) and CIPHER-SELECTED-001 (low)."
        ),
        "build": lambda: _smtp_starttls_tls_conversation(
            client_port=50020,
            server_hello_flight=(
                server_hello(server_version=0x0301, suite=0xC013, record_version=0x0301)
                + certificate_message([_leaf_der()])
                + ccs(record_version=0x0301)
            ),
        ).to_pcap(),
        "ground_truth": GroundTruth(
            protocol="smtp",
            session_count=1,
            tls_version="TLS 1.0",
            cipher_suite="TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
            key_exchange="ecdhe",
            handshake_complete=True,
            certificate_count=1,
            rule_severities={
                "TLS-VERSION-001": "high",
                "CIPHER-SELECTED-001": "low",
                "CERT-CHAIN-001": "info",
            },
            posture_state="degraded",
            anomaly_expectation="insufficient_evidence",
            graph_node_types=_BASIC_GRAPH_NODES + ("tls_handshake", "certificate"),
        ),
    },
    # ---- 4. Weak cipher + static RSA key exchange ---------------------------
    {
        "id": "weak-cipher-3des",
        "title": "3DES cipher with static RSA key exchange",
        "description": (
            "TLS 1.2 session selecting TLS_RSA_WITH_3DES_EDE_CBC_SHA. "
            "Expected: CIPHER-SELECTED-001 (medium) and KEYEX-001 (medium)."
        ),
        "build": lambda: _smtp_starttls_tls_conversation(
            client_port=50030,
            server_hello_flight=(
                server_hello(suite=0x000A) + certificate_message([_leaf_der(), _ca_der()]) + ccs()
            ),
        ).to_pcap(),
        "ground_truth": GroundTruth(
            protocol="smtp",
            session_count=1,
            tls_version="TLS 1.2",
            cipher_suite="TLS_RSA_WITH_3DES_EDE_CBC_SHA",
            key_exchange="rsa",
            handshake_complete=True,
            certificate_count=2,
            rule_severities={"CIPHER-SELECTED-001": "medium", "KEYEX-001": "medium"},
            posture_state="acceptable",
            anomaly_expectation="insufficient_evidence",
            graph_node_types=_BASIC_GRAPH_NODES + ("tls_handshake", "certificate"),
        ),
    },
    # ---- 5. Expired certificate ----------------------------------------------
    {
        "id": "expired-certificate",
        "title": "Certificate expired at capture time",
        "description": (
            "TLS 1.2 session with a leaf certificate whose validity ended "
            "2024-06-01, before the 2024-09-27 capture instant. Expected: "
            "CERT-VALIDITY-001 (high)."
        ),
        "build": lambda: _smtp_starttls_tls_conversation(
            client_port=50040,
            server_hello_flight=(
                server_hello() + certificate_message([_leaf_der(validity=VALIDITY_EXPIRED)]) + ccs()
            ),
        ).to_pcap(),
        "ground_truth": GroundTruth(
            protocol="smtp",
            session_count=1,
            tls_version="TLS 1.2",
            cipher_suite="TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            key_exchange="ecdhe",
            handshake_complete=True,
            certificate_count=1,
            rule_severities={"CERT-VALIDITY-001": "high", "CERT-CHAIN-001": "info"},
            posture_state="acceptable",
            anomaly_expectation="insufficient_evidence",
            graph_node_types=_BASIC_GRAPH_NODES + ("tls_handshake", "certificate"),
        ),
    },
    # ---- 6. SHA-1 certificate signature --------------------------------------
    {
        "id": "sha1-certificate",
        "title": "SHA-1 signed certificate",
        "description": (
            "TLS 1.2 session whose leaf certificate is signed with SHA-1. "
            "Expected: CERT-SIG-001 (high)."
        ),
        "build": lambda: _smtp_starttls_tls_conversation(
            client_port=50050,
            server_hello_flight=(
                server_hello() + certificate_message([_sha1_signed_leaf_der()]) + ccs()
            ),
        ).to_pcap(),
        "ground_truth": GroundTruth(
            protocol="smtp",
            session_count=1,
            tls_version="TLS 1.2",
            cipher_suite="TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            key_exchange="ecdhe",
            handshake_complete=True,
            certificate_count=1,
            rule_severities={"CERT-SIG-001": "high", "CERT-CHAIN-001": "info"},
            posture_state="acceptable",
            anomaly_expectation="insufficient_evidence",
            graph_node_types=_BASIC_GRAPH_NODES + ("tls_handshake", "certificate"),
        ),
    },
    # ---- 7. Weak public key ----------------------------------------------------
    {
        "id": "weak-certificate-key",
        "title": "1024-bit RSA certificate key",
        "description": (
            "TLS 1.2 session whose leaf certificate uses a 1024-bit RSA key, "
            "below the 2048-bit policy minimum. Expected: CERT-KEY-001 (high)."
        ),
        "build": lambda: _smtp_starttls_tls_conversation(
            client_port=50060,
            server_hello_flight=(
                server_hello() + certificate_message([_leaf_der(key=_KEY_1024)]) + ccs()
            ),
        ).to_pcap(),
        "ground_truth": GroundTruth(
            protocol="smtp",
            session_count=1,
            tls_version="TLS 1.2",
            cipher_suite="TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            key_exchange="ecdhe",
            handshake_complete=True,
            certificate_count=1,
            rule_severities={"CERT-KEY-001": "high", "CERT-CHAIN-001": "info"},
            posture_state="acceptable",
            anomaly_expectation="insufficient_evidence",
            graph_node_types=_BASIC_GRAPH_NODES + ("tls_handshake", "certificate"),
        ),
    },
    # ---- 8. SAN mismatch --------------------------------------------------------
    {
        "id": "san-mismatch",
        "title": "Certificate does not cover the requested hostname",
        "description": (
            "TLS 1.2 session where SNI mail.example.org does not match the "
            "certificate SAN other.example.org. Expected: CERT-IDENTITY-001 (high)."
        ),
        "build": lambda: _smtp_starttls_tls_conversation(
            client_port=50070,
            server_hello_flight=(
                server_hello() + certificate_message([_leaf_der(sans=[OTHER_CN])]) + ccs()
            ),
        ).to_pcap(),
        "ground_truth": GroundTruth(
            protocol="smtp",
            session_count=1,
            tls_version="TLS 1.2",
            cipher_suite="TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            key_exchange="ecdhe",
            handshake_complete=True,
            certificate_count=1,
            rule_severities={"CERT-IDENTITY-001": "high", "CERT-CHAIN-001": "info"},
            posture_state="acceptable",
            anomaly_expectation="insufficient_evidence",
            graph_node_types=_BASIC_GRAPH_NODES + ("tls_handshake", "certificate"),
        ),
    },
    # ---- 9. Self-signed certificate ----------------------------------------------
    {
        "id": "self-signed-certificate",
        "title": "Self-signed certificate presented",
        "description": (
            "TLS 1.2 session whose leaf certificate is its own issuer with a "
            "matching SAN. Expected: CERT-SELF-SIGNED-001 (low)."
        ),
        "build": lambda: _smtp_starttls_tls_conversation(
            client_port=50080,
            server_hello_flight=(
                server_hello()
                + certificate_message([_leaf_der(subject=LEAF_CN, issuer=LEAF_CN)])
                + ccs()
            ),
        ).to_pcap(),
        "ground_truth": GroundTruth(
            protocol="smtp",
            session_count=1,
            tls_version="TLS 1.2",
            cipher_suite="TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            key_exchange="ecdhe",
            handshake_complete=True,
            certificate_count=1,
            rule_severities={"CERT-SELF-SIGNED-001": "low"},
            posture_state="healthy",
            anomaly_expectation="insufficient_evidence",
            graph_node_types=_BASIC_GRAPH_NODES + ("tls_handshake", "certificate"),
        ),
    },
    # ---- 10. STARTTLS attempted but unsuccessful ---------------------------------
    {
        "id": "starttls-requested-not-accepted",
        "title": "STARTTLS requested but refused (454)",
        "description": (
            "Server advertises STARTTLS, client requests it, server refuses "
            "with 454 and the session stays plaintext. Expected: "
            "STARTTLS-001 (medium) and PLAINTEXT-001 (medium)."
        ),
        "build": lambda: _starttls_refused_conversation(50090).to_pcap(),
        "ground_truth": GroundTruth(
            protocol="smtp",
            session_count=1,
            tls_version=None,
            cipher_suite=None,
            key_exchange=None,
            handshake_complete=None,
            certificate_count=0,
            rule_severities={"STARTTLS-001": "medium", "PLAINTEXT-001": "medium"},
            posture_state="acceptable",
            anomaly_expectation="none",
            graph_node_types=_BASIC_GRAPH_NODES,
        ),
    },
    # ---- 11. Plaintext SMTP -------------------------------------------------------
    {
        "id": "plaintext-smtp",
        "title": "Plaintext SMTP session without TLS",
        "description": (
            "A full SMTP conversation where STARTTLS is never offered or "
            "attempted. Expected: PLAINTEXT-001 (medium)."
        ),
        "build": lambda: _plain_smtp_conversation(client_port=50100).to_pcap(),
        "ground_truth": GroundTruth(
            protocol="smtp",
            session_count=1,
            tls_version=None,
            cipher_suite=None,
            key_exchange=None,
            handshake_complete=None,
            certificate_count=0,
            rule_severities={"PLAINTEXT-001": "medium"},
            posture_state="acceptable",
            anomaly_expectation="none",
            graph_node_types=_BASIC_GRAPH_NODES,
        ),
    },
    # ---- 12. Plaintext authentication -----------------------------------------------
    {
        "id": "plaintext-authentication",
        "title": "Credentials transmitted in plaintext",
        "description": (
            "An SMTP session performing AUTH LOGIN in plaintext (synthetic "
            "credentials). Expected: AUTH-PLAINTEXT-001 (high) and "
            "PLAINTEXT-001 (medium)."
        ),
        "build": lambda: _plain_smtp_conversation(client_port=50110, with_auth=True).to_pcap(),
        "ground_truth": GroundTruth(
            protocol="smtp",
            session_count=1,
            tls_version=None,
            cipher_suite=None,
            key_exchange=None,
            handshake_complete=None,
            certificate_count=0,
            rule_severities={"AUTH-PLAINTEXT-001": "high", "PLAINTEXT-001": "medium"},
            posture_state="degraded",
            anomaly_expectation="none",
            graph_node_types=_BASIC_GRAPH_NODES,
        ),
    },
    # ---- 13. Incomplete TLS handshake -------------------------------------------------
    {
        "id": "incomplete-tls-handshake",
        "title": "TLS handshake aborted after ServerHello",
        "description": (
            "STARTTLS accepted, ClientHello and ServerHello observed, then the "
            "stream ends before any CCS/application data. Expected: "
            "TLS-FAILURE-001 (info)."
        ),
        "build": lambda: _smtp_starttls_tls_conversation(
            client_port=50120,
            server_hello_flight=server_hello(suite=0xC02F),
        ).to_pcap(),
        "ground_truth": GroundTruth(
            protocol="smtp",
            session_count=1,
            tls_version="TLS 1.2",
            cipher_suite="TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            key_exchange="ecdhe",
            handshake_complete=False,
            certificate_count=0,
            rule_severities={"TLS-FAILURE-001": "info"},
            posture_state="healthy",
            anomaly_expectation="insufficient_evidence",
            graph_node_types=_BASIC_GRAPH_NODES + ("tls_handshake",),
        ),
    },
    # ---- 14. TLS behavioral anomaly -----------------------------------------------------
    {
        "id": "tls-anomaly-outlier",
        "title": "TLS behavioral anomaly (capture-local baseline)",
        "description": (
            "Ten implicit-TLS IMAP sessions: nine identical baselines and one "
            "session with an order-of-magnitude larger transfer. Expected: the "
            "outlier is flagged unusual or beyond; baselines stay normal."
        ),
        "build": lambda: _anomaly_conversations(),
        "ground_truth": GroundTruth(
            protocol="imap",
            session_count=10,
            tls_version="TLS 1.2",
            cipher_suite="TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            key_exchange="ecdhe",
            handshake_complete=True,
            certificate_count=0,
            rule_severities={},
            posture_state="healthy",
            anomaly_expectation="outlier_flagged",
            graph_node_types=_BASIC_GRAPH_NODES + ("tls_handshake",),
        ),
    },
    # ---- 15. Multiple sessions, mixed posture -------------------------------------------
    {
        "id": "mixed-posture",
        "title": "Mixed-posture capture (four sessions)",
        "description": (
            "One capture with a secure TLS 1.2 session, a TLS 1.0 session, a "
            "plaintext session, and a plaintext-auth session. Expected: "
            "TLS-VERSION-001, CIPHER-SELECTED-001, PLAINTEXT-001 (x2), "
            "AUTH-PLAINTEXT-001, CERT-CHAIN-001; degraded/high-exposure posture."
        ),
        "build": lambda: _mixed_posture_capture(),
        "ground_truth": GroundTruth(
            protocol="smtp",
            session_count=4,
            tls_version="TLS 1.2",
            cipher_suite="TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            key_exchange="ecdhe",
            handshake_complete=True,
            certificate_count=2,
            rule_severities={
                "TLS-VERSION-001": "high",
                "CIPHER-SELECTED-001": "low",
                "PLAINTEXT-001": "medium",
                "AUTH-PLAINTEXT-001": "high",
                "CERT-CHAIN-001": "info",
            },
            posture_state="high_exposure",
            anomaly_expectation="insufficient_evidence",
            graph_node_types=_BASIC_GRAPH_NODES + ("tls_handshake", "certificate", "finding"),
        ),
    },
]


def _imaps_tls13_conversation(client_port: int) -> Conversation:
    """Implicit-TLS IMAP session negotiating TLS 1.3 (no plaintext, no cert)."""
    b = Conversation(server=IMAPS_SERVER, client_port=client_port)
    (
        b.syn()
        .synack()
        .ack()
        .c(client_hello(suites=(0x1301, 0xC02F), supported_versions=(0x0304, 0x0303)))
        .s(server_hello(suite=0x1301, negotiated_version=0x0304) + ccs())
        .c(app_data(64))
        .s(app_data(256))
        .fin_c()
        .fin_s()
    )
    return b


def _starttls_refused_conversation(client_port: int) -> Conversation:
    b = Conversation(server=SMTP_SERVER, client_port=client_port)
    (
        b.syn()
        .synack()
        .ack()
        .s(b"220 mail.example.org ESMTP Synthetic\r\n")
        .c(b"EHLO client.example.net\r\n")
        .s(b"250-mail.example.org\r\n250-STARTTLS\r\n250 8BITMIME\r\n")
        .c(b"STARTTLS\r\n")
        .s(b"454 4.7.0 TLS not available due to temporary reason\r\n")
        .c(b"QUIT\r\n")
        .s(b"221 2.0.0 Bye\r\n")
        .fin_c()
        .fin_s()
    )
    return b


def _imaps_tls12_conversation(
    client_port: int, server_app_records: int, app_size: int
) -> Conversation:
    """Implicit-TLS IMAP session: TLS 1.2 handshake plus application data."""
    b = Conversation(server=IMAPS_SERVER, client_port=client_port)
    (
        b.syn()
        .synack()
        .ack()
        .c(client_hello(suites=(0xC02F,)))
        .s(server_hello(suite=0xC02F) + ccs())
        .c(app_data(64))
    )
    for _ in range(server_app_records):
        b.s(app_data(app_size))
    b.fin_c().fin_s()
    return b


def _anomaly_conversations() -> bytes:
    """Ten IMAPS sessions in one capture: nine identical baselines, one outlier.

    The outlier transfers an order of magnitude more application data over a
    longer duration while keeping the identical TLS configuration, so every
    continuous behavioral feature separates it from the baseline cluster.
    """
    frames: list[bytes] = []
    for index in range(10):
        outlier = index == 9
        conversation = _imaps_tls12_conversation(
            client_port=50200 + index,
            server_app_records=40 if outlier else 1,
            app_size=1400 if outlier else 512,
        )
        frames.extend(conversation.frames)
    return _merge_frames(frames)


def _merge_frames(frames: list[bytes]) -> bytes:
    out = struct.pack("<I", 0xA1B2C3D4) + struct.pack("<HHiIII", 2, 4, 0, 0, 65535, 1)
    for index, frame in enumerate(frames):
        out += struct.pack("<IIII", CAPTURE_BASE_TS + index, 0, len(frame), len(frame))
        out += frame
    return out


def _mixed_posture_capture() -> bytes:
    """Four SMTP sessions in one capture: secure, TLS 1.0, plaintext, auth."""
    conversations = [
        _smtp_starttls_tls_conversation(
            client_port=50300,
            server_hello_flight=(
                server_hello() + certificate_message([_leaf_der(), _ca_der()]) + ccs()
            ),
        ),
        _smtp_starttls_tls_conversation(
            client_port=50301,
            server_hello_flight=(
                server_hello(server_version=0x0301, suite=0xC013, record_version=0x0301)
                + certificate_message([_leaf_der()])
                + ccs(record_version=0x0301)
            ),
        ),
        _plain_smtp_conversation(client_port=50302),
        _plain_smtp_conversation(client_port=50303, with_auth=True),
    ]
    frames: list[bytes] = []
    for conversation in conversations:
        frames.extend(conversation.frames)
    return _merge_frames(frames)


# --------------------------------------------------------------------------
# Scenario access helpers
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Scenario:
    """One evaluation scenario: identity, deterministic bytes, ground truth."""

    scenario_id: str
    title: str
    description: str
    pcap: bytes
    ground_truth: GroundTruth

    @property
    def filename(self) -> str:
        return f"{self.scenario_id}.pcap"

    @property
    def capture_id(self) -> str:
        return "capture_" + hashlib.sha256(self.pcap).hexdigest()[:12]


def load_scenarios() -> list[Scenario]:
    """Materialize all scenarios deterministically."""
    scenarios: list[Scenario] = []
    for entry in SCENARIOS:
        builder = entry["build"]
        ground_truth = entry["ground_truth"]
        assert callable(builder) and isinstance(ground_truth, GroundTruth)
        pcap = builder()
        scenarios.append(
            Scenario(
                scenario_id=str(entry["id"]),
                title=str(entry["title"]),
                description=str(entry["description"]),
                pcap=pcap,
                ground_truth=ground_truth,
            )
        )
    return scenarios
