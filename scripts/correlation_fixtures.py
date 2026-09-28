"""Deterministic multi-capture correlation fixtures (Stage 12).

Three synthetic captures with deliberate, hand-designed overlaps:

- Capture A: endpoint X, TLS configuration X, certificate X (full chain)
- Capture B: endpoint X, TLS configuration Y, certificate X (leaf only)
- Capture C: endpoint Z, TLS configuration X, certificate Y (leaf only)

All certificates are built from fixed synthetic key material with fixed
serials and validity windows (reused from scripts.fixtures), so every
PCAP — and therefore every capture id, finding id, certificate
fingerprint, and correlation id — is byte-stable across runs.

GROUND TRUTH (defined before executing the correlation engine):

- endpoint X (198.51.100.20:25): A + B            -> shared_endpoint
- host of endpoint X: A + B                       -> shared_host
- certificate X fingerprint: A + B                -> shared_certificate
- certificate X subject: A + B                    -> shared_certificate_subject
- TLS configuration X (1.2/ECDHE/GCM): A + C      -> shared_tls_configuration
- protocol smtp: A + B + C                        -> shared_protocol
- CERT-CHAIN-001 (leaf without issuer): B + C     -> shared_finding
- session pattern (smtp/STARTTLS/TLS-1.2): A+B+C  -> repeated_session_pattern
- SNI mail.example.org: A + B + C                 -> shared_evidence (sni)
- issuer Synthetic Mail CA: A + B + C             -> shared_evidence (issuer)

Capture B negotiates TLS_RSA_WITH_3DES_EDE_CBC_SHA (configuration Y),
which additionally fires CIPHER-SELECTED-001 and KEYEX-001 in B alone;
those single-capture rules correctly produce no correlation.
"""

from dataclasses import dataclass

from scripts.fixtures import (
    Conversation,
    _ca_der,
    _leaf_der,
    ccs,
    certificate_message,
    client_hello,
    server_hello,
)

# Endpoint X: the shared mail service. Endpoint Z: an unrelated host.
ENDPOINT_X = ("198.51.100.20", 25)
ENDPOINT_Z = ("198.51.100.22", 25)

# Certificate Y: distinct subject, same issuer as certificate X.
CERT_Y_SUBJECT = "archive.example.org"

# TLS configuration X: TLS 1.2 + ECDHE AEAD. Configuration Y: 3DES/RSA.
CONFIG_X_SUITE = 0xC02F
CONFIG_Y_SUITE = 0x000A


def _smtp_starttls_conversation(
    server: tuple[str, int],
    client_port: int,
    server_hello_flight: bytes,
) -> Conversation:
    """SMTP + STARTTLS + TLS handshake against an explicit server."""
    conversation = Conversation(server=server, client_port=client_port)
    (
        conversation.syn()
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
    return conversation


def _cert_x_der() -> bytes:
    return _leaf_der()


def _cert_y_der() -> bytes:
    return _leaf_der(serial=0x1001, subject=CERT_Y_SUBJECT)


def build_capture_a() -> bytes:
    """Endpoint X, configuration X, certificate X with a complete chain."""
    return _smtp_starttls_conversation(
        ENDPOINT_X,
        50400,
        server_hello_flight=(
            server_hello(suite=CONFIG_X_SUITE)
            + certificate_message([_cert_x_der(), _ca_der()])
            + ccs()
        ),
    ).to_pcap()


def build_capture_b() -> bytes:
    """Endpoint X, configuration Y (3DES/RSA), certificate X leaf only."""
    return _smtp_starttls_conversation(
        ENDPOINT_X,
        50401,
        server_hello_flight=(
            server_hello(suite=CONFIG_Y_SUITE) + certificate_message([_cert_x_der()]) + ccs()
        ),
    ).to_pcap()


def build_capture_c() -> bytes:
    """Endpoint Z, configuration X, certificate Y leaf only."""
    return _smtp_starttls_conversation(
        ENDPOINT_Z,
        50402,
        server_hello_flight=(
            server_hello(suite=CONFIG_X_SUITE) + certificate_message([_cert_y_der()]) + ccs()
        ),
    ).to_pcap()


@dataclass(frozen=True, slots=True)
class CorrelationScenario:
    """One correlation fixture: identity plus deterministic bytes."""

    scenario_id: str
    pcap: bytes

    @property
    def filename(self) -> str:
        return f"{self.scenario_id}.pcap"


def load_correlation_scenarios() -> list[CorrelationScenario]:
    """Materialize captures A, B, and C deterministically."""
    return [
        CorrelationScenario(scenario_id="corr-capture-a", pcap=build_capture_a()),
        CorrelationScenario(scenario_id="corr-capture-b", pcap=build_capture_b()),
        CorrelationScenario(scenario_id="corr-capture-c", pcap=build_capture_c()),
    ]
