"""Deterministic longitudinal drift fixtures (Stage 14).

Three synthetic captures with deliberate, hand-designed evolution:

- Capture A: TLS 1.0 + ECDHE CBC + leafV only (valid at A-time).
  Rules: TLS-VERSION-001 (high), CIPHER-SELECTED-001 (low),
  CERT-CHAIN-001 (info). Posture: degraded.
- Capture B: TLS 1.2 + ECDHE AEAD + full chain (leafB + CA), no
  findings. Posture: healthy.
- Capture C: TLS 1.0 + ECDHE CBC + leafV only (SAME DER as A, hence
  the same fingerprint — but C's packets land two hours later, past
  leafV's not_after, so the certificate is expired at C-time).
  Rules: TLS-VERSION-001, CIPHER-SELECTED-001, CERT-CHAIN-001 plus
  CERT-VALIDITY-001 (high, new). Posture: high_exposure, below A.

All certificates are built from fixed synthetic key material with
fixed serials and validity windows (reused from scripts.fixtures), so
every PCAP — and therefore every capture id, finding id, certificate
fingerprint, and drift id — is byte-stable across runs. Packet
timestamps are fixed per capture (A/B at the fixture base instant, C
exactly two hours later) via an explicit container writer.

GROUND TRUTH (defined before executing the drift engine):

A -> B:
- posture_change (degraded -> healthy, score increases)
- finding_resolved x3 (TLS-VERSION-001, CIPHER-SELECTED-001,
  CERT-CHAIN-001)
- tls_configuration_changed x2 (1.0/CBC removed, 1.2/AEAD added)
- certificate_changed x3 (fpV removed, fpB + fpCA added)
- correlation_pattern_changed x2 (fpV sharing + subjectV sharing
  no longer observed)

B -> C:
- posture_change (healthy -> degraded, score decreases)
- finding_recurred x3 (TLS-VERSION-001, CIPHER-SELECTED-001,
  CERT-CHAIN-001)
- finding_introduced x1 (CERT-VALIDITY-001)
- tls_configuration_changed x2 (1.2/AEAD removed, 1.0/CBC added)
- certificate_changed x3 (fpB + fpCA removed, fpV added)
- certificate_validity_changed x1 (fpV valid at A-time basis is not
  the pair basis; validity is compared B-vs-C evidence — see note)
- correlation_pattern_changed x2 (fpV sharing + subjectV sharing
  newly observed)

NOTE on validity: the validity comparison is per fingerprint present
on both sides of a pair. fpV appears in A and C but in neither pair
together with itself... it appears in pair (A,B)? No — fpV is absent
from B. So within consecutive pairs, fpV never meets itself and no
validity record fires; validity drift for fpV is observable only in
an explicit A-vs-C comparison. The evaluation asserts exactly that:
chain pairs carry no certificate_validity_changed, while POST
comparisons A-vs-C carries exactly one. This is the honest
consequence of pair-scoped comparison, documented here deliberately.

Posture relations (pre-defined, no exact scores asserted):
degraded(A) -> healthy(B) increase; healthy(B) -> degraded(C)
decrease; C scores strictly below A (superset of findings).
"""

import struct
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from scripts.fixtures import (
    _KEY_2048,
    CA_CN,
    CAPTURE_BASE_TS,
    SNI,
    Conversation,
    _ca_der,
    _leaf_der,
    build_certificate,
    ccs,
    certificate_message,
    client_hello,
    server_hello,
)

# Shared mail service endpoint for all three captures (comparable sessions).
ENDPOINT = ("198.51.100.20", 25)

# leafV straddles the A/C observation instants: valid at A, expired at C.
LEAF_V_SERIAL = 0x2000
LEAF_V_SUBJECT = "drift-v.example.org"
LEAF_V_NOT_AFTER_OFFSET = 3600
LEAF_B_SERIAL = 0x2001

# C's packets land exactly two hours after the fixture base instant.
CAPTURE_C_OFFSET = 7200

# TLS 1.0 + ECDHE CBC (configuration V) vs TLS 1.2 + ECDHE AEAD (B).
CONFIG_V_SUITE = 0xC013
CONFIG_B_SUITE = 0xC02F


def _leaf_v_der() -> bytes:
    base = datetime.fromtimestamp(CAPTURE_BASE_TS, tz=UTC)
    return build_certificate(
        serial=LEAF_V_SERIAL,
        subject=LEAF_V_SUBJECT,
        issuer=CA_CN,
        key=_KEY_2048,
        not_before=base - timedelta(days=30),
        not_after=base + timedelta(seconds=LEAF_V_NOT_AFTER_OFFSET),
        sans=[SNI],
    )


def _leaf_b_der() -> bytes:
    return _leaf_der(serial=LEAF_B_SERIAL)


def _smtp_starttls_conversation(
    client_port: int,
    server_hello_flight: bytes,
) -> Conversation:
    """SMTP + STARTTLS + TLS handshake against the shared endpoint."""
    conversation = Conversation(server=ENDPOINT, client_port=client_port)
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


def _to_pcap_at(frames: list[bytes], base_ts: int) -> bytes:
    """Deterministic pcap container with an explicit base timestamp."""
    out = struct.pack("<I", 0xA1B2C3D4) + struct.pack("<HHiIII", 2, 4, 0, 0, 65535, 1)
    for index, frame in enumerate(frames):
        out += struct.pack("<IIII", base_ts + index, 0, len(frame), len(frame))
        out += frame
    return out


def build_capture_a() -> bytes:
    """TLS 1.0 + CBC, leafV only, observed while valid."""
    conversation = _smtp_starttls_conversation(
        50510,
        server_hello_flight=(
            server_hello(server_version=0x0301, suite=CONFIG_V_SUITE, record_version=0x0301)
            + certificate_message([_leaf_v_der()])
            + ccs(record_version=0x0301)
        ),
    )
    return _to_pcap_at(conversation.frames, CAPTURE_BASE_TS)


def build_capture_b() -> bytes:
    """TLS 1.2 + AEAD, full valid chain, no findings."""
    conversation = _smtp_starttls_conversation(
        50511,
        server_hello_flight=(
            server_hello(suite=CONFIG_B_SUITE)
            + certificate_message([_leaf_b_der(), _ca_der()])
            + ccs()
        ),
    )
    return _to_pcap_at(conversation.frames, CAPTURE_BASE_TS)


def build_capture_c() -> bytes:
    """TLS 1.0 + CBC, same leafV DER as A, observed after expiry."""
    conversation = _smtp_starttls_conversation(
        50512,
        server_hello_flight=(
            server_hello(server_version=0x0301, suite=CONFIG_V_SUITE, record_version=0x0301)
            + certificate_message([_leaf_v_der()])
            + ccs(record_version=0x0301)
        ),
    )
    return _to_pcap_at(conversation.frames, CAPTURE_BASE_TS + CAPTURE_C_OFFSET)


@dataclass(frozen=True, slots=True)
class DriftScenario:
    """One longitudinal fixture: identity plus deterministic bytes."""

    scenario_id: str
    pcap: bytes

    @property
    def filename(self) -> str:
        return f"{self.scenario_id}.pcap"


def load_drift_scenarios() -> list[DriftScenario]:
    """Materialize captures A, B, and C deterministically."""
    return [
        DriftScenario(scenario_id="drift-capture-a", pcap=build_capture_a()),
        DriftScenario(scenario_id="drift-capture-b", pcap=build_capture_b()),
        DriftScenario(scenario_id="drift-capture-c", pcap=build_capture_c()),
    ]
