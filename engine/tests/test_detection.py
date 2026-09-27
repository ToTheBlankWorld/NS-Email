"""Tests for protocol detection confidence and evidence."""

from conftest import (
    DEFAULT_CLIENT,
    imap_conversation,
    malformed_conversation,
    pop3_conversation,
    smtp_plain_conversation,
    unknown_protocol_conversation,
)
from engine.core.session import Confidence, EmailProtocol
from engine.protocols.detection import detect_protocol
from engine.transport.packets import TCP_ACK, TCP_PSH, PacketRecord
from engine.transport.reassembly import StreamAssembler, assemble_direction


def streams_for(packets):
    """Assemble both directions of a conversation (client side = conftest default)."""
    client_pkts = [p for p in packets if (p.src_ip, p.src_port) == DEFAULT_CLIENT]
    server_pkts = [p for p in packets if (p.src_ip, p.src_port) != DEFAULT_CLIENT]
    return assemble_direction(client_pkts), assemble_direction(server_pkts)


def test_smtp_detected_with_high_confidence_and_evidence() -> None:
    client_stream, server_stream = streams_for(smtp_plain_conversation())

    result = detect_protocol(client_stream, server_stream, 49152, 587)

    assert result.protocol is EmailProtocol.SMTP
    assert result.confidence is Confidence.HIGH
    assert any("greeting" in evidence for evidence in result.evidence)
    assert any("commands" in evidence for evidence in result.evidence)


def test_imap_detected() -> None:
    client_stream, server_stream = streams_for(imap_conversation())

    result = detect_protocol(client_stream, server_stream, 49152, 143)

    assert result.protocol is EmailProtocol.IMAP
    assert result.confidence is Confidence.HIGH


def test_pop3_detected() -> None:
    client_stream, server_stream = streams_for(pop3_conversation())

    result = detect_protocol(client_stream, server_stream, 49152, 110)

    assert result.protocol is EmailProtocol.POP3
    assert result.confidence is Confidence.HIGH


def test_unknown_protocol_stays_unknown() -> None:
    client_stream, server_stream = streams_for(unknown_protocol_conversation())

    result = detect_protocol(client_stream, server_stream, 49152, 9999)

    assert result.protocol is None
    assert result.confidence is Confidence.UNKNOWN


def test_malformed_conversation_is_not_confident() -> None:
    client_stream, server_stream = streams_for(malformed_conversation())

    result = detect_protocol(client_stream, server_stream, 49152, 587)

    assert result.confidence is not Confidence.HIGH


def test_service_port_alone_never_identifies_a_protocol() -> None:
    # One packet on port 587 with no email content: port evidence is LOW
    # confidence, and the protocol stays undetermined.
    assembler = StreamAssembler()
    assembler.add_packet(
        PacketRecord(
            number=1,
            timestamp=1.0,
            captured_len=0,
            original_len=0,
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            src_port=40000,
            dst_port=587,
            tcp_flags=TCP_ACK | TCP_PSH,
        )
    )

    result = detect_protocol(assembler.assemble(), StreamAssembler().assemble(), 40000, 587)

    assert result.protocol is None
    assert result.confidence is Confidence.LOW
