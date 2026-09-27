"""End-to-end engine pipeline tests: packets → flows → sessions."""

from conftest import (
    incomplete_conversation,
    malformed_conversation,
    pop3_conversation,
    smtp_out_of_order_conversation,
    smtp_plain_conversation,
    smtp_retransmission_conversation,
    unknown_protocol_conversation,
)
from engine.analysis import analyze_capture_packets
from engine.core.events import EventType
from engine.core.session import Confidence, EmailProtocol, Orientation


def analyze(packets):
    return analyze_capture_packets("capture_aaaaaaaaaaaa", packets)


def test_full_smtp_session_analysis() -> None:
    result = analyze(smtp_plain_conversation())

    assert len(result.sessions) == 1
    session = result.sessions[0]
    assert session.protocol is EmailProtocol.SMTP
    assert session.confidence is Confidence.HIGH
    assert session.orientation is Orientation.CLIENT_SERVER
    assert str(session.client_ip) == "10.10.0.23"
    assert str(session.server_ip) == "198.51.100.7"
    assert session.server_port == 587
    assert session.complete is True
    assert session.packet_count == len(smtp_plain_conversation())
    assert session.bytes_client_to_server > 0
    assert session.bytes_server_to_client > 0
    assert session.started_at is not None and session.ended_at is not None
    assert session.duration_seconds is not None and session.duration_seconds >= 0


def test_out_of_order_capture_still_reconstructs_clean_session() -> None:
    result = analyze(smtp_out_of_order_conversation())

    session = result.sessions[0]
    # reassembly reordered the segments: no gaps, clean termination
    assert session.gap_count == 0
    assert session.complete is True
    # both commands were recovered; the timeline reflects observation order
    commands = [
        e.detail.get("command") for e in session.events if e.type is EventType.CLIENT_COMMAND
    ]
    assert sorted(commands, key=str.lower) == ["EHLO", "QUIT"]


def test_retransmission_is_reported_on_the_session() -> None:
    result = analyze(smtp_retransmission_conversation())

    session = result.sessions[0]
    assert session.retransmissions >= 1


def test_incomplete_capture_reports_missing_evidence_honestly() -> None:
    result = analyze(incomplete_conversation())

    session = result.sessions[0]
    assert session.complete is False
    assert session.completeness_reason is not None
    assert "gap" in session.completeness_reason.lower()
    assert session.gap_count >= 1


def test_unknown_protocol_yields_transport_level_session_without_claims() -> None:
    result = analyze(unknown_protocol_conversation())

    session = result.sessions[0]
    assert session.protocol is None
    assert session.confidence is Confidence.UNKNOWN
    # transport facts are still recorded
    assert session.packet_count > 0
    assert session.complete is True


def test_malformed_conversation_does_not_crash_analysis() -> None:
    result = analyze(malformed_conversation())

    assert len(result.sessions) == 1
    session = result.sessions[0]
    assert session.protocol is None


def test_multiple_flows_produce_multiple_ordered_sessions() -> None:
    packets = [
        *smtp_plain_conversation(),
        *pop3_conversation(),
    ]

    result = analyze(packets)

    assert len(result.sessions) == 2
    protocols = {session.protocol for session in result.sessions}
    assert protocols == {EmailProtocol.SMTP, EmailProtocol.POP3}
    # sessions are ordered by first packet timestamp
    starts = [s.started_at for s in result.sessions]
    assert starts == sorted(
        starts, key=lambda value: (value.hour, value.minute, value.second, value.microsecond)
    )


def test_session_ids_are_stable_across_reanalysis() -> None:
    first = analyze(smtp_plain_conversation()).sessions[0].id
    second = analyze(smtp_plain_conversation()).sessions[0].id

    assert first == second
