"""Tests for SMTP session reconstruction: events, STARTTLS, redaction."""

from conftest import (
    smtp_fragmented_conversation,
    smtp_plain_conversation,
    smtp_starttls_conversation,
)
from engine.core.events import EventType
from engine.core.session import Confidence, EmailProtocol, Orientation
from engine.protocols.reconstruct import reconstruct_session


def test_smtp_session_reconstructs_full_timeline() -> None:
    session = reconstruct_session_flow(smtp_plain_conversation())

    assert session.protocol is EmailProtocol.SMTP
    assert session.confidence is Confidence.HIGH
    assert session.orientation is Orientation.CLIENT_SERVER
    assert session.complete is True
    event_types = [event.type for event in session.events]
    assert event_types[0] is EventType.CONNECTION_ESTABLISHED
    assert EventType.SERVER_GREETING in event_types
    assert EventType.MAIL_TRANSACTION_START in event_types
    assert EventType.MAIL_TRANSACTION_COMPLETE in event_types
    assert event_types[-1] is EventType.CONNECTION_CLOSED


def reconstruct_session_flow(packets):
    from engine.transport.flows import build_flows

    flows = build_flows("capture_aaaaaaaaaaaa", packets)
    assert len(flows) == 1
    return reconstruct_session(flows[0])


def test_smtp_events_reference_packets_and_timestamps() -> None:
    session = reconstruct_session_flow(smtp_plain_conversation())

    greeting = next(e for e in session.events if e.type is EventType.SERVER_GREETING)
    assert greeting.packet_numbers, "greeting must reference packet numbers"
    assert greeting.timestamp is not None
    assert greeting.detail["banner"].startswith("220")

    transaction = next(e for e in session.events if e.type is EventType.MAIL_TRANSACTION_START)
    assert "alice@example.net" in transaction.detail["envelope"]


def test_smtp_fragmented_payload_still_reconstructs_banner() -> None:
    session = reconstruct_session_flow(smtp_fragmented_conversation())

    greeting = next(e for e in session.events if e.type is EventType.SERVER_GREETING)
    assert "mail.example.org" in greeting.detail["banner"]


def test_smtp_starttls_negotiation_is_recorded_with_transition() -> None:
    session = reconstruct_session_flow(smtp_starttls_conversation())

    assert session.starttls is not None
    assert session.starttls.advertised is True
    assert session.starttls.requested is True
    assert session.starttls.response_seen is True
    assert session.starttls.packet_number is not None

    event_types = [event.type for event in session.events]
    assert EventType.STARTTLS_ADVERTISED in event_types
    assert EventType.STARTTLS_REQUESTED in event_types
    assert EventType.STARTTLS_RESPONSE in event_types
    assert EventType.TLS_TRANSITION in event_types
    # the transition is the last plaintext event before close
    transition_index = event_types.index(EventType.TLS_TRANSITION)
    assert event_types[transition_index + 1] is EventType.CONNECTION_CLOSED
    assert any("encrypted" in warning for warning in session.warnings)


def test_smtp_starttls_absent_when_never_negotiated() -> None:
    session = reconstruct_session_flow(smtp_plain_conversation())

    assert session.starttls is None
    assert not any(e.type is EventType.TLS_TRANSITION for e in session.events)
