"""Tests for IMAP and POP3 session reconstruction, including credential redaction."""

from conftest import imap_conversation, pop3_conversation
from engine.core.events import EventType
from engine.core.session import Confidence, EmailProtocol
from engine.protocols.reconstruct import reconstruct_session
from engine.transport.flows import build_flows

IMAP_USER = "carol"
IMAP_PASSWORD = "s3cret-password"
POP3_USER = "dave"
POP3_PASSWORD = "hunter2-secret"


def reconstruct_one(packets):
    flows = build_flows("capture_aaaaaaaaaaaa", packets)
    assert len(flows) == 1
    return reconstruct_session(flows[0])


def test_imap_session_events_and_tags() -> None:
    session = reconstruct_one(imap_conversation())

    assert session.protocol is EmailProtocol.IMAP
    assert session.confidence is Confidence.HIGH

    login = next(e for e in session.events if e.type is EventType.AUTHENTICATION)
    assert login.detail["tag"] == "a002"
    assert login.detail["command"] == "LOGIN"
    assert login.detail["credential_data"] == "redacted"

    select = next(e for e in session.events if e.detail.get("command") == "SELECT")
    assert select.detail["tag"] == "a003"


def test_pop3_session_events() -> None:
    session = reconstruct_one(pop3_conversation())

    assert session.protocol is EmailProtocol.POP3
    event_types = [event.type for event in session.events]
    assert EventType.SERVER_GREETING in event_types
    assert EventType.AUTHENTICATION in event_types
    assert event_types[-1] is EventType.CONNECTION_CLOSED


def test_pop3_credentials_are_never_persisted() -> None:
    session = reconstruct_one(pop3_conversation())

    serialized = session.model_dump_json()
    assert POP3_PASSWORD not in serialized
    assert POP3_USER not in serialized
    auth_events = [e for e in session.events if e.type is EventType.AUTHENTICATION]
    assert {e.detail.get("argument") for e in auth_events} == {"redacted"}


def test_imap_credentials_are_never_persisted() -> None:
    session = reconstruct_one(imap_conversation())

    serialized = session.model_dump_json()
    assert IMAP_PASSWORD not in serialized
    assert IMAP_USER not in serialized


def test_redaction_holds_across_the_whole_session_object() -> None:
    session = reconstruct_one(pop3_conversation())

    flat = repr(session.events)
    assert "hunter2" not in flat
    assert "dave" not in flat
