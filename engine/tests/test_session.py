"""Tests for email protocol taxonomy and Session evidence."""

from typing import Any

import pytest
from engine.core.session import Confidence, EmailProtocol, Orientation, Session
from pydantic import ValidationError


def build_session(**overrides: Any) -> Session:
    defaults: dict[str, Any] = {
        "id": "session_" + "a" * 16,
        "capture_id": "capture_aaaaaaaaaaaa",
        "client_ip": "10.10.0.23",
        "server_ip": "198.51.100.7",
        "client_port": 51520,
        "server_port": 993,
    }
    defaults.update(overrides)
    return Session(**defaults)


@pytest.mark.parametrize(
    ("port", "expected"),
    [
        (25, EmailProtocol.SMTP),
        (587, EmailProtocol.SMTP),
        (465, EmailProtocol.SMTP),
        (143, EmailProtocol.IMAP),
        (993, EmailProtocol.IMAP),
        (110, EmailProtocol.POP3),
        (995, EmailProtocol.POP3),
        (8080, None),
        (1, None),
    ],
)
def test_from_port_maps_well_known_email_ports(port: int, expected: EmailProtocol | None) -> None:
    assert EmailProtocol.from_port(port) == expected


@pytest.mark.parametrize(
    ("port", "expected"),
    [(465, True), (993, True), (995, True), (25, False), (587, False), (143, False), (110, False)],
)
def test_is_implicit_tls_port(port: int, expected: bool) -> None:
    assert EmailProtocol.is_implicit_tls_port(port) is expected


def test_session_builds_with_ipv4_and_ipv6_endpoints() -> None:
    session = build_session(client_ip="2001:db8::5")

    assert str(session.client_ip) == "2001:db8::5"
    assert str(session.server_ip) == "198.51.100.7"


def test_reconstruction_fields_start_undetermined() -> None:
    session = build_session()

    assert session.protocol is None
    assert session.confidence is Confidence.UNKNOWN
    assert session.orientation is Orientation.UNKNOWN
    assert session.implicit_tls is None
    assert session.starttls is None
    assert session.events == []
    assert session.complete is False


@pytest.mark.parametrize("port", [65536, -1])
def test_rejects_out_of_range_ports(port: int) -> None:
    with pytest.raises(ValidationError):
        build_session(server_port=port)


def test_rejects_invalid_ip_addresses() -> None:
    with pytest.raises(ValidationError):
        build_session(server_ip="999.10.1.1")


def test_rejects_ids_that_are_not_flow_derived() -> None:
    for bad_id in ["session_short", "random-id", "../etc/passwd", ""]:
        with pytest.raises(ValidationError):
            build_session(id=bad_id)
