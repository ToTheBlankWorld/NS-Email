"""Tests for TLS record and handshake message parsing."""

from engine.crypto.records import parse_tls_stream
from tls_bytes import (
    ccs_record,
    client_hello_bytes,
    client_hello_record,
    handshake_message,
    server_hello_record,
    tls_record,
)


def test_parses_records_and_hello_messages() -> None:
    stream = client_hello_record() + server_hello_record() + ccs_record()

    result = parse_tls_stream(stream)

    assert [r.content_type for r in result.records] == [22, 22, 20]
    assert [m.type_name for m in result.handshake_messages] == ["client_hello", "server_hello"]
    assert result.saw_change_cipher_spec is True
    assert result.warnings == []


def test_handshake_message_fragmented_across_records_is_defragmented() -> None:
    hello = handshake_message(1, client_hello_bytes())
    split = len(hello) // 2

    stream = (
        tls_record(22, 0x0301, hello[:split])
        + tls_record(22, 0x0301, hello[split:])
        + server_hello_record()
    )

    result = parse_tls_stream(stream)

    assert [m.type_name for m in result.handshake_messages] == ["client_hello", "server_hello"]
    assert result.warnings == []


def test_truncated_final_record_is_reported() -> None:
    record = client_hello_record()
    truncated = record[:-6]  # cut into the payload

    result = parse_tls_stream(truncated)

    assert any("truncated record" in warning for warning in result.warnings)


def test_truncated_handshake_body_is_reported() -> None:
    body = client_hello_bytes()
    stream = tls_record(22, 0x0301, handshake_message(1, body)[: len(body) - 10])

    result = parse_tls_stream(stream)

    assert result.warnings, "incomplete handshake must be reported"
    assert result.handshake_messages == []


def test_garbage_stream_yields_warning_not_crash() -> None:
    result = parse_tls_stream(b"\xff\xff\xff\xff\xff garbage")

    assert result.records == []
    assert any("unparseable record" in warning for warning in result.warnings)


def test_empty_stream_parses_to_empty_result() -> None:
    result = parse_tls_stream(b"")

    assert result.records == []
    assert result.handshake_messages == []
    assert result.warnings == []
