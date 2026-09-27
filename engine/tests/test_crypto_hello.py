"""Tests for ClientHello / ServerHello parsing and extension evidence."""

from engine.crypto.hello import parse_client_hello, parse_server_hello
from tls_bytes import client_hello_bytes, server_hello_bytes


def test_client_hello_parses_fully() -> None:
    hello = parse_client_hello(client_hello_bytes())

    assert hello.client_version == 0x0303
    assert 0xC02F in hello.cipher_suites
    assert 0x1301 in hello.cipher_suites
    assert hello.server_name == "mail.example.org"
    assert 0x0304 in hello.supported_versions
    assert 29 in hello.supported_groups  # x25519
    assert hello.alpn_protocols == ["smtp"]


def test_client_hello_extension_evidence_is_named() -> None:
    hello = parse_client_hello(client_hello_bytes())

    names = {e.name for e in hello.extensions}
    assert "server_name" in names
    assert "supported_versions" in names
    assert "supported_groups" in names
    assert "signature_algorithms" in names
    sni = next(e for e in hello.extensions if e.name == "server_name")
    assert sni.value == "mail.example.org"


def test_server_hello_parses_selected_suite() -> None:
    hello = parse_server_hello(server_hello_bytes())

    assert hello.server_version == 0x0303
    assert hello.selected_cipher_suite == 0xC02F
    assert hello.negotiated_version is None


def test_server_hello_tls13_negotiation() -> None:
    hello = parse_server_hello(server_hello_bytes(suite=0x1301, supported_version=0x0304))

    assert hello.negotiated_version == 0x0304
    assert hello.selected_cipher_suite == 0x1301


def test_truncated_hello_raises_parse_error() -> None:
    body = client_hello_bytes()[:20]

    try:
        parse_client_hello(body)
    except Exception as error:  # HelloParseError
        assert "truncated" in str(error) or "short" in str(error)
    else:
        raise AssertionError("truncated hello parsed without error")
