"""TLS byte-stream builders for Stage 3 tests.

Emit real TLS record/handshake bytes (synthetic but structurally valid)
so the reconstruction pipeline runs over actual wire-format evidence.
"""

import struct

from conftest import ConversationBuilder

TLS_CONTENT_CHANGE_CIPHER_SPEC = 20
TLS_CONTENT_HANDSHAKE = 22
TLS_CONTENT_APPLICATION_DATA = 23


def tls_record(content_type: int, version: int, payload: bytes) -> bytes:
    return struct.pack(">BHH", content_type, version, len(payload)) + payload


def handshake_message(message_type: int, body: bytes) -> bytes:
    return bytes([message_type]) + len(body).to_bytes(3, "big") + body


def extension(type_code: int, body: bytes) -> bytes:
    return struct.pack(">HH", type_code, len(body)) + body


def client_hello_bytes(
    *,
    sni: bytes = b"mail.example.org",
    suites: tuple[int, ...] = (0xC02F, 0x009C, 0x1301),
    offered_versions: tuple[int, ...] = (0x0304, 0x0303),
    groups: tuple[int, ...] = (29, 23),
    alpn: bytes = b"smtp",
) -> bytes:
    """A realistic TLS 1.3-capable ClientHello (record version 0x0301)."""
    body = struct.pack(">H", 0x0303)  # legacy_version
    body += b"\x42" * 32  # random
    body += bytes([0])  # empty session id
    suites_blob = b"".join(struct.pack(">H", suite) for suite in suites)
    body += struct.pack(">H", len(suites_blob)) + suites_blob
    body += bytes([1, 0])  # compression: null
    exts = b""
    name_entry = bytes([0]) + struct.pack(">H", len(sni)) + sni
    exts += extension(0, struct.pack(">H", len(name_entry)) + name_entry)
    versions_body = bytes([2 * len(offered_versions)]) + b"".join(
        struct.pack(">H", v) for v in offered_versions
    )
    exts += extension(43, versions_body)
    groups_body = struct.pack(">H", 2 * len(groups)) + b"".join(
        struct.pack(">H", g) for g in groups
    )
    exts += extension(10, groups_body)
    algs_body = struct.pack(">H", 4) + struct.pack(">H", 0x0401) + struct.pack(">H", 0x0804)
    exts += extension(13, algs_body)
    alpn_list = bytes([len(alpn)]) + alpn
    exts += extension(16, struct.pack(">H", len(alpn_list)) + alpn_list)
    body += struct.pack(">H", len(exts)) + exts
    return body


def server_hello_bytes(
    *,
    suite: int = 0xC02F,
    supported_version: int | None = None,
) -> bytes:
    body = struct.pack(">H", 0x0303)  # legacy_version
    body += b"\x43" * 32  # random
    body += bytes([0])  # empty session id
    body += struct.pack(">H", suite)
    body += bytes([0])  # compression: null
    exts = b""
    if supported_version is not None:
        exts += extension(43, struct.pack(">H", supported_version))
    body += struct.pack(">H", len(exts)) + exts
    return body


def client_hello_record() -> bytes:
    return tls_record(22, 0x0301, handshake_message(1, client_hello_bytes()))


def server_hello_record(suite: int = 0xC02F, supported_version: int | None = None) -> bytes:
    version = 0x0304 if supported_version is not None else 0x0303
    return tls_record(
        22,
        version,
        handshake_message(2, server_hello_bytes(suite=suite, supported_version=supported_version)),
    )


def tls_record_for_payload(payload: bytes, version: int = 0x0303) -> bytes:
    return tls_record(22, version, payload)


def certificate_message_bytes(der_certificates: list[bytes]) -> bytes:
    entries = b""
    for der in der_certificates:
        entries += len(der).to_bytes(3, "big") + der
    return len(entries).to_bytes(3, "big") + entries


def certificate_record(der_certificates: list[bytes]) -> bytes:
    return tls_record(
        22, 0x0303, handshake_message(11, certificate_message_bytes(der_certificates))
    )


def ccs_record() -> bytes:
    return tls_record(TLS_CONTENT_CHANGE_CIPHER_SPEC, 0x0303, b"\x01")


def smtp_starttls_full_tls_conversation() -> list:
    """STARTTLS negotiation followed by a real TLS 1.2 handshake."""
    b = ConversationBuilder()
    (
        b.syn()
        .synack()
        .ack()
        .s(b"220 mail.example.org ESMTP\r\n")
        .c(b"EHLO client.example.net\r\n")
        .s(b"250-mail.example.org\r\n250-STARTTLS\r\n250 8BITMIME\r\n")
        .c(b"STARTTLS\r\n")
        .s(b"220 2.0.0 Ready to start TLS\r\n")
    )
    b.c(client_hello_record())
    b.s(server_hello_record() + ccs_record())
    b.fin_c().fin_s()
    return b.build()


def implicit_tls_conversation() -> list:
    """IMAPS session: TLS from the first byte, no plaintext at all."""
    b = ConversationBuilder(server=("198.51.100.7", 993))
    (
        b.syn()
        .synack()
        .ack()
        .c(client_hello_record())
        .s(server_hello_record() + ccs_record())
        .fin_c()
        .fin_s()
    )
    return b.build()


def smtp_starttls_tls13_conversation() -> list:
    """STARTTLS followed by a TLS 1.3 handshake (certificate encrypted)."""
    b = ConversationBuilder()
    (
        b.syn()
        .synack()
        .ack()
        .s(b"220 mail.example.org ESMTP\r\n")
        .c(b"EHLO client.example.net\r\n")
        .s(b"250-mail.example.org\r\n250-STARTTLS\r\n250 8BITMIME\r\n")
        .c(b"STARTTLS\r\n")
        .s(b"220 2.0.0 Ready to start TLS\r\n")
    )
    b.c(client_hello_record())
    b.s(
        server_hello_record(suite=0x1301, supported_version=0x0304)
        + ccs_record()
        + tls_record(23, 0x0303, b"encrypted-application-data")
    )
    b.fin_c().fin_s()
    return b.build()


def smtp_starttls_client_hello_only_conversation() -> list:
    """STARTTLS accepted but the capture ends after the ClientHello."""
    b = ConversationBuilder()
    (
        b.syn()
        .synack()
        .ack()
        .s(b"220 mail.example.org ESMTP\r\n")
        .c(b"EHLO client.example.net\r\n")
        .s(b"250-mail.example.org\r\n250-STARTTLS\r\n250 8BITMIME\r\n")
        .c(b"STARTTLS\r\n")
        .s(b"220 2.0.0 Ready to start TLS\r\n")
    )
    b.c(client_hello_record())
    b.fin_c().fin_s()
    return b.build()
