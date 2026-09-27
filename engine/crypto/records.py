"""TLS record and handshake message parsing.

Parses the plaintext portion of a TLS byte stream (the reassembled bytes
of one direction after a STARTTLS boundary, or of an implicit-TLS session)
into records and defragmented handshake messages. Parsing is defensive and
bounded: any truncation, corruption, or encryption boundary is reported as
a warning — malformed input never produces fabricated structures.
"""

import struct
from dataclasses import dataclass, field
from typing import Final

from engine.ingestion.errors import CaptureIngestionError

# Record content types (RFC 5246 §6.2.1, RFC 8446).
CONTENT_CHANGE_CIPHER_SPEC: Final[int] = 20
CONTENT_ALERT: Final[int] = 21
CONTENT_HANDSHAKE: Final[int] = 22
CONTENT_APPLICATION_DATA: Final[int] = 23

CONTENT_TYPE_NAMES: Final[dict[int, str]] = {
    20: "change_cipher_spec",
    21: "alert",
    22: "handshake",
    23: "application_data",
}

# Handshake message types (RFC 5246 §7.4, RFC 8446 §4).
HANDSHAKE_HELLO_REQUEST: Final[int] = 0
HANDSHAKE_CLIENT_HELLO: Final[int] = 1
HANDSHAKE_SERVER_HELLO: Final[int] = 2
HANDSHAKE_CERTIFICATE: Final[int] = 11
HANDSHAKE_SERVER_KEY_EXCHANGE: Final[int] = 12
HANDSHAKE_SERVER_HELLO_DONE: Final[int] = 14
HANDSHAKE_CLIENT_KEY_EXCHANGE: Final[int] = 16
HANDSHAKE_FINISHED: Final[int] = 20
HANDSHAKE_ENCRYPTED_EXTENSIONS: Final[int] = 8

HANDSHAKE_TYPE_NAMES: Final[dict[int, str]] = {
    0: "hello_request",
    1: "client_hello",
    2: "server_hello",
    4: "new_session_ticket",
    8: "encrypted_extensions",
    11: "certificate",
    12: "server_key_exchange",
    13: "certificate_request",
    14: "server_hello_done",
    15: "certificate_verify",
    16: "client_key_exchange",
    20: "finished",
    24: "key_update",
}

MAX_RECORD_LENGTH: Final[int] = 18432 + 5  # 2^14 + overhead, with slack
MAX_HANDSHAKE_MESSAGE_LENGTH: Final[int] = 1 << 20


class TlsParseError(CaptureIngestionError):
    """The byte stream cannot be parsed as TLS at all."""


@dataclass(frozen=True, slots=True)
class TlsRecord:
    """One parsed TLS record header + payload."""

    content_type: int
    version: int  # raw 16-bit record-layer version
    payload: bytes
    offset: int  # byte offset of this record in the parsed stream

    @property
    def content_type_name(self) -> str:
        return CONTENT_TYPE_NAMES.get(self.content_type, f"unknown({self.content_type})")

    @property
    def is_encrypted(self) -> bool:
        """Application-data records after the first CCS are ciphertext."""
        return self.content_type == CONTENT_APPLICATION_DATA


@dataclass(frozen=True, slots=True)
class TlsHandshakeMessage:
    """One defragmented handshake message."""

    message_type: int
    body: bytes
    offset: int  # byte offset of the message's first record in the stream

    @property
    def type_name(self) -> str:
        return HANDSHAKE_TYPE_NAMES.get(self.message_type, f"unknown({self.message_type})")


@dataclass(frozen=True, slots=True)
class TlsParseResult:
    """Parsed records and handshake messages plus honest parse coverage."""

    records: list[TlsRecord] = field(default_factory=list)
    handshake_messages: list[TlsHandshakeMessage] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def saw_change_cipher_spec(self) -> bool:
        return any(r.content_type == CONTENT_CHANGE_CIPHER_SPEC for r in self.records)

    @property
    def saw_application_data(self) -> bool:
        return any(r.content_type == CONTENT_APPLICATION_DATA for r in self.records)

    @property
    def saw_alert(self) -> bool:
        return any(r.content_type == CONTENT_ALERT for r in self.records)


def parse_tls_stream(data: bytes) -> TlsParseResult:
    """Parse a plaintext TLS byte stream into records and handshake messages.

    Handshake messages fragmented across records are reassembled
    (handshake bodies are up to 2^24 bytes; hello messages routinely span
    records). Records that cannot be parsed are counted as warnings.
    """
    warnings: list[str] = []
    records: list[TlsRecord] = []
    messages: list[TlsHandshakeMessage] = []
    offset = 0
    total = len(data)

    # Defragmentation state for the handshake content type.
    hs_buffer = bytearray()
    hs_buffer_offset: int | None = None
    hs_expected_length: int | None = None
    hs_message_type: int | None = None

    def _flush_handshake(force: bool = False) -> None:
        nonlocal hs_buffer, hs_buffer_offset, hs_expected_length, hs_message_type
        while hs_buffer:
            if hs_expected_length is None:
                if len(hs_buffer) < 4:
                    if force:
                        warnings.append("truncated handshake message header at end of stream")
                    return
                message_type = hs_buffer[0]
                length = int.from_bytes(hs_buffer[1:4], "big")
                if length > MAX_HANDSHAKE_MESSAGE_LENGTH:
                    warnings.append("implausible handshake message length; stream discarded")
                    hs_buffer = bytearray()
                    hs_buffer_offset = None
                    hs_expected_length = None
                    hs_message_type = None
                    return
                hs_message_type = message_type
                hs_expected_length = length
            if len(hs_buffer) < 4 + hs_expected_length:
                if force and hs_expected_length is not None:
                    type_name = HANDSHAKE_TYPE_NAMES.get(
                        hs_message_type if hs_message_type is not None else -1,
                        "handshake",
                    )
                    warnings.append(f"incomplete {type_name} message at end of stream")
                return
            body = bytes(hs_buffer[4 : 4 + hs_expected_length])
            messages.append(
                TlsHandshakeMessage(
                    message_type=hs_message_type or 0,
                    body=body,
                    offset=hs_buffer_offset or 0,
                )
            )
            del hs_buffer[: 4 + hs_expected_length]
            hs_expected_length = None
            hs_message_type = None
            hs_buffer_offset = None

    while offset + 5 <= total:
        content_type, version, length = struct.unpack_from(">BHH", data, offset)
        if length > MAX_RECORD_LENGTH or content_type not in CONTENT_TYPE_NAMES:
            warnings.append(
                f"unparseable record header at offset {offset}; remaining bytes treated as opaque"
            )
            break
        payload = data[offset + 5 : offset + 5 + length]
        if len(payload) < length:
            warnings.append(f"truncated record at offset {offset}")
            records.append(
                TlsRecord(
                    content_type=content_type,
                    version=version,
                    payload=payload,
                    offset=offset,
                )
            )
            if content_type == CONTENT_HANDSHAKE:
                hs_buffer.extend(payload)
                if hs_buffer_offset is None:
                    hs_buffer_offset = offset + 5
            break
        records.append(
            TlsRecord(content_type=content_type, version=version, payload=payload, offset=offset)
        )
        if content_type == CONTENT_HANDSHAKE:
            if not hs_buffer:
                hs_buffer_offset = offset + 5
            hs_buffer.extend(payload)
            _flush_handshake()
        offset += 5 + length

    _flush_handshake(force=True)
    return TlsParseResult(records=records, handshake_messages=messages, warnings=warnings)
