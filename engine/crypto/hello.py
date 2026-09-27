"""ClientHello / ServerHello parsing with structured extension extraction."""

import re
import struct
from dataclasses import dataclass, field

from engine.crypto.cipher_suites import (
    EXTENSION_NAMES,
    GROUP_NAMES,
    SIGNATURE_ALGORITHM_NAMES,
    VERSION_NAMES,
    cipher_suite_name,
)


class HelloParseError(ValueError):
    """A hello message body could not be parsed."""


@dataclass(frozen=True, slots=True)
class HelloExtension:
    """One parsed hello extension."""

    type_code: int
    name: str
    length: int
    value: str | None = None


@dataclass(frozen=True, slots=True)
class ClientHello:
    """Parsed ClientHello evidence."""

    client_version: int
    cipher_suites: list[int] = field(default_factory=list)
    extensions: list[HelloExtension] = field(default_factory=list)
    server_name: str | None = None
    supported_versions: list[int] = field(default_factory=list)
    supported_groups: list[int] = field(default_factory=list)
    alpn_protocols: list[str] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class ServerHello:
    """Parsed ServerHello evidence."""

    server_version: int
    selected_cipher_suite: int
    extensions: list[HelloExtension] = field(default_factory=list)
    negotiated_version: int | None = None  # from supported_versions (TLS 1.3)


def _read(data: bytes, offset: int, size: int, what: str) -> tuple[bytes, int]:
    end = offset + size
    if end > len(data):
        raise HelloParseError(f"truncated {what}")
    return data[offset:end], end


def _parse_extensions(data: bytes) -> list[HelloExtension]:
    extensions: list[HelloExtension] = []
    if len(data) < 2:
        return extensions
    total_length = struct.unpack_from(">H", data, 0)[0]
    offset = 2
    end = min(2 + total_length, len(data))
    while offset + 4 <= end:
        type_code, length = struct.unpack_from(">HH", data, offset)
        offset += 4
        body, offset = _read(data, offset, length, "extension body")
        extensions.append(
            HelloExtension(
                type_code=type_code,
                name=EXTENSION_NAMES.get(type_code, f"unknown({type_code:#06x})"),
                length=length,
                value=_summarize_extension(type_code, body),
            )
        )
    return extensions


def _summarize_extension(type_code: int, body: bytes) -> str | None:
    """Bounded, human-readable summary for well-understood extensions."""
    if type_code == 0:  # server_name
        match = re.search(rb"\x00.{2}([A-Za-z0-9.\-*_]+)", body)
        return match.group(1).decode("ascii", "replace") if match else None
    if type_code == 16:  # ALPN
        names = re.findall(rb"[A-Za-z0-9./-]+", body[2:])
        return ", ".join(name.decode("ascii", "replace") for name in names) or None
    if type_code == 43:  # supported_versions
        if len(body) == 2:  # ServerHello: a single negotiated version
            codes = [int.from_bytes(body, "big")]
        elif len(body) > 2:  # ClientHello: 1-byte list length + 2-byte versions
            codes = [int.from_bytes(body[i : i + 2], "big") for i in range(1, len(body) - 1, 2)]
        else:
            codes = []
        return ", ".join(VERSION_NAMES.get(code, f"0x{code:04x}") for code in codes) or None
    if type_code == 10:  # supported_groups
        if len(body) >= 2:
            groups = [int.from_bytes(body[i : i + 2], "big") for i in range(2, len(body) - 1, 2)]
            names = [GROUP_NAMES.get(group, f"0x{group:04x}") for group in groups]
            return ", ".join(names)
        return None
    if type_code == 13:  # signature_algorithms
        if len(body) >= 2:
            algs = [int.from_bytes(body[i : i + 2], "big") for i in range(2, len(body) - 1, 2)]
            names = [SIGNATURE_ALGORITHM_NAMES.get(alg, f"0x{alg:04x}") for alg in algs]
            return ", ".join(names)
        return None
    if type_code in (22, 23, 5, 0xFF01):  # flag-style extensions
        return "offered"
    if type_code == 51:  # key_share — key material is opaque, report shape only
        return f"key material ({len(body)} bytes)"
    if type_code == 35:  # session_ticket
        return f"ticket ({len(body)} bytes)" if body else "offered"
    return f"{len(body)} bytes" if body else None


def parse_client_hello(body: bytes) -> ClientHello:
    """Parse a ClientHello handshake message body."""
    offset = 0
    client_version = struct.unpack_from(">H", body, offset)[0] if len(body) >= 2 else 0
    offset = 2
    _random, offset = _read(body, offset, 32, "client random")
    session_id_length = body[offset]
    offset += 1
    _session_id, offset = _read(body, offset, session_id_length, "session id")
    suites_length = struct.unpack_from(">H", body, offset)[0]
    offset += 2
    suites_blob, offset = _read(body, offset, suites_length, "cipher suites")
    if suites_length % 2:
        raise HelloParseError("cipher suite list length is odd")
    suites = [int.from_bytes(suites_blob[i : i + 2], "big") for i in range(0, len(suites_blob), 2)]
    offset += 1  # compression methods length
    compression_length = body[offset - 1]
    _compression, offset = _read(body, offset, compression_length, "compression methods")

    extensions: list[HelloExtension] = []
    if offset + 2 <= len(body):
        extensions = _parse_extensions(body[offset:])

    server_name = next((e.value for e in extensions if e.type_code == 0 and e.value), None)
    supported_versions: list[int] = []
    for extension in extensions:
        if extension.type_code == 43 and extension.value:
            for name in extension.value.split(", "):
                for code, version_name in VERSION_NAMES.items():
                    if version_name == name:
                        supported_versions.append(code)
    supported_groups: list[int] = []
    groups_ext = next((e for e in extensions if e.type_code == 10), None)
    if groups_ext is not None and groups_ext.value:
        for name in groups_ext.value.split(", "):
            for code, group_name in GROUP_NAMES.items():
                if group_name == name:
                    supported_groups.append(code)
    alpn_ext = next((e for e in extensions if e.type_code == 16), None)
    alpn = alpn_ext.value.split(", ") if alpn_ext and alpn_ext.value else []

    return ClientHello(
        client_version=client_version,
        cipher_suites=suites,
        extensions=extensions,
        server_name=server_name,
        supported_versions=supported_versions,
        supported_groups=supported_groups,
        alpn_protocols=alpn,
    )


def parse_server_hello(body: bytes) -> ServerHello:
    """Parse a ServerHello handshake message body."""
    if len(body) < 2:
        raise HelloParseError("server hello too short")
    server_version = struct.unpack_from(">H", body, 0)[0]
    offset = 2
    _random, offset = _read(body, offset, 32, "server random")
    session_id_length = body[offset]
    offset += 1
    _session_id, offset = _read(body, offset, session_id_length, "session id")
    selected = struct.unpack_from(">H", body, offset)[0]
    offset += 2
    offset += 1  # compression method
    extensions: list[HelloExtension] = []
    if offset + 2 <= len(body):
        extensions = _parse_extensions(body[offset:])

    negotiated: int | None = None
    versions_ext = next((e for e in extensions if e.type_code == 43), None)
    if versions_ext is not None and versions_ext.value:
        for code, name in VERSION_NAMES.items():
            if name == versions_ext.value:
                negotiated = code
                break

    return ServerHello(
        server_version=server_version,
        selected_cipher_suite=selected,
        extensions=extensions,
        negotiated_version=negotiated,
    )


def suite_name(code: int) -> str:
    """Public re-export for callers working with parsed hellos."""
    return cipher_suite_name(code)
