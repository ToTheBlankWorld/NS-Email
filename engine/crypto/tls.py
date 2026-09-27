"""TLS evidence reconstruction for one session.

Combines both directions' post-STARTTLS (or implicit-TLS) byte streams
into structured ``TLSHandshake`` + ``CertificateEvidence`` objects. Facts
only: negotiated version, selected and offered cipher suites, key-exchange
family, hello extensions, and the visible certificate chain. TLS 1.3
encrypts certificates from the ServerHello onward — the evidence records
that limitation instead of pretending otherwise.
"""

import hashlib
from dataclasses import dataclass, field
from datetime import UTC, datetime

from engine.core.certificate import CertificateEvidence
from engine.core.tls import KeyExchange, TlsExtension, TLSHandshake, TLSVersion
from engine.crypto.certificates import parse_certificate_chain
from engine.crypto.cipher_suites import VERSION_NAMES, cipher_suite_name, key_exchange_for_suite
from engine.crypto.hello import (
    ClientHello,
    HelloParseError,
    ServerHello,
    parse_client_hello,
    parse_server_hello,
)
from engine.crypto.records import (
    HANDSHAKE_CERTIFICATE,
    HANDSHAKE_CLIENT_HELLO,
    HANDSHAKE_SERVER_HELLO,
    TlsParseError,
    parse_tls_stream,
)
from engine.transport.reassembly import StreamSlice


def _tls_version_name(code: int | None) -> TLSVersion:
    if code is None:
        return TLSVersion.UNKNOWN
    return TLSVersion(VERSION_NAMES.get(code, "unknown"))


def _negotiated_version(client: ClientHello | None, server: ServerHello | None) -> int | None:
    """The negotiated protocol version from ServerHello evidence."""
    if server is not None and server.negotiated_version is not None:
        return server.negotiated_version
    if server is not None:
        return server.server_version
    if client is not None:
        # No ServerHello seen: report the client's highest offered version.
        if client.supported_versions:
            return max(client.supported_versions)
        return client.client_version
    return None


@dataclass(frozen=True, slots=True)
class TlsEvidenceResult:
    """TLS evidence reconstructed from one session's byte streams."""

    handshake: TLSHandshake
    certificates: list[CertificateEvidence] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def parse_tls_evidence(
    client_slice: StreamSlice,
    server_slice: StreamSlice,
    session_id: str,
) -> TlsEvidenceResult:
    """Reconstruct TLS evidence from both directions' TLS byte streams."""
    warnings: list[str] = []
    client_bytes = client_slice.bytes()
    server_bytes = server_slice.bytes()
    if not client_bytes and not server_bytes:
        return TlsEvidenceResult(
            handshake=_empty_handshake(session_id),
            warnings=["no TLS bytes observed after the plaintext boundary"],
        )

    try:
        client_result = parse_tls_stream(client_bytes) if client_bytes else None
    except TlsParseError as error:
        client_result = None
        warnings.append(f"client TLS stream unparseable: {error}")
    try:
        server_result = parse_tls_stream(server_bytes) if server_bytes else None
    except TlsParseError as error:
        server_result = None
        warnings.append(f"server TLS stream unparseable: {error}")

    client_hello: ClientHello | None = None
    server_hello: ServerHello | None = None
    client_hello_packets: list[int] = []
    server_hello_packets: list[int] = []
    certificate_packets: list[int] = []
    if client_result is not None:
        warnings.extend(f"client stream: {warning}" for warning in client_result.warnings)
        for message in client_result.handshake_messages:
            if message.message_type == HANDSHAKE_CLIENT_HELLO and client_hello is None:
                try:
                    client_hello = parse_client_hello(message.body)
                    client_hello_packets = client_slice.packets_covering(
                        message.offset, message.offset + 4 + len(message.body)
                    )
                except HelloParseError as error:
                    warnings.append(f"ClientHello could not be parsed: {error}")
    if server_result is not None:
        warnings.extend(f"server stream: {warning}" for warning in server_result.warnings)
        for message in server_result.handshake_messages:
            if message.message_type == HANDSHAKE_SERVER_HELLO and server_hello is None:
                try:
                    server_hello = parse_server_hello(message.body)
                    server_hello_packets = server_slice.packets_covering(
                        message.offset, message.offset + 4 + len(message.body)
                    )
                except HelloParseError as error:
                    warnings.append(f"ServerHello could not be parsed: {error}")

    # --- negotiated facts ------------------------------------------------
    negotiated_code = _negotiated_version(client_hello, server_hello)
    tls_version = _tls_version_name(negotiated_code)

    selected_code: int | None = None
    if server_hello is not None:
        selected_code = server_hello.selected_cipher_suite
    cipher_suite = cipher_suite_name(selected_code) if selected_code is not None else None
    key_exchange = key_exchange_for_suite(cipher_suite) if cipher_suite else KeyExchange.UNKNOWN

    extensions: list[TlsExtension] = []
    if server_hello is not None:
        extensions.extend(
            TlsExtension(type_code=e.type_code, name=e.name, length=e.length, value=e.value)
            for e in server_hello.extensions
        )
    if client_hello is not None:
        extensions.extend(
            TlsExtension(type_code=e.type_code, name=e.name, length=e.length, value=e.value)
            for e in client_hello.extensions
        )

    sni = client_hello.server_name if client_hello else None
    offered = (
        [cipher_suite_name(code) for code in client_hello.cipher_suites] if client_hello else []
    )

    # --- certificates (TLS 1.2 plaintext only) ----------------------------
    certificates: list[CertificateEvidence] = []
    if server_result is not None:
        certificate_message = next(
            (
                m
                for m in server_result.handshake_messages
                if m.message_type == HANDSHAKE_CERTIFICATE
            ),
            None,
        )
        if certificate_message is not None:
            certificate_packets = server_slice.packets_covering(
                certificate_message.offset,
                certificate_message.offset + 4 + len(certificate_message.body),
            )
            chain, chain_warnings = parse_certificate_chain(certificate_message, session_id)
            certificates.extend(chain)
            warnings.extend(chain_warnings)
        else:
            warnings.append("no plaintext Certificate message observed in the server stream")

    # --- handshake completeness ------------------------------------------
    saw_client_hello = client_hello is not None
    saw_server_hello = server_hello is not None
    progressed = any(
        result is not None
        and (result.saw_change_cipher_spec or result.saw_application_data or result.saw_alert)
        for result in (client_result, server_result)
    )
    handshake_complete = saw_client_hello and saw_server_hello and progressed
    completeness_reason: str | None = None
    if not handshake_complete:
        reasons = []
        if not saw_client_hello:
            reasons.append("no ClientHello observed")
        if not saw_server_hello:
            reasons.append("no ServerHello observed")
        if saw_client_hello and saw_server_hello and not progressed:
            reasons.append("handshake did not progress beyond the hello exchange")
        completeness_reason = "; ".join(reasons)

    started_at = None
    if client_bytes:
        _, timestamp = client_slice.locator(0)
        started_at = datetime.fromtimestamp(timestamp, tz=UTC)

    handshake = TLSHandshake(
        id=f"tls_{hashlib.sha256(session_id.encode()).hexdigest()[:12]}",
        session_id=session_id,
        tls_version=tls_version,
        cipher_suite=cipher_suite,
        cipher_suite_code=selected_code,
        key_exchange=key_exchange,
        cipher_suites_offered=offered,
        extensions=extensions,
        sni_server_name=sni,
        started_at=started_at,
        handshake_complete=handshake_complete,
        completeness_reason=completeness_reason,
        certificate_ids=[certificate.id for certificate in certificates],
        client_hello_packets=client_hello_packets,
        server_hello_packets=server_hello_packets,
        certificate_packets=certificate_packets,
        warnings=warnings,
    )
    return TlsEvidenceResult(
        handshake=handshake,
        certificates=certificates,
        warnings=warnings,
    )


def _empty_handshake(session_id: str) -> TLSHandshake:
    return TLSHandshake(
        id=f"tls_{hashlib.sha256(session_id.encode()).hexdigest()[:12]}",
        session_id=session_id,
        tls_version=TLSVersion.UNKNOWN,
        key_exchange=KeyExchange.UNKNOWN,
    )
