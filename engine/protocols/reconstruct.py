"""Session reconstruction: from a reassembled flow to a Session model.

Pipeline per flow: protocol detection → orientation (SYN, service ports,
then greeting evidence) → protocol conversation events (SMTP/IMAP/POP3) →
Session evidence with a timeline and evidence references. Unknown
protocols produce a transport-level session without protocol claims.
"""

from dataclasses import replace
from datetime import UTC, datetime
from ipaddress import ip_address

from engine.core.certificate import CertificateEvidence
from engine.core.events import EventDirection, EventType, SessionEvent
from engine.core.session import (
    Confidence,
    EmailProtocol,
    Orientation,
    Session,
    StarttlsObservation,
)
from engine.core.tls import TLSHandshake, TLSVersion
from engine.crypto.tls import parse_tls_evidence
from engine.protocols.base import (
    RawEvent,
    ReconstructedConversation,
    extract_lines,
    merge_conversation,
)
from engine.protocols.detection import detect_protocol
from engine.protocols.imap import build_imap_conversation
from engine.protocols.pop3 import build_pop3_conversation
from engine.protocols.smtp import build_smtp_conversation
from engine.transport.flows import Direction, Flow
from engine.transport.orientation import OrientationResult, determine_orientation
from engine.transport.reassembly import StreamSlice, assemble_direction

_DETECTORS = {
    EmailProtocol.SMTP: build_smtp_conversation,
    EmailProtocol.IMAP: build_imap_conversation,
    EmailProtocol.POP3: build_pop3_conversation,
}


def _to_datetime(epoch: float) -> datetime:
    return datetime.fromtimestamp(epoch, tz=UTC)


def reconstruct_session(flow: Flow) -> Session:
    """Reconstruct one session from a reassembled, bidirectional flow."""
    warnings: list[str] = []
    stream_a = assemble_direction(flow.direction_a.packets)
    stream_b = assemble_direction(flow.direction_b.packets)

    detection = detect_protocol(stream_a, stream_b, flow.direction_a.port, flow.direction_b.port)
    if detection.confidence is Confidence.UNKNOWN:
        warnings.extend(f"protocol detection: {evidence}" for evidence in detection.evidence)

    orientation_result = determine_orientation(flow)
    if (
        orientation_result is None
        and detection.protocol is not None
        and detection.greeting_direction in ("a", "b")
    ):
        # Email servers speak first: the greeting direction is the server.
        if detection.greeting_direction == "a":
            orientation_result = _greeting_orientation(
                client=flow.direction_b, server=flow.direction_a
            )
        else:
            orientation_result = _greeting_orientation(
                client=flow.direction_a, server=flow.direction_b
            )
        warnings.append("orientation inferred from server greeting evidence")

    if orientation_result is None:
        client, server = flow.direction_a, flow.direction_b
        orientation = Orientation.UNKNOWN
        warnings.append(
            "client/server orientation could not be established; endpoints are "
            "reported in canonical order"
        )
    else:
        orientation = orientation_result.orientation
        client, server = _directions_for(flow, orientation_result)

    client_stream = stream_a if flow.direction_a is client else stream_b
    server_stream = stream_b if flow.direction_a is client else stream_a

    events: list[RawEvent] = []
    first = flow.first_packet
    last = flow.last_packet

    if first is not None:
        events.append(
            RawEvent(
                type=EventType.CONNECTION_ESTABLISHED,
                direction=EventDirection.UNKNOWN,
                timestamp=first.timestamp,
                packet_numbers=[first.number],
                detail={"basis": "syn" if first.has_syn else "first packet"},
            )
        )

    conversation = ReconstructedConversation()
    starttls = StarttlsObservation()
    if detection.protocol is not None:
        conversation_lines = merge_conversation(
            extract_lines(client_stream, EventDirection.CLIENT_TO_SERVER),
            extract_lines(server_stream, EventDirection.SERVER_TO_CLIENT),
        )
        conversation = _DETECTORS[detection.protocol](conversation_lines)
        events.extend(conversation.events)
        starttls = conversation.starttls.to_observation()
        warnings.extend(conversation.warnings)

    if last is not None and (last.has_fin or last.has_rst):
        events.append(
            RawEvent(
                type=EventType.CONNECTION_CLOSED,
                direction=EventDirection.UNKNOWN,
                timestamp=last.timestamp,
                packet_numbers=[last.number],
                detail={"basis": "rst" if last.has_rst else "fin"},
            )
        )
    elif conversation.saw_graceful_logout and last is not None:
        events.append(
            RawEvent(
                type=EventType.CONNECTION_CLOSED,
                direction=EventDirection.UNKNOWN,
                timestamp=last.timestamp,
                packet_numbers=[last.number],
                detail={"basis": "protocol"},
            )
        )

    gap_count = stream_a.gap_count + stream_b.gap_count
    gap_bytes = stream_a.gap_bytes + stream_b.gap_bytes
    graceful_termination = any(
        (stream.fin_seen or stream.rst_seen) for stream in (stream_a, stream_b)
    )
    complete = gap_count == 0 and graceful_termination
    completeness_reason: str | None = None
    if not complete:
        reasons = []
        if gap_count:
            reasons.append(f"{gap_count} gap(s) covering {gap_bytes} byte(s)")
        if not graceful_termination:
            reasons.append("no FIN or RST observed (no graceful termination)")
        completeness_reason = "; ".join(reasons)

    # --- TLS reconstruction (Stage 3) ------------------------------------
    handshake: TLSHandshake | None = None
    certificates: list[CertificateEvidence] = []
    implicit_tls = EmailProtocol.is_implicit_tls_port(
        flow.direction_b.port
    ) or EmailProtocol.is_implicit_tls_port(flow.direction_a.port)
    if conversation.starttls.response_seen and (
        conversation.starttls.client_tls_start is not None
        and conversation.starttls.server_tls_start is not None
    ):
        client_tls = StreamSlice(client_stream, conversation.starttls.client_tls_start)
        server_tls = StreamSlice(server_stream, conversation.starttls.server_tls_start)
        evidence = parse_tls_evidence(client_tls, server_tls, session_id=flow.id)
        handshake = evidence.handshake
        certificates = evidence.certificates
        warnings.extend(evidence.warnings)
    elif implicit_tls:
        # The whole session is TLS from the first byte.
        evidence = parse_tls_evidence(
            StreamSlice(client_stream, 0), StreamSlice(server_stream, 0), session_id=flow.id
        )
        handshake = evidence.handshake
        certificates = evidence.certificates
        warnings.extend(evidence.warnings)
        if handshake.tls_version is not TLSVersion.UNKNOWN and detection.protocol is None:
            port_protocol = EmailProtocol.from_port(
                flow.direction_b.port
            ) or EmailProtocol.from_port(flow.direction_a.port)
            if port_protocol is not None:
                detection = replace(detection, protocol=port_protocol, confidence=Confidence.MEDIUM)
                warnings.append(
                    "protocol inferred from the implicit-TLS service port and a "
                    "successful TLS handshake"
                )

    started_at = _to_datetime(first.timestamp) if first is not None else None
    ended_at = _to_datetime(last.timestamp) if last is not None else None
    duration = last.timestamp - first.timestamp if first is not None and last is not None else None

    return Session(
        id=flow.id,
        capture_id=flow.capture_id,
        client_ip=ip_address(client.ip),
        client_port=client.port,
        server_ip=ip_address(server.ip),
        server_port=server.port,
        protocol=detection.protocol,
        confidence=detection.confidence,
        orientation=orientation,
        implicit_tls=implicit_tls,
        started_at=started_at,
        ended_at=ended_at,
        duration_seconds=max(0.0, duration) if duration is not None else None,
        packet_count=flow.packet_count,
        bytes_client_to_server=client_stream.bytes_reconstructed,
        bytes_server_to_client=server_stream.bytes_reconstructed,
        complete=complete,
        completeness_reason=completeness_reason,
        handshake=handshake,
        certificates=certificates,
        retransmissions=stream_a.retransmitted_segments + stream_b.retransmitted_segments,
        gap_count=gap_count,
        gap_bytes=gap_bytes,
        starttls=(
            starttls
            if (starttls.advertised or starttls.requested or starttls.response_seen)
            else None
        ),
        warnings=warnings,
        events=_number_events(events),
    )


def _greeting_orientation(client: Direction, server: Direction) -> OrientationResult:
    return OrientationResult(
        client_ip=client.ip,
        client_port=client.port,
        server_ip=server.ip,
        server_port=server.port,
        orientation=Orientation.CLIENT_SERVER,
        basis="server_greeting",
    )


def _directions_for(flow: Flow, result: OrientationResult) -> tuple[Direction, Direction]:
    client = next(
        d
        for d in (flow.direction_a, flow.direction_b)
        if (d.ip, d.port) == (result.client_ip, result.client_port)
    )
    server = next(
        d
        for d in (flow.direction_a, flow.direction_b)
        if (d.ip, d.port) == (result.server_ip, result.server_port)
    )
    return client, server


def _number_events(events: list[RawEvent]) -> list[SessionEvent]:
    ordered = sorted(
        enumerate(events),
        key=lambda pair: (
            pair[1].timestamp if pair[1].timestamp is not None else float("inf"),
            min(pair[1].packet_numbers) if pair[1].packet_numbers else 1 << 30,
            pair[0],
        ),
    )
    return [
        SessionEvent(
            seq=index,
            type=raw.type,
            direction=raw.direction,
            timestamp=_to_datetime(raw.timestamp) if raw.timestamp is not None else None,
            packet_numbers=raw.packet_numbers,
            detail=raw.detail,
        )
        for index, (_, raw) in enumerate(ordered)
    ]
