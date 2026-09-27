"""POP3 session reconstruction.

Credential safety is absolute here: USER and PASS arguments are observed
as command types only and their values are redacted before storage.
Multi-line responses (LIST/RETR/TOP/CAPA) are consumed without storing
message content.
"""

from typing import Final

from engine.core.events import EventDirection, EventType, safe_value
from engine.protocols.base import (
    ConversationLine,
    RawEvent,
    ReconstructedConversation,
    StarttlsTracker,
)
from engine.protocols.redaction import command_and_args

_C2S: Final[EventDirection] = EventDirection.CLIENT_TO_SERVER
_S2C: Final[EventDirection] = EventDirection.SERVER_TO_CLIENT

_MULTILINE_COMMANDS: Final[frozenset[str]] = frozenset({"LIST", "RETR", "TOP", "CAPA", "UIDL"})


def build_pop3_conversation(lines: list[ConversationLine]) -> ReconstructedConversation:
    """Walk a merged POP3 conversation and emit session-structure events."""
    events: list[RawEvent] = []
    starttls = StarttlsTracker()
    warnings: list[str] = []
    greeting_seen = False
    graceful_logout = False
    multiline_pending = False
    in_multiline = False
    awaiting_stls_response = False
    tls_after = False

    for line in lines:
        if tls_after:
            continue  # encrypted stream: not parseable as POP3
        command, _arguments = command_and_args(line.text)

        if line.direction is _C2S:
            if in_multiline or multiline_pending:
                continue  # client is silent during server multi-line data
            if command == "USER" or command == "PASS":
                events.append(
                    RawEvent(
                        EventType.AUTHENTICATION,
                        _C2S,
                        line.timestamp,
                        line.packet_numbers,
                        {"command": command, "argument": "redacted"},
                    )
                )
            elif command == "STLS":
                events.append(
                    RawEvent(
                        EventType.STARTTLS_REQUESTED, _C2S, line.timestamp, line.packet_numbers, {}
                    )
                )
                starttls.note_request(line)
                awaiting_stls_response = True
            elif command == "CAPA":
                events.append(
                    RawEvent(
                        EventType.CLIENT_COMMAND,
                        _C2S,
                        line.timestamp,
                        line.packet_numbers,
                        {"command": "CAPA"},
                    )
                )
                multiline_pending = True
            elif command in _MULTILINE_COMMANDS:
                events.append(
                    RawEvent(
                        EventType.CLIENT_COMMAND,
                        _C2S,
                        line.timestamp,
                        line.packet_numbers,
                        {"command": command},
                    )
                )
                multiline_pending = True
            else:
                events.append(
                    RawEvent(
                        EventType.CLIENT_COMMAND,
                        _C2S,
                        line.timestamp,
                        line.packet_numbers,
                        {"command": safe_value(command, 32)},
                    )
                )
                if command == "QUIT":
                    graceful_logout = True
            continue

        # Server direction -------------------------------------------------
        if awaiting_stls_response:
            awaiting_stls_response = False
            if line.text.startswith("+OK"):
                events.append(
                    RawEvent(
                        EventType.STARTTLS_RESPONSE, _S2C, line.timestamp, line.packet_numbers, {}
                    )
                )
                events.append(
                    RawEvent(
                        EventType.TLS_TRANSITION,
                        _S2C,
                        line.timestamp,
                        line.packet_numbers,
                        {"phase": "encrypted stream expected"},
                    )
                )
                starttls.note_accept(line)
                tls_after = True
                warnings.append(
                    "plaintext parsing stopped after STLS; the remainder of the "
                    "stream is encrypted and was not interpreted"
                )
            else:
                events.append(
                    RawEvent(
                        EventType.SERVER_RESPONSE,
                        _S2C,
                        line.timestamp,
                        line.packet_numbers,
                        {"status": "ERR"},
                    )
                )
            continue
        if in_multiline:
            # message/list/capability data content is never stored
            if line.text == ".":
                in_multiline = False
            elif line.text.upper() == "STLS" and not starttls.advertised:
                events.append(
                    RawEvent(
                        EventType.STARTTLS_ADVERTISED,
                        _S2C,
                        line.timestamp,
                        line.packet_numbers,
                        {"capability": "STLS"},
                    )
                )
                starttls.advertised = True
            continue
        if multiline_pending:
            if line.text.startswith("+OK"):
                events.append(
                    RawEvent(
                        EventType.SERVER_RESPONSE,
                        _S2C,
                        line.timestamp,
                        line.packet_numbers,
                        {"status": "OK"},
                    )
                )
                in_multiline = True
                continue
            multiline_pending = False  # server rejected: handle as a normal response
        if not greeting_seen:
            greeting_seen = True
            events.append(
                RawEvent(
                    EventType.SERVER_GREETING,
                    _S2C,
                    line.timestamp,
                    line.packet_numbers,
                    {"greeting": safe_value(line.text, 255)},
                )
            )
            continue
        status = "OK" if line.text.startswith("+OK") else "ERR"
        events.append(
            RawEvent(
                EventType.SERVER_RESPONSE,
                _S2C,
                line.timestamp,
                line.packet_numbers,
                {"status": status},
            )
        )
        continue

    return ReconstructedConversation(
        events=events, starttls=starttls, warnings=warnings, saw_graceful_logout=graceful_logout
    )
