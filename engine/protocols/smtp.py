"""SMTP session reconstruction: commands, responses, and STARTTLS.

Reconstructs session structure only — message body content is skipped and
never stored. AUTH arguments are redacted; envelope addresses (MAIL FROM /
RCPT TO) are forensic metadata and are kept, sanitized and length-bounded.
"""

import re
from typing import Final

from engine.core.events import EventDirection, EventType, safe_value
from engine.protocols.base import (
    ConversationLine,
    RawEvent,
    ReconstructedConversation,
    StarttlsTracker,
)
from engine.protocols.redaction import command_and_args

_TAG: Final[re.Pattern[str]] = re.compile(r"^\d{3}[ -]")

_C2S: Final[EventDirection] = EventDirection.CLIENT_TO_SERVER
_S2C: Final[EventDirection] = EventDirection.SERVER_TO_CLIENT


def build_smtp_conversation(lines: list[ConversationLine]) -> ReconstructedConversation:
    """Walk a merged SMTP conversation and emit session-structure events."""
    events: list[RawEvent] = []
    starttls = StarttlsTracker()
    warnings: list[str] = []
    in_data = False
    awaiting_delivery_confirmation = False
    awaiting_starttls_response = False
    tls_after = False
    greeting_seen = False
    graceful_logout = False

    for line in lines:
        if tls_after:
            continue  # encrypted stream: not parseable as SMTP
        command, arguments = command_and_args(line.text)

        if line.direction is _C2S:
            if in_data:
                if line.text == ".":
                    in_data = False
                    awaiting_delivery_confirmation = True
                continue  # message body is never stored
            if command == "STARTTLS":
                events.append(
                    RawEvent(
                        EventType.STARTTLS_REQUESTED, _C2S, line.timestamp, line.packet_numbers, {}
                    )
                )
                starttls.note_request(line)
                awaiting_starttls_response = True
            elif command == "AUTH":
                mechanism = safe_value(arguments.split(" ")[0] if arguments else "", 64)
                events.append(
                    RawEvent(
                        EventType.AUTHENTICATION,
                        _C2S,
                        line.timestamp,
                        line.packet_numbers,
                        {"mechanism": mechanism, "credential_data": "redacted"},
                    )
                )
            elif command == "MAIL":
                events.append(
                    RawEvent(
                        EventType.MAIL_TRANSACTION_START,
                        _C2S,
                        line.timestamp,
                        line.packet_numbers,
                        {"envelope": safe_value(arguments, 320)},
                    )
                )
            elif command == "RCPT":
                events.append(
                    RawEvent(
                        EventType.CLIENT_COMMAND,
                        _C2S,
                        line.timestamp,
                        line.packet_numbers,
                        {"command": "RCPT TO", "argument": safe_value(arguments, 320)},
                    )
                )
            elif command == "EHLO" or command == "HELO":
                events.append(
                    RawEvent(
                        EventType.CLIENT_COMMAND,
                        _C2S,
                        line.timestamp,
                        line.packet_numbers,
                        {"command": command, "argument": safe_value(arguments, 255)},
                    )
                )
            elif command == "QUIT":
                events.append(
                    RawEvent(
                        EventType.CLIENT_COMMAND,
                        _C2S,
                        line.timestamp,
                        line.packet_numbers,
                        {"command": "QUIT"},
                    )
                )
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
            continue

        # Server direction -------------------------------------------------
        code = line.text[:3]
        if awaiting_starttls_response:
            awaiting_starttls_response = False
            if code == "220":
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
                starttls.response_seen = True
                tls_after = True
                warnings.append(
                    "plaintext parsing stopped after STARTTLS; the remainder of the "
                    "stream is encrypted and was not interpreted"
                )
            else:
                events.append(
                    RawEvent(
                        EventType.SERVER_RESPONSE,
                        _S2C,
                        line.timestamp,
                        line.packet_numbers,
                        {"code": safe_value(code, 3)},
                    )
                )
            continue
        if in_data:
            continue  # unexpected server traffic inside DATA: ignored
        if not greeting_seen and code == "220":
            greeting_seen = True
            events.append(
                RawEvent(
                    EventType.SERVER_GREETING,
                    _S2C,
                    line.timestamp,
                    line.packet_numbers,
                    {"banner": safe_value(line.text, 255)},
                )
            )
            continue
        greeting_seen = True
        if awaiting_delivery_confirmation and code == "250":
            awaiting_delivery_confirmation = False
            events.append(
                RawEvent(
                    EventType.MAIL_TRANSACTION_COMPLETE,
                    _S2C,
                    line.timestamp,
                    line.packet_numbers,
                    {"code": "250"},
                )
            )
            continue
        if line.text.startswith("250-") and "STARTTLS" in line.text.upper():
            events.append(
                RawEvent(
                    EventType.STARTTLS_ADVERTISED,
                    _S2C,
                    line.timestamp,
                    line.packet_numbers,
                    {"capability": "STARTTLS"},
                )
            )
            starttls.advertised = True
            continue
        if _TAG.match(line.text):
            events.append(
                RawEvent(
                    EventType.SERVER_RESPONSE,
                    _S2C,
                    line.timestamp,
                    line.packet_numbers,
                    {"code": safe_value(code, 3)},
                )
            )
        if code == "354":
            in_data = True
        if code == "221":
            graceful_logout = True
        continue

    return ReconstructedConversation(
        events=events, starttls=starttls, warnings=warnings, saw_graceful_logout=graceful_logout
    )
