"""IMAP session reconstruction with tag preservation.

IMAP client commands carry tags (``A001 CAPABILITY``); the original tag is
preserved where safely parsed. LOGIN/AUTHENTICATE arguments are credentials
and are always redacted — only the command shape is recorded.
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
from engine.protocols.redaction import redact_arguments

_C2S: Final[EventDirection] = EventDirection.CLIENT_TO_SERVER
_S2C: Final[EventDirection] = EventDirection.SERVER_TO_CLIENT

_CLIENT_LINE: Final[re.Pattern[str]] = re.compile(
    r"^(?P<tag>\S{1,32})\s+(?P<command>\S{1,32})(?:\s+(?P<args>.*))?$"
)
_SERVER_LINE: Final[re.Pattern[str]] = re.compile(
    r"^(?P<tag>\S{1,32})\s+(?P<status>OK|NO|BAD)\b(?P<text>.*)$", re.IGNORECASE
)


def build_imap_conversation(lines: list[ConversationLine]) -> ReconstructedConversation:
    """Walk a merged IMAP conversation and emit session-structure events."""
    events: list[RawEvent] = []
    starttls = StarttlsTracker()
    warnings: list[str] = []
    greeting_seen = False
    graceful_logout = False
    pending_starttls_tag: str | None = None
    tls_after = False

    for line in lines:
        if tls_after:
            continue  # encrypted stream: not parseable as IMAP
        if line.direction is _C2S:
            match = _CLIENT_LINE.match(line.text)
            if match is None:
                continue  # binary or unparseable client traffic
            tag = match.group("tag")
            command = match.group("command").upper()
            arguments = match.group("args") or ""
            if command == "STARTTLS":
                events.append(
                    RawEvent(
                        EventType.STARTTLS_REQUESTED,
                        _C2S,
                        line.timestamp,
                        line.packet_numbers,
                        {"tag": safe_value(tag, 32)},
                    )
                )
                starttls.note_request(line)
                pending_starttls_tag = tag
            elif command in ("LOGIN", "AUTHENTICATE"):
                events.append(
                    RawEvent(
                        EventType.AUTHENTICATION,
                        _C2S,
                        line.timestamp,
                        line.packet_numbers,
                        {
                            "tag": safe_value(tag, 32),
                            "command": command,
                            "credential_data": "redacted" if arguments else "",
                        },
                    )
                )
            else:
                events.append(
                    RawEvent(
                        EventType.CLIENT_COMMAND,
                        _C2S,
                        line.timestamp,
                        line.packet_numbers,
                        {
                            "tag": safe_value(tag, 32),
                            "command": command,
                            "argument": redact_arguments(command, arguments),
                        },
                    )
                )
                if command == "LOGOUT":
                    graceful_logout = True
            continue

        # Server direction -------------------------------------------------
        if not greeting_seen:
            greeting_seen = True
            if line.text.startswith("*"):
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
        if line.text.startswith("* CAPABILITY") and "STARTTLS" in line.text.upper():
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
        response = _SERVER_LINE.match(line.text)
        if response is not None:
            tag = response.group("tag")
            status = response.group("status").upper()
            if pending_starttls_tag is not None and tag == pending_starttls_tag and status == "OK":
                events.append(
                    RawEvent(
                        EventType.STARTTLS_RESPONSE,
                        _S2C,
                        line.timestamp,
                        line.packet_numbers,
                        {"tag": safe_value(tag, 32)},
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
                pending_starttls_tag = None
                tls_after = True
                warnings.append(
                    "plaintext parsing stopped after STARTTLS; the remainder of the "
                    "stream is encrypted and was not interpreted"
                )
                continue
            events.append(
                RawEvent(
                    EventType.SERVER_RESPONSE,
                    _S2C,
                    line.timestamp,
                    line.packet_numbers,
                    {"tag": safe_value(tag, 32), "status": status},
                )
            )
        continue

    return ReconstructedConversation(
        events=events, starttls=starttls, warnings=warnings, saw_graceful_logout=graceful_logout
    )
