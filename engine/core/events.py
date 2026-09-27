"""Session event evidence: the timeline of a reconstructed email session.

Events are derived from reassembled stream bytes and always carry the
packet numbers they were observed in. Sensitive values (credentials,
authentication arguments) are redacted at construction time — raw lines
are never stored on events.
"""

import re
from enum import StrEnum
from typing import Final

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field


class EventType(StrEnum):
    """Timeline event types emitted by session reconstruction."""

    CONNECTION_ESTABLISHED = "connection_established"
    CONNECTION_CLOSED = "connection_closed"
    SERVER_GREETING = "server_greeting"
    CLIENT_COMMAND = "client_command"
    SERVER_RESPONSE = "server_response"
    STARTTLS_ADVERTISED = "starttls_advertised"
    STARTTLS_REQUESTED = "starttls_requested"
    STARTTLS_RESPONSE = "starttls_response"
    TLS_TRANSITION = "tls_transition"
    AUTHENTICATION = "authentication"
    MAIL_TRANSACTION_START = "mail_transaction_start"
    MAIL_TRANSACTION_COMPLETE = "mail_transaction_complete"


class EventDirection(StrEnum):
    """Direction of the traffic an event was observed in."""

    CLIENT_TO_SERVER = "client_to_server"
    SERVER_TO_CLIENT = "server_to_client"
    UNKNOWN = "unknown"


# Control characters that must never appear in stored detail values.
_CONTROL_CHARS: Final[re.Pattern[str]] = re.compile(r"[\x00-\x1f\x7f]")

MAX_DETAIL_VALUE_LENGTH: Final[int] = 512
REDACTED: Final[str] = "redacted"


def safe_value(value: str, max_length: int = MAX_DETAIL_VALUE_LENGTH) -> str:
    """Sanitize a value for storage in event detail.

    Strips control characters and enforces a length bound so packet bytes
    can never be replayed verbatim into evidence or API responses.
    """
    cleaned = _CONTROL_CHARS.sub("", value)
    return cleaned[:max_length]


class SessionEvent(BaseModel):
    """One forensic event on a session timeline.

    ``detail`` contains only sanitized, non-sensitive structured fields;
    credential material is replaced with the literal ``redacted``.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    seq: int = Field(ge=0)
    type: EventType
    direction: EventDirection = EventDirection.UNKNOWN
    timestamp: AwareDatetime | None = None
    packet_numbers: list[int] = Field(default_factory=list)
    detail: dict[str, str] = Field(default_factory=dict)
