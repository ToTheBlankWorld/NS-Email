"""Shared conversation-line abstraction for protocol reconstruction.

Reconstructors work on ``ConversationLine`` objects: sanitized lines from
each reassembled direction, carrying their stream offset, the packets that
carried them (evidence), and the packet timestamp. Raw line text beyond a
sanitized, length-bounded form never enters events.
"""

import re
from dataclasses import dataclass, field
from typing import Final

from engine.core.events import EventDirection, EventType, safe_value
from engine.core.session import StarttlsObservation
from engine.transport.reassembly import StreamAssembly

_LINE_BREAK: Final[re.Pattern[bytes]] = re.compile(rb"\r?\n")
MAX_LINE_LENGTH: Final[int] = 512


@dataclass(frozen=True, slots=True)
class ConversationLine:
    """One sanitized application-layer line and its evidence."""

    direction: EventDirection
    offset: int
    text: str
    packet_numbers: list[int] = field(default_factory=list)
    timestamp: float = 0.0


@dataclass(frozen=True, slots=True)
class RawEvent:
    """Intermediate event before chronological numbering."""

    type: EventType
    direction: EventDirection
    timestamp: float | None
    packet_numbers: list[int]
    detail: dict[str, str]


@dataclass(slots=True)
class StarttlsTracker:
    """Mutable collection state for STARTTLS observation during parsing."""

    advertised: bool = False
    requested: bool = False
    response_seen: bool = False
    packet_number: int | None = None
    timestamp: float | None = None

    def note_request(self, line: "ConversationLine") -> None:
        self.requested = True
        if self.packet_number is None:
            self.packet_number = line.packet_numbers[0] if line.packet_numbers else None
            self.timestamp = line.timestamp

    def to_observation(self) -> StarttlsObservation:
        from datetime import UTC, datetime

        return StarttlsObservation(
            advertised=self.advertised,
            requested=self.requested,
            response_seen=self.response_seen,
            packet_number=self.packet_number,
            timestamp=(
                datetime.fromtimestamp(self.timestamp, tz=UTC)
                if self.timestamp is not None
                else None
            ),
        )


@dataclass(frozen=True, slots=True)
class ReconstructedConversation:
    """Protocol-level reconstruction output for one conversation."""

    events: list[RawEvent] = field(default_factory=list)
    starttls: StarttlsTracker = field(default_factory=StarttlsTracker)
    warnings: list[str] = field(default_factory=list)
    saw_graceful_logout: bool = False


def extract_lines(assembly: StreamAssembly, direction: EventDirection) -> list[ConversationLine]:
    """Split one reassembled direction into sanitized conversation lines."""
    data = assembly.stream()
    lines: list[ConversationLine] = []
    cursor = 0
    for match in _LINE_BREAK.finditer(data):
        raw = data[cursor : match.start()]
        lines.append(_make_line(raw, cursor, direction, assembly))
        cursor = match.end()
    if cursor < len(data):
        remainder = data[cursor:]
        # A trailing fragment without a line break is still conversation
        # data (e.g. truncated capture); keep it if it is printable-ish.
        lines.append(_make_line(remainder, cursor, direction, assembly))
    return lines


def _make_line(
    raw: bytes, offset: int, direction: EventDirection, assembly: StreamAssembly
) -> ConversationLine:
    text = safe_value(raw.decode("latin-1"), MAX_LINE_LENGTH)
    return ConversationLine(
        direction=direction,
        offset=offset,
        text=text,
        packet_numbers=assembly.packets_covering(offset, offset + max(1, len(raw))),
        timestamp=assembly.timestamp_at(offset),
    )


def merge_conversation(
    lines_a: list[ConversationLine], lines_b: list[ConversationLine]
) -> list[ConversationLine]:
    """Merge both directions into wire order (by packet number, then offset)."""
    merged = [*lines_a, *lines_b]
    merged.sort(
        key=lambda line: (min(line.packet_numbers) if line.packet_numbers else 1 << 30, line.offset)
    )
    return merged
