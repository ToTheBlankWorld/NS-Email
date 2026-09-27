"""Bidirectional TCP stream reassembly with honest gap accounting.

The assembler consumes TCP data segments for one direction of a flow and
produces a ``StreamAssembly``: the reconstructed byte sequence plus
explicit evidence about retransmissions, duplicates, gaps, and
termination. Missing data is never fabricated — ``complete`` is ``False``
with a reason whenever the stream is not fully and cleanly observed.

Sequence normalization uses 32-bit wraparound arithmetic. When the SYN is
observed, data starts at ISN+1; otherwise the base is the smallest
observed sequence number at assembly time (deterministic, no data loss).
Segments that fall below an ISN-anchored base (stale data from a previous
connection incarnation) cannot be placed and are reported as ignored.
"""

from bisect import bisect_right
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Final

from engine.transport.packets import PacketRecord

_WRAP: Final = 1 << 32
_HALF: Final = 1 << 31


@dataclass(frozen=True, slots=True)
class Segment:
    """One TCP data segment offered to the assembler."""

    seq: int
    payload: bytes
    packet_number: int
    timestamp: float


@dataclass(frozen=True, slots=True)
class StreamAssembly:
    """Reconstruction result for one direction of a TCP stream."""

    bytes_reconstructed: int
    segment_count: int
    retransmitted_segments: int
    duplicate_segments: int
    ignored_segments: int
    gap_count: int
    gap_bytes: int
    complete: bool
    completeness_reason: str | None
    fin_seen: bool
    rst_seen: bool
    _ranges: tuple[tuple[int, int, int, float, bytes], ...]

    def stream(self) -> bytes:
        """The reconstructed byte sequence (data only, in sequence order)."""
        return b"".join(data for _, _, _, _, data in self._ranges)

    def locator(self, offset: int) -> tuple[int, float]:
        """Map a stream byte offset to (packet number, timestamp)."""
        index = bisect_right(self._ranges, offset, key=lambda r: r[0]) - 1
        if index >= 0:
            start, end, packet_number, timestamp, _ = self._ranges[index]
            if start <= offset < end:
                return (packet_number, timestamp)
            return (packet_number, timestamp)
        return (0, 0.0)

    def packets_covering(self, start: int, end: int) -> list[int]:
        """Packet numbers whose data covers the stream range [start, end)."""
        numbers: list[int] = []
        for range_start, range_end, packet_number, *_ in self._ranges:
            if range_end <= start:
                continue
            if range_start >= end:
                break
            numbers.append(packet_number)
        return numbers

    def timestamp_at(self, offset: int) -> float:
        """Timestamp of the packet covering the given stream offset."""
        return self.locator(offset)[1]


@dataclass
class _AssemblerState:
    isn: int | None = None
    fin_seen: bool = False
    rst_seen: bool = False


class StreamAssembler:
    """Reassembles one direction of a TCP flow (two-phase: collect, place)."""

    def __init__(self) -> None:
        self._state = _AssemblerState()
        self._segments: list[Segment] = []
        self._retransmitted = 0
        self._duplicates = 0
        self._ignored = 0

    def add_packet(self, packet: PacketRecord) -> None:
        """Feed one TCP packet (data or control) for this direction."""
        if packet.has_syn:
            self._state.isn = packet.tcp_seq
        if packet.has_fin:
            self._state.fin_seen = True
        if packet.has_rst:
            self._state.rst_seen = True
        if packet.payload:
            self._segments.append(
                Segment(
                    seq=packet.tcp_seq,
                    payload=packet.payload,
                    packet_number=packet.number,
                    timestamp=packet.timestamp,
                )
            )

    def assemble(self) -> StreamAssembly:
        """Place all collected segments and compute reconstruction evidence."""
        base = self._resolve_base()
        ranges: list[tuple[int, int, int, float, bytes]] = []
        retransmitted = 0
        duplicates = 0
        ignored = 0
        for segment in self._segments:
            start = (segment.seq - base) % _WRAP
            if start >= _HALF:
                ignored += 1  # precedes the ISN-anchored base: stale data
                continue
            end = start + len(segment.payload)
            overlap, touched = _overlap(ranges, start, end)
            if overlap == len(segment.payload):
                if touched == 1:
                    duplicates += 1
                else:
                    retransmitted += 1
            elif overlap > 0:
                retransmitted += 1
            _insert(ranges, start, end, segment.packet_number, segment.timestamp, segment.payload)
        return _build_assembly(
            ranges,
            segment_count=len(self._segments) - ignored,
            retransmitted=retransmitted,
            duplicates=duplicates,
            ignored=ignored,
            fin_seen=self._state.fin_seen,
            rst_seen=self._state.rst_seen,
        )

    def _resolve_base(self) -> int:
        if self._state.isn is not None:
            return (self._state.isn + 1) % _WRAP
        if not self._segments:
            return 0
        return min(segment.seq for segment in self._segments)


def _overlap(
    ranges: list[tuple[int, int, int, float, bytes]], start: int, end: int
) -> tuple[int, int]:
    total = 0
    touched = 0
    for existing_start, existing_end, *_ in ranges:
        if existing_end <= start:
            continue
        if existing_start >= end:
            break
        total += min(existing_end, end) - max(existing_start, start)
        touched += 1
    return total, touched


def _insert(
    ranges: list[tuple[int, int, int, float, bytes]],
    start: int,
    end: int,
    packet_number: int,
    timestamp: float,
    payload: bytes,
) -> None:
    """Insert new data, splitting around existing ranges (kept as-is)."""
    pieces: list[tuple[int, int, int, float, bytes]] = []
    cursor = start
    for existing_start, existing_end, *_ in ranges:
        if existing_end <= cursor:
            continue
        if existing_start >= end:
            break
        if existing_start > cursor:
            pieces.append(
                (
                    cursor,
                    existing_start,
                    packet_number,
                    timestamp,
                    payload[cursor - start : existing_start - start],
                )
            )
        cursor = max(cursor, existing_end)
        if cursor >= end:
            break
    if cursor < end:
        pieces.append(
            (cursor, end, packet_number, timestamp, payload[cursor - start : end - start])
        )
    if pieces:
        ranges.extend(pieces)
        ranges.sort(key=lambda r: r[0])


def _build_assembly(
    ranges: list[tuple[int, int, int, float, bytes]],
    *,
    segment_count: int,
    retransmitted: int,
    duplicates: int,
    ignored: int,
    fin_seen: bool,
    rst_seen: bool,
) -> StreamAssembly:
    gap_count = 0
    gap_bytes = 0
    previous_end: int | None = None
    for existing_start, existing_end, *_ in ranges:
        if previous_end is not None and existing_start > previous_end:
            gap_count += 1
            gap_bytes += existing_start - previous_end
        previous_end = existing_end if previous_end is None else max(previous_end, existing_end)
    bytes_reconstructed = sum(end - start for start, end, *_ in ranges)
    complete = gap_count == 0 and (fin_seen or rst_seen)
    reason: str | None = None
    if not complete:
        reasons = []
        if gap_count:
            reasons.append(f"{gap_count} gap(s) covering {gap_bytes} byte(s)")
        if not (fin_seen or rst_seen):
            reasons.append("no FIN or RST observed (no graceful termination)")
        reason = "; ".join(reasons)
    return StreamAssembly(
        bytes_reconstructed=bytes_reconstructed,
        segment_count=segment_count,
        retransmitted_segments=retransmitted,
        duplicate_segments=duplicates,
        ignored_segments=ignored,
        gap_count=gap_count,
        gap_bytes=gap_bytes,
        complete=complete,
        completeness_reason=reason,
        fin_seen=fin_seen,
        rst_seen=rst_seen,
        _ranges=tuple(ranges),
    )


def assemble_direction(packets: Iterable[PacketRecord]) -> StreamAssembly:
    """Convenience: reassemble one direction from its packets (capture order)."""
    assembler = StreamAssembler()
    for packet in sorted(packets, key=lambda p: (p.timestamp, p.number)):
        assembler.add_packet(packet)
    return assembler.assemble()
