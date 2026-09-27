"""TCP flow identification and deterministic session identity.

A flow is one bidirectional TCP connection keyed by the canonical 5-tuple
(source IP, source port, destination IP, destination port, transport) with
both endpoints sorted, so client→server and server→client packets group
into a single logical flow. Session ids are derived deterministically from
the capture id and the canonical flow tuple — no random ids, no user input.
"""

import hashlib
import struct
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Final

from engine.transport.packets import PacketRecord

_FLOW_HEX_LENGTH: Final[int] = 16


def _endpoint_key(ip: str, port: int) -> tuple[str, str, int]:
    # Numeric ordering: parse IPv4 octets so 10.0.0.9 sorts before 10.0.0.10.
    try:
        packed = struct.pack(">4s", bytes(int(part) for part in ip.split(".")))
        return (packed.decode("latin-1"), ip, port)
    except (ValueError, struct.error):
        return (ip, ip, port)


@dataclass(frozen=True, slots=True)
class FlowKey:
    """Canonical bidirectional flow identity."""

    endpoint_a: tuple[str, int]
    endpoint_b: tuple[str, int]

    @classmethod
    def from_packet(cls, packet: PacketRecord) -> "FlowKey":
        endpoints = sorted(
            [(packet.src_ip, packet.src_port), (packet.dst_ip, packet.dst_port)],
            key=lambda ep: _endpoint_key(*ep),
        )
        return cls(
            endpoint_a=(endpoints[0][0], endpoints[0][1]),
            endpoint_b=(endpoints[1][0], endpoints[1][1]),
        )

    def canonical(self) -> str:
        a, b = self.endpoint_a, self.endpoint_b
        return f"tcp|{a[0]}|{a[1]}|{b[0]}|{b[1]}"


def derive_session_id(capture_id: str, key: FlowKey) -> str:
    """Deterministic, filesystem-safe session id from capture and flow."""
    digest = hashlib.sha256(f"{capture_id}|{key.canonical()}".encode()).hexdigest()
    return f"session_{digest[:_FLOW_HEX_LENGTH]}"


@dataclass(slots=True)
class Direction:
    """One direction of a flow (endpoint + packets in capture order)."""

    ip: str
    port: int
    packets: list[PacketRecord] = field(default_factory=list)


@dataclass(slots=True)
class Flow:
    """A bidirectional TCP flow assembled from normalized packets."""

    capture_id: str
    key: FlowKey
    id: str
    direction_a: Direction  # packets sent from endpoint_a
    direction_b: Direction  # packets sent from endpoint_b

    @property
    def packet_count(self) -> int:
        return len(self.direction_a.packets) + len(self.direction_b.packets)

    @property
    def first_packet(self) -> PacketRecord | None:
        packets = sorted(
            [*self.direction_a.packets, *self.direction_b.packets],
            key=lambda p: (p.timestamp, p.number),
        )
        return packets[0] if packets else None

    @property
    def last_packet(self) -> PacketRecord | None:
        packets = sorted(
            [*self.direction_a.packets, *self.direction_b.packets],
            key=lambda p: (p.timestamp, p.number),
        )
        return packets[-1] if packets else None


class FlowBuilder:
    """Groups normalized packets into bidirectional flows."""

    def __init__(self, capture_id: str) -> None:
        self._capture_id = capture_id
        self._flows: dict[FlowKey, tuple[Direction, Direction]] = {}

    def add(self, packet: PacketRecord) -> None:
        key = FlowKey.from_packet(packet)
        direction_a, direction_b = self._flows.setdefault(
            key,
            (
                Direction(key.endpoint_a[0], key.endpoint_a[1]),
                Direction(key.endpoint_b[0], key.endpoint_b[1]),
            ),
        )
        if (packet.src_ip, packet.src_port) == key.endpoint_a:
            direction_a.packets.append(packet)
        else:
            direction_b.packets.append(packet)

    def flows(self) -> list[Flow]:
        """Return flows ordered by their first observed packet."""
        result = [
            Flow(
                capture_id=self._capture_id,
                key=key,
                id=derive_session_id(self._capture_id, key),
                direction_a=pair[0],
                direction_b=pair[1],
            )
            for key, pair in self._flows.items()
        ]
        result.sort(key=_flow_first_timestamp)
        return result


def build_flows(capture_id: str, packets: Iterable[PacketRecord]) -> list[Flow]:
    """Convenience pipeline: group packets into flows."""
    builder = FlowBuilder(capture_id)
    for packet in packets:
        builder.add(packet)
    return builder.flows()


def _flow_first_timestamp(flow: Flow) -> tuple[float, int]:
    first = flow.first_packet
    if first is None:  # pragma: no cover - flows are never empty
        return (float("inf"), 1 << 30)
    return (first.timestamp, first.number)
