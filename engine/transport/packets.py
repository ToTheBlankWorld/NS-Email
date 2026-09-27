"""Normalized packet records and packet sources.

``PacketSource`` is the abstraction boundary between capture bytes and the
analysis pipeline: implementations read evidence files and yield
``PacketRecord`` stream entries. The pure-Python ``PcapPacketSource``
reads pcap/pcapng containers directly (Ethernet or raw-IP link layer,
IPv4, TCP) so the pipeline runs on real evidence without external tools;
tool-backed sources (tshark, Scapy) can be added behind the same
protocol.

Non-TCP and unparseable packets are counted, never fabricated: the stats
travelling with the source make coverage explicit.
"""

import struct
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Final, Protocol

from engine.ingestion.errors import CaptureIngestionError

# TCP flag bits (low byte of the TCP header flags field).
TCP_FIN: Final[int] = 0x01
TCP_SYN: Final[int] = 0x02
TCP_RST: Final[int] = 0x04
TCP_PSH: Final[int] = 0x08
TCP_ACK: Final[int] = 0x10

# Guard against corrupt length fields claiming absurd allocations.
MAX_PLAUSIBLE_PACKET_BYTES: Final[int] = 262_144

_ETHERTYPE_IPV4: Final[int] = 0x0800
_ETHERTYPE_VLAN: Final[int] = 0x8100
_IPPROTO_TCP: Final[int] = 6

_LINKTYPE_ETHERNET: Final[int] = 1
_LINKTYPE_RAW_IP: Final[int] = 101

_PCAP_MAGICS: Final[dict[bytes, tuple[str, float]]] = {
    b"\xd4\xc3\xb2\xa1": ("<", 1e6),  # little-endian, microseconds
    b"\xa1\xb2\xc3\xd4": (">", 1e6),  # big-endian, microseconds
    b"\x4d\x3c\xb2\xa1": ("<", 1e9),  # little-endian, nanoseconds
    b"\xa1\xb2\x3c\x4d": (">", 1e9),  # big-endian, nanoseconds
}

_PCAPNG_SHB: Final[int] = 0x0A0D0D0A
_PCAPNG_IDB: Final[int] = 0x00000001
_PCAPNG_EPB: Final[int] = 0x00000006
_PCAPNG_LITTLE_ENDIAN_BOM: Final[bytes] = b"\x4d\x3c\x2b\x1a"
_PCAPNG_BIG_ENDIAN_BOM: Final[bytes] = b"\x1a\x2b\x3c\x4d"

_TCP_FLAG_NAMES: Final[dict[int, str]] = {
    TCP_FIN: "FIN",
    TCP_SYN: "SYN",
    TCP_RST: "RST",
    TCP_PSH: "PSH",
    TCP_ACK: "ACK",
}


class TransportProtocol(StrEnum):
    """Transport-layer protocol of a packet record."""

    TCP = "tcp"
    OTHER = "other"


class PacketSourceError(CaptureIngestionError):
    """The evidence bytes could not be read as packets."""


def describe_tcp_flags(flags: int) -> str:
    """Human-readable flag set, e.g. ``SYN+ACK`` (diagnostics only)."""
    names = [name for bit, name in _TCP_FLAG_NAMES.items() if flags & bit]
    return "+".join(names) if names else "none"


@dataclass(frozen=True, slots=True)
class PacketRecord:
    """Normalized internal representation of one observed packet.

    Payload bytes are transient: they exist for stream reassembly and
    protocol detection and are never persisted on evidence models.
    """

    number: int
    timestamp: float  # epoch seconds, packet capture resolution
    captured_len: int
    original_len: int
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    transport: TransportProtocol = TransportProtocol.TCP
    tcp_flags: int = 0
    tcp_seq: int = 0
    tcp_ack: int = 0
    payload: bytes = b""

    @property
    def payload_len(self) -> int:
        return len(self.payload)

    @property
    def has_syn(self) -> bool:
        return bool(self.tcp_flags & TCP_SYN)

    @property
    def has_fin(self) -> bool:
        return bool(self.tcp_flags & TCP_FIN)

    @property
    def has_rst(self) -> bool:
        return bool(self.tcp_flags & TCP_RST)


@dataclass(slots=True)
class PacketSourceStats:
    """Honest coverage report for one packet source run."""

    parsed: int = 0
    skipped: dict[str, int] = field(default_factory=dict)

    def skip(self, reason: str) -> None:
        self.skipped[reason] = self.skipped.get(reason, 0) + 1

    def skip_reasons(self) -> list[str]:
        return [
            f"{count} packet(s) skipped: {reason}" for reason, count in sorted(self.skipped.items())
        ]


class PacketSource(Protocol):
    """Anything that can turn capture evidence into normalized packets."""

    def packets(self) -> Iterator[PacketRecord]:
        """Yield TCP packet records in capture order."""
        ...

    def stats(self) -> PacketSourceStats:
        """Coverage report (valid after iteration completes)."""
        ...


class PcapPacketSource:
    """Read packets from a pcap/pcapng evidence file without external tools.

    Supports Ethernet (linktype 1) and raw IP (linktype 101) link layers
    with IPv4/TCP payloads. Anything else is counted as skipped and
    reported through ``stats()`` — never silently dropped and never
    guessed. A container whose link layer cannot be interpreted at all
    raises ``PacketSourceError``.
    """

    def __init__(self, evidence_path: Path) -> None:
        self._path = evidence_path
        self._stats = PacketSourceStats()

    def stats(self) -> PacketSourceStats:
        return self._stats

    def packets(self) -> Iterator[PacketRecord]:
        data = self._path.read_bytes()
        if data[:4] in _PCAP_MAGICS:
            yield from self._iter_pcap(data)
        elif data[:4] == struct.pack("<I", _PCAPNG_SHB):
            yield from self._iter_pcapng(data)
        else:
            raise PacketSourceError("evidence is not a readable pcap/pcapng container")

    # -- classic pcap -----------------------------------------------------

    def _iter_pcap(self, data: bytes) -> Iterator[PacketRecord]:
        endian, scale = _PCAP_MAGICS[data[:4]]
        if len(data) < 24:
            raise PacketSourceError("pcap global header is truncated")
        _vmaj, _vmin, _tz, _sig, _snap, linktype = struct.unpack_from(f"{endian}HHiIII", data, 4)
        parser = self._link_parser(linktype)
        number = 0
        offset = 24
        while offset + 16 <= len(data):
            ts_sec, ts_frac, incl_len, _orig_len = struct.unpack_from(f"{endian}IIII", data, offset)
            offset += 16
            if incl_len > MAX_PLAUSIBLE_PACKET_BYTES:
                raise PacketSourceError(
                    f"implausible packet length {incl_len} at record {number + 1}"
                )
            frame = data[offset : offset + incl_len]
            offset += incl_len
            if len(frame) < incl_len:
                self._stats.skip("truncated packet record")
                continue
            number += 1
            parsed = parser(frame, number, ts_sec + ts_frac / scale)
            if parsed is not None:
                self._stats.parsed += 1
                yield parsed

    # -- pcapng -----------------------------------------------------------

    def _iter_pcapng(self, data: bytes) -> Iterator[PacketRecord]:
        if len(data) < 28:
            raise PacketSourceError("pcapng section header block is truncated")
        bom = data[8:12]
        if bom == _PCAPNG_LITTLE_ENDIAN_BOM:
            endian = "<"
        elif bom == _PCAPNG_BIG_ENDIAN_BOM:
            endian = ">"
        else:
            raise PacketSourceError("pcapng section header has an unknown byte order")
        # if_tsresol options are not interpreted; the default microsecond
        # resolution is used and recorded honestly when timestamps matter.
        scale = 1e6
        linktypes: dict[int, int] = {}
        number = 0
        offset = 0
        while offset + 8 <= len(data):
            block_type, block_len = struct.unpack_from(f"{endian}II", data, offset)
            if block_len < 12 or offset + block_len > len(data):
                raise PacketSourceError(f"corrupt pcapng block length at offset {offset}")
            body = data[offset + 8 : offset + block_len - 4]
            if block_type == _PCAPNG_SHB:
                pass  # byte order already established from the first section
            elif block_type == _PCAPNG_IDB and len(body) >= 8:
                linktype = struct.unpack_from(f"{endian}H", body, 0)[0]
                linktypes.setdefault(len(linktypes), linktype)
            elif block_type == _PCAPNG_EPB and len(body) >= 20:
                iface, ts_high, ts_low, incl_len, _orig_len = struct.unpack_from(
                    f"{endian}IIIII", body, 0
                )
                if incl_len > MAX_PLAUSIBLE_PACKET_BYTES:
                    raise PacketSourceError(
                        f"implausible packet length {incl_len} at packet {number + 1}"
                    )
                frame = body[20 : 20 + incl_len]
                if len(frame) < incl_len:
                    self._stats.skip("truncated packet block")
                else:
                    linktype = linktypes.get(iface)
                    parser = self._link_parser(linktype) if linktype is not None else None
                    number += 1
                    timestamp = ((ts_high << 32) | ts_low) / scale
                    if parser is None:
                        self._stats.skip("unknown interface link type")
                    else:
                        parsed = parser(frame, number, timestamp)
                        if parsed is not None:
                            self._stats.parsed += 1
                            yield parsed
            else:
                self._stats.skip("unsupported pcapng block type")
            offset += block_len

    # -- link/network/transport parsing -----------------------------------

    def _link_parser(
        self, linktype: int | None
    ) -> Callable[[bytes, int, float], PacketRecord | None]:
        if linktype == _LINKTYPE_ETHERNET:
            return self._parse_ethernet
        if linktype == _LINKTYPE_RAW_IP:
            return self._parse_ipv4
        raise PacketSourceError(
            f"unsupported link-layer type {linktype}: packet parsing requires "
            "Ethernet (1) or raw IP (101) captures"
        )

    def _parse_ethernet(self, frame: bytes, number: int, timestamp: float) -> PacketRecord | None:
        if len(frame) < 14:
            self._stats.skip("truncated ethernet frame")
            return None
        ethertype = struct.unpack_from(">H", frame, 12)[0]
        if ethertype == _ETHERTYPE_VLAN:
            self._stats.skip("vlan-tagged frame")
            return None
        if ethertype != _ETHERTYPE_IPV4:
            self._stats.skip("non-ipv4 ethernet frame")
            return None
        return self._parse_ipv4(frame[14:], number, timestamp)

    def _parse_ipv4(self, datagram: bytes, number: int, timestamp: float) -> PacketRecord | None:
        if len(datagram) < 20:
            self._stats.skip("truncated ipv4 header")
            return None
        version_ihl = datagram[0]
        if version_ihl >> 4 != 4:
            self._stats.skip("non-ipv4 packet")
            return None
        header_len = (version_ihl & 0x0F) * 4
        if header_len < 20 or len(datagram) < header_len:
            self._stats.skip("truncated ipv4 header")
            return None
        total_len = struct.unpack_from(">H", datagram, 2)[0]
        flags_fragment = struct.unpack_from(">H", datagram, 6)[0]
        if flags_fragment & 0x1FFF:  # non-first fragment: payload incomplete
            self._stats.skip("ip fragment")
            return None
        if flags_fragment & 0x2000:  # more fragments follow
            self._stats.skip("fragmented ip datagram")
            return None
        protocol = datagram[9]
        if protocol != _IPPROTO_TCP:
            self._stats.skip("non-tcp packet")
            return None
        src_ip = ".".join(str(octet) for octet in datagram[12:16])
        dst_ip = ".".join(str(octet) for octet in datagram[16:20])
        return self._parse_tcp(
            datagram[header_len:], number, timestamp, total_len - header_len, src_ip, dst_ip
        )

    def _parse_tcp(
        self,
        segment: bytes,
        number: int,
        timestamp: float,
        ip_payload_len: int,
        src_ip: str,
        dst_ip: str,
    ) -> PacketRecord | None:
        if len(segment) < 20:
            self._stats.skip("truncated tcp header")
            return None
        src_port, dst_port, seq, ack = struct.unpack_from(">HHII", segment, 0)
        data_offset = (segment[12] >> 4) * 4
        flags = segment[13]
        if data_offset < 20 or len(segment) < data_offset:
            self._stats.skip("truncated tcp header")
            return None
        tcp_payload_len = max(0, ip_payload_len - data_offset)
        payload = segment[data_offset : data_offset + tcp_payload_len]
        return PacketRecord(
            number=number,
            timestamp=timestamp,
            captured_len=len(payload),
            original_len=tcp_payload_len,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            transport=TransportProtocol.TCP,
            tcp_flags=flags,
            tcp_seq=seq,
            tcp_ack=ack,
            payload=payload,
        )
