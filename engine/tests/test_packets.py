"""Tests for the pure-Python pcap/pcapng packet source."""

import struct

import pytest
from engine.transport.packets import TCP_ACK, TCP_PSH, TCP_SYN, PacketSourceError, PcapPacketSource

CLIENT = "10.10.0.23"
SERVER = "198.51.100.7"


def eth_ipv4_tcp_frame(
    payload: bytes = b"",
    *,
    src: str = CLIENT,
    dst: str = SERVER,
    sport: int = 49152,
    dport: int = 587,
    seq: int = 1000,
    flags: int = TCP_ACK | TCP_PSH,
    proto: int = 6,
) -> bytes:
    def ip_bytes(ip: str) -> bytes:
        return bytes(int(octet) for octet in ip.split("."))

    macs = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb"
    tcp_header = struct.pack(">HHIIBBHHH", sport, dport, seq, 0, 5 << 4, flags, 8192, 0, 0)
    total_len = 20 + len(tcp_header) + len(payload)
    ip_header = (
        struct.pack(">BBHHHBBH", 0x45, 0, total_len, 0, 0, 64, proto, 0)
        + ip_bytes(src)
        + ip_bytes(dst)
    )
    return macs + struct.pack(">H", 0x0800) + ip_header + tcp_header + payload


def pcap_bytes(frames: list[bytes], linktype: int = 1) -> bytes:
    out = struct.pack("<I", 0xA1B2C3D4) + struct.pack("<HHiIII", 2, 4, 0, 0, 65535, linktype)
    for index, frame in enumerate(frames):
        out += struct.pack("<IIII", 1727430000 + index, 0, len(frame), len(frame))
        out += frame
    return out


def pcapng_bytes(frames: list[bytes], linktype: int = 1) -> bytes:
    blocks = (
        struct.pack("<I", 0x0A0D0D0A)
        + struct.pack("<I", 28)
        + b"\x4d\x3c\x2b\x1a"
        + struct.pack("<HHq", 1, 0, -1)
        + struct.pack("<I", 28)
        + struct.pack("<II", 0x00000001, 20)
        + struct.pack("<HHI", linktype, 0, 65535)
        + struct.pack("<I", 20)
    )
    for index, frame in enumerate(frames):
        padded = frame + b"\x00" * ((4 - len(frame) % 4) % 4)
        ts_us = (1727430000 + index) * 1_000_000
        total = 32 + len(padded)
        blocks += (
            struct.pack(
                "<IIIIIII",
                0x00000006,
                total,
                0,
                ts_us >> 32,
                ts_us & 0xFFFFFFFF,
                len(frame),
                len(frame),
            )
            + padded
            + struct.pack("<I", total)
        )
    return blocks


def write(tmp_path, name: str, data: bytes):
    path = tmp_path / name
    path.write_bytes(data)
    return path


def test_parses_tcp_records_with_normalized_fields(tmp_path) -> None:
    frame = eth_ipv4_tcp_frame(b"EHLO test\r\n")
    source = PcapPacketSource(write(tmp_path, "e.pcap", pcap_bytes([frame])))

    packets = list(source.packets())

    assert len(packets) == 1
    packet = packets[0]
    assert packet.number == 1
    assert packet.src_ip == CLIENT and packet.dst_ip == SERVER
    assert packet.src_port == 49152 and packet.dst_port == 587
    assert packet.tcp_flags == TCP_ACK | TCP_PSH
    assert packet.tcp_seq == 1000
    assert packet.payload == b"EHLO test\r\n"
    assert packet.timestamp == 1727430000.0
    assert source.stats().parsed == 1


def test_pcapng_container_is_supported(tmp_path) -> None:
    frame = eth_ipv4_tcp_frame(b"DATA\r\n", seq=500)
    source = PcapPacketSource(write(tmp_path, "e.pcapng", pcapng_bytes([frame])))

    packets = list(source.packets())

    assert len(packets) == 1
    assert packets[0].payload == b"DATA\r\n"


def test_non_tcp_packets_are_counted_as_skipped(tmp_path) -> None:
    udp_frame = eth_ipv4_tcp_frame(b"x", proto=17)
    syn_frame = eth_ipv4_tcp_frame(b"", flags=TCP_SYN)
    source = PcapPacketSource(write(tmp_path, "e.pcap", pcap_bytes([udp_frame, syn_frame])))

    packets = list(source.packets())

    assert len(packets) == 1  # only the TCP SYN survived
    assert packets[0].has_syn
    assert source.stats().skipped == {"non-tcp packet": 1}


def test_unsupported_link_type_raises(tmp_path) -> None:
    source = PcapPacketSource(
        write(tmp_path, "e.pcap", pcap_bytes([eth_ipv4_tcp_frame()], linktype=113))
    )

    with pytest.raises(PacketSourceError, match="link-layer"):
        list(source.packets())


def test_not_a_container_raises(tmp_path) -> None:
    source = PcapPacketSource(write(tmp_path, "e.pcap", b"not a pcap file at all"))

    with pytest.raises(PacketSourceError):
        list(source.packets())


def test_truncated_records_are_counted_not_parsed(tmp_path) -> None:
    data = pcap_bytes([eth_ipv4_tcp_frame(b"hello")])
    source = PcapPacketSource(write(tmp_path, "e.pcap", data[:-4]))

    assert list(source.packets()) == []
    assert source.stats().skipped.get("truncated packet record") == 1
