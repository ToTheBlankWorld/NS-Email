"""Stage 6 TLS conversation fixture: 20 normal + 1 unusual TLS session."""

import struct


def _tls_record(content_type: int, version: int, payload: bytes) -> bytes:
    return struct.pack(">BHH", content_type, version, len(payload)) + payload


def _handshake_message(message_type: int, body: bytes) -> bytes:
    return bytes([message_type]) + len(body).to_bytes(3, "big") + body


def _client_hello_record(sni: bytes = b"mail.example.org") -> bytes:
    body = struct.pack(">H", 0x0303) + b"\x42" * 32 + bytes([0])
    suites = (0xC02F, 0x009C)
    suites_blob = b"".join(struct.pack(">H", s) for s in suites)
    body += struct.pack(">H", len(suites_blob)) + suites_blob + bytes([1, 0])
    name_entry = bytes([0]) + struct.pack(">H", len(sni)) + sni
    sni_ext = (
        struct.pack(">HH", 0, len(name_entry) + 2) + struct.pack(">H", len(name_entry)) + name_entry
    )
    exts = sni_ext
    body += struct.pack(">H", len(exts)) + exts
    return _tls_record(22, 0x0301, _handshake_message(1, body))


def _unusual_client_hello_record() -> bytes:
    """Unusual profile: no SNI, only one suite, short extensions block."""
    body = struct.pack(">H", 0x0303) + b"\x42" * 32 + bytes([0])
    suites_blob = struct.pack(">H", 0x009C)  # single unusual suite
    body += struct.pack(">H", len(suites_blob)) + suites_blob + bytes([1, 0])
    body += struct.pack(">H", 0)  # no extensions
    return _tls_record(22, 0x0301, _handshake_message(1, body))


def _server_hello_record(suite: int = 0xC02F) -> bytes:
    body = struct.pack(">H", 0x0303) + b"\x43" * 32 + bytes([0])
    body += struct.pack(">H", suite) + bytes([0])
    return _tls_record(22, 0x0303, _handshake_message(2, body))


def _ccs_record() -> bytes:
    return _tls_record(20, 0x0303, b"\x01")


def multi_session_tls_pcap(*, normal_count: int = 20) -> bytes:
    """Build a multi-session capture: N normal TLS sessions + 1 unusual."""
    all_frames: list[bytes] = []

    def build_session(client_ip: str, client_port: int, unusual: bool = False) -> list[bytes]:
        frames: list[bytes] = []

        def frame(src_ip, dst_ip, sport, dport, seq, flags, payload=b""):
            tcp = struct.pack(">HHIIBBHHH", sport, dport, seq, 0, 5 << 4, flags, 8192, 0, 0)
            total = 20 + len(tcp) + len(payload)

            def ip4(ip):
                return bytes(int(o) for o in ip.split("."))

            ip = (
                struct.pack(">BBHHHBBH", 0x45, 0, total, 0, 0, 64, 6, 0) + ip4(src_ip) + ip4(dst_ip)
            )
            eth = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb" + struct.pack(">H", 0x0800)
            return eth + ip + tcp + payload

        syn_flags, synack_flags, ack_psh_flags, fin_flags = 0x02, 0x12, 0x18, 0x11
        frames.append(frame(client_ip, "198.51.100.7", client_port, 443, 1000, syn_flags))
        frames.append(frame("198.51.100.7", client_ip, 443, client_port, 9000, synack_flags))
        frames.append(frame(client_ip, "198.51.100.7", client_port, 443, 1001, ack_psh_flags))
        hello = _unusual_client_hello_record() if unusual else _client_hello_record()
        frames.append(
            frame(client_ip, "198.51.100.7", client_port, 443, 1001, ack_psh_flags | 0x20, hello)
        )
        frames.append(
            frame(
                "198.51.100.7",
                client_ip,
                443,
                client_port,
                9001,
                ack_psh_flags,
                _server_hello_record(),
            )
        )
        frames.append(
            frame("198.51.100.7", client_ip, 443, client_port, 9001, ack_psh_flags, _ccs_record())
        )
        frames.append(
            frame(client_ip, "198.51.100.7", client_port, 443, 1001 + len(hello), fin_flags)
        )
        frames.append(frame("198.51.100.7", client_ip, 443, client_port, 9001, fin_flags))
        return frames

    for i in range(normal_count):
        client_port = 49200 + i
        client_ip = f"10.10.0.{20 + i % 200}"
        all_frames += build_session(client_ip, client_port, unusual=False)

    all_frames += build_session("10.10.0.99", 49999, unusual=True)
    return tf_frames_to_pcap(all_frames)


def tf_frames_to_pcap(frames: list[bytes]) -> bytes:
    out = struct.pack("<I", 0xA1B2C3D4) + struct.pack("<HHiIII", 2, 4, 0, 0, 65535, 1)
    for index, frame in enumerate(frames):
        out += struct.pack("<IIII", 1727430000 + index * 10, 0, len(frame), len(frame))
        out += frame
    return out
