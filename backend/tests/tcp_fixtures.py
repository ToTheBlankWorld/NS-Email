"""Byte-level TCP conversation builders for analysis-pipeline tests.

These emit full pcap containers (Ethernet/IPv4/TCP frames) for the ten
Stage 2 fixture scenarios — real evidence bytes, no external tooling.
"""

import struct

CLIENT: tuple[str, int] = ("10.10.0.23", 49152)
SMTP_SERVER: tuple[str, int] = ("198.51.100.7", 587)
TCP_FIN, TCP_SYN, TCP_PSH, TCP_ACK = 0x01, 0x02, 0x08, 0x10


def _ip_bytes(ip: str) -> bytes:
    return bytes(int(octet) for octet in ip.split("."))


def _tcp_frame(
    src: tuple[str, int],
    dst: tuple[str, int],
    seq: int,
    flags: int,
    payload: bytes = b"",
) -> bytes:
    tcp_header = struct.pack(">HHIIBBHHH", src[1], dst[1], seq, 0, 5 << 4, flags, 8192, 0, 0)
    total_len = 20 + len(tcp_header) + len(payload)
    ip_header = (
        struct.pack(">BBHHHBBH", 0x45, 0, total_len, 0, 0, 64, 6, 0)
        + _ip_bytes(src[0])
        + _ip_bytes(dst[0])
    )
    return (
        b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb"
        + struct.pack(">H", 0x0800)
        + ip_header
        + tcp_header
        + payload
    )


class FrameConversation:
    """Builds Ethernet/IPv4/TCP frames for a synthetic client/server exchange."""

    def __init__(
        self,
        client: tuple[str, int] = CLIENT,
        server: tuple[str, int] = SMTP_SERVER,
    ) -> None:
        self.client = client
        self.server = server
        self.seq_c = 1000
        self.seq_s = 9000
        self.frames: list[bytes] = []

    def _add(
        self,
        src: tuple[str, int],
        dst: tuple[str, int],
        seq: int,
        flags: int,
        payload: bytes = b"",
    ) -> "FrameConversation":
        self.frames.append(_tcp_frame(src, dst, seq, flags, payload))
        return self

    def syn(self) -> "FrameConversation":
        self._add(self.client, self.server, self.seq_c, TCP_SYN)
        self.seq_c += 1
        return self

    def synack(self) -> "FrameConversation":
        self._add(self.server, self.client, self.seq_s, TCP_SYN | TCP_ACK)
        self.seq_s += 1
        return self

    def ack(self) -> "FrameConversation":
        self._add(self.client, self.server, self.seq_c, TCP_ACK)
        return self

    def c(self, payload: bytes) -> "FrameConversation":
        self._add(self.client, self.server, self.seq_c, TCP_ACK | TCP_PSH, payload)
        self.seq_c += len(payload)
        return self

    def s(self, payload: bytes) -> "FrameConversation":
        self._add(self.server, self.client, self.seq_s, TCP_ACK | TCP_PSH, payload)
        self.seq_s += len(payload)
        return self

    def raw_c(self, payload: bytes, seq: int) -> "FrameConversation":
        self._add(self.client, self.server, seq, TCP_ACK | TCP_PSH, payload)
        return self

    def fin_c(self) -> "FrameConversation":
        self._add(self.client, self.server, self.seq_c, TCP_ACK | TCP_FIN)
        return self

    def fin_s(self) -> "FrameConversation":
        self._add(self.server, self.client, self.seq_s, TCP_ACK | TCP_FIN)
        return self

    def to_pcap(self) -> bytes:
        out = struct.pack("<I", 0xA1B2C3D4) + struct.pack("<HHiIII", 2, 4, 0, 0, 65535, 1)
        for index, frame in enumerate(self.frames):
            out += struct.pack("<IIII", 1727430000 + index, 0, len(frame), len(frame))
            out += frame
        return out


def smtp_plain_pcap() -> bytes:
    b = FrameConversation()
    (
        b.syn()
        .synack()
        .ack()
        .s(b"220 mail.example.org ESMTP Postfix\r\n")
        .c(b"EHLO client.example.net\r\n")
        .s(b"250-mail.example.org\r\n250-PIPELINING\r\n250 8BITMIME\r\n")
        .c(b"MAIL FROM:<alice@example.net>\r\n")
        .s(b"250 2.1.0 Ok\r\n")
        .c(b"RCPT TO:<bob@example.org>\r\n")
        .s(b"250 2.1.5 Ok\r\n")
        .c(b"DATA\r\n")
        .s(b"354 End data with <CR><LF>.<CR><LF>\r\n")
        .c(b"Subject: Hello\r\n\r\nBody must not appear in evidence.\r\n.\r\n")
        .s(b"250 2.0.0 Ok: queued\r\n")
        .c(b"QUIT\r\n")
        .s(b"221 2.0.0 Bye\r\n")
        .fin_c()
        .fin_s()
    )
    return b.to_pcap()


def smtp_starttls_pcap() -> bytes:
    b = FrameConversation()
    (
        b.syn()
        .synack()
        .ack()
        .s(b"220 mail.example.org ESMTP\r\n")
        .c(b"EHLO client.example.net\r\n")
        .s(b"250-mail.example.org\r\n250-STARTTLS\r\n250 8BITMIME\r\n")
        .c(b"STARTTLS\r\n")
        .s(b"220 2.0.0 Ready to start TLS\r\n")
        .c(b"\x16\x03\x01\x00\x40encrypted-not-parsed\x01\x02")
        .fin_c()
        .fin_s()
    )
    return b.to_pcap()


def imap_pcap() -> bytes:
    b = FrameConversation(server=("198.51.100.7", 143))
    (
        b.syn()
        .synack()
        .ack()
        .s(b"* OK IMAP4rev1 server ready\r\n")
        .c(b"a001 CAPABILITY\r\n")
        .s(b"* CAPABILITY IMAP4rev1 STARTTLS\r\n")
        .s(b"a001 OK CAPABILITY completed\r\n")
        .c(b"a002 LOGIN carol s3cret-password\r\n")
        .s(b"a002 OK LOGIN completed\r\n")
        .c(b"a003 LOGOUT\r\n")
        .s(b"a003 OK LOGOUT completed\r\n")
        .fin_c()
        .fin_s()
    )
    return b.to_pcap()


def pop3_pcap() -> bytes:
    b = FrameConversation(server=("198.51.100.7", 110))
    (
        b.syn()
        .synack()
        .ack()
        .s(b"+OK POP3 mail.example.org ready\r\n")
        .c(b"USER dave\r\n")
        .s(b"+OK\r\n")
        .c(b"PASS hunter2-secret\r\n")
        .s(b"+OK maildrop locked\r\n")
        .c(b"STAT\r\n")
        .s(b"+OK 2 300\r\n")
        .c(b"QUIT\r\n")
        .s(b"+OK signing off\r\n")
        .fin_c()
        .fin_s()
    )
    return b.to_pcap()


def smtp_fragmented_pcap() -> bytes:
    b = FrameConversation()
    (
        b.syn()
        .synack()
        .ack()
        .s(b"220 mail.example.or")
        .s(b"g ESMTP ready\r\n")
        .c(b"EHLO client.example.net\r\n")
        .s(b"250 2.0.0 Ok\r\n")
        .c(b"QUIT\r\n")
        .s(b"221 2.0.0 Bye\r\n")
        .fin_c()
        .fin_s()
    )
    return b.to_pcap()


def smtp_out_of_order_pcap() -> bytes:
    b = FrameConversation()
    b.syn().synack().ack()
    b.s(b"220 mail.example.org ESMTP ready\r\n")
    ehlo_seq = b.seq_c
    ehlo = b"EHLO client.example.net\r\n"
    b.raw_c(b"QUIT\r\n", ehlo_seq + len(ehlo))
    b.raw_c(ehlo, ehlo_seq)
    b.seq_c = ehlo_seq + len(ehlo) + len(b"QUIT\r\n")
    b.s(b"250 2.0.0 Ok\r\n")
    b.s(b"221 2.0.0 Bye\r\n")
    b.fin_c().fin_s()
    return b.to_pcap()


def smtp_retransmission_pcap() -> bytes:
    b = FrameConversation()
    (
        b.syn()
        .synack()
        .ack()
        .s(b"220 mail.example.org ESMTP ready\r\n")
        .c(b"EHLO client.example.net\r\n")
    )
    b.raw_c(
        b"EHLO client.example.net\r\nEXTRA\r\n",
        b.seq_c - len(b"EHLO client.example.net\r\n"),
    )
    (b.s(b"250 2.0.0 Ok\r\n").c(b"QUIT\r\n").s(b"221 2.0.0 Bye\r\n").fin_c().fin_s())
    return b.to_pcap()


def incomplete_pcap() -> bytes:
    b = FrameConversation()
    (
        b.syn()
        .synack()
        .ack()
        .s(b"220 mail.example.org ESMTP ready\r\n")
        .c(b"EHLO client.example.net\r\n")
        .s(b"250 2.1.0 Ok\r\n")
        .s(b"250 2.1.5 Ok\r\n")
        .c(b"QUIT\r\n")
        .s(b"221 2.0.0 Bye\r\n")
        .fin_c()
        .fin_s()
    )
    dropped = b"250 2.1.0 Ok\r\n"
    for index, frame in enumerate(b.frames):
        if dropped in frame and index > 3:
            del b.frames[index]
            break
    return b.to_pcap()


def unknown_protocol_pcap() -> bytes:
    b = FrameConversation(server=("198.51.100.7", 9999))
    (b.syn().synack().ack().s(b"\x00\x01\x02binary\x00").c(b"\xaa\xbb\xcc\xdd").fin_c().fin_s())
    return b.to_pcap()


def malformed_pcap() -> bytes:
    b = FrameConversation()
    (b.syn().synack().ack().s(b"not-a-greeting at all\r\n").c(b"\x01\x02\x03\x04").fin_s())
    return b.to_pcap()


def frames_to_pcap(frames: list[bytes]) -> bytes:
    """Wrap pre-built Ethernet frames into one pcap container."""
    out = struct.pack("<I", 0xA1B2C3D4) + struct.pack("<HHiIII", 2, 4, 0, 0, 65535, 1)
    for index, frame in enumerate(frames):
        out += struct.pack("<IIII", 1727430000 + index, 0, len(frame), len(frame))
        out += frame
    return out
