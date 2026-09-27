"""Shared TCP conversation builders for engine tests.

``ConversationBuilder`` emits normalized ``PacketRecord`` streams for a
synthetic client/server exchange with realistic sequence-number
accounting, so protocol tests read like the wire.
"""

from dataclasses import dataclass, field

from engine.transport.packets import (
    TCP_ACK,
    TCP_FIN,
    TCP_PSH,
    TCP_SYN,
    PacketRecord,
)

Endpoint = tuple[str, int]

DEFAULT_CLIENT: Endpoint = ("10.10.0.23", 49152)
DEFAULT_SERVER: Endpoint = ("198.51.100.7", 587)
START_TIMESTAMP = 1727430000.0


@dataclass
class ConversationBuilder:
    """Builds a synthetic TCP conversation, one packet at a time."""

    client: Endpoint = field(default_factory=lambda: DEFAULT_CLIENT)
    server: Endpoint = field(default_factory=lambda: DEFAULT_SERVER)
    timestamp: float = START_TIMESTAMP
    seq_c: int = 1000
    seq_s: int = 9000
    packets: list[PacketRecord] = field(default_factory=list)
    _number: int = 1

    def _add(
        self, src: Endpoint, dst: Endpoint, seq: int, flags: int, payload: bytes = b""
    ) -> "ConversationBuilder":
        self.packets.append(
            PacketRecord(
                number=self._number,
                timestamp=self.timestamp,
                captured_len=len(payload),
                original_len=len(payload),
                src_ip=src[0],
                dst_ip=dst[0],
                src_port=src[1],
                dst_port=dst[1],
                tcp_flags=flags,
                tcp_seq=seq,
                tcp_ack=0,
                payload=payload,
            )
        )
        self._number += 1
        self.timestamp += 0.01
        return self

    def syn(self) -> "ConversationBuilder":
        self._add(self.client, self.server, self.seq_c, TCP_SYN)
        self.seq_c += 1
        return self

    def synack(self) -> "ConversationBuilder":
        self._add(self.server, self.client, self.seq_s, TCP_SYN | TCP_ACK)
        self.seq_s += 1
        return self

    def ack(self) -> "ConversationBuilder":
        self._add(self.client, self.server, self.seq_c, TCP_ACK)
        return self

    def c(self, payload: bytes) -> "ConversationBuilder":
        """Client → server data segment."""
        self._add(self.client, self.server, self.seq_c, TCP_ACK | TCP_PSH, payload)
        self.seq_c += len(payload)
        return self

    def s(self, payload: bytes) -> "ConversationBuilder":
        """Server → client data segment."""
        self._add(self.server, self.client, self.seq_s, TCP_ACK | TCP_PSH, payload)
        self.seq_s += len(payload)
        return self

    def fin_c(self) -> "ConversationBuilder":
        self._add(self.client, self.server, self.seq_c, TCP_ACK | TCP_FIN)
        return self

    def fin_s(self) -> "ConversationBuilder":
        self._add(self.server, self.client, self.seq_s, TCP_ACK | TCP_FIN)
        return self

    def raw_c(
        self, payload: bytes, seq: int, flags: int = TCP_ACK | TCP_PSH
    ) -> "ConversationBuilder":
        """Client segment with an explicit sequence number (reordering tests)."""
        self._add(self.client, self.server, seq, flags, payload)
        return self

    def raw_s(
        self, payload: bytes, seq: int, flags: int = TCP_ACK | TCP_PSH
    ) -> "ConversationBuilder":
        """Server segment with an explicit sequence number (reordering tests)."""
        self._add(self.server, self.client, seq, flags, payload)
        return self

    def advance(self, seconds: float) -> "ConversationBuilder":
        self.timestamp += seconds
        return self

    def build(self) -> list[PacketRecord]:
        return list(self.packets)


def smtp_plain_conversation() -> list[PacketRecord]:
    """Complete plain SMTP session with a full mail transaction."""
    b = ConversationBuilder()
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
        .c(b"Subject: Hello\r\n\r\nMessage body must not be stored.\r\n.\r\n")
        .s(b"250 2.0.0 Ok: queued\r\n")
        .c(b"QUIT\r\n")
        .s(b"221 2.0.0 Bye\r\n")
        .fin_c()
        .fin_s()
    )
    return b.build()


def smtp_starttls_conversation() -> list[PacketRecord]:
    """SMTP session where STARTTLS is advertised, requested, accepted."""
    b = ConversationBuilder()
    (
        b.syn()
        .synack()
        .ack()
        .s(b"220 mail.example.org ESMTP\r\n")
        .c(b"EHLO client.example.net\r\n")
        .s(b"250-mail.example.org\r\n250-STARTTLS\r\n250 8BITMIME\r\n")
        .c(b"STARTTLS\r\n")
        .s(b"220 2.0.0 Ready to start TLS\r\n")
        .c(b"\x16\x03\x01\x00\x40encrypted-handshake-not-parsed\x01\x02")
        .fin_c()
        .fin_s()
    )
    return b.build()


def imap_conversation() -> list[PacketRecord]:
    b = ConversationBuilder(server=("198.51.100.7", 143))
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
        .c(b"a003 SELECT INBOX\r\n")
        .s(b"a003 OK [READ-WRITE] SELECT completed\r\n")
        .c(b"a004 LOGOUT\r\n")
        .s(b"* BYE IMAP4rev1 Server logging out\r\n")
        .s(b"a004 OK LOGOUT completed\r\n")
        .fin_c()
        .fin_s()
    )
    return b.build()


def pop3_conversation() -> list[PacketRecord]:
    b = ConversationBuilder(server=("198.51.100.7", 110))
    (
        b.syn()
        .synack()
        .ack()
        .s(b"+OK POP3 mail.example.org ready\r\n")
        .c(b"USER dave\r\n")
        .s(b"+OK\r\n")
        .c(b"PASS hunter2-secret\r\n")
        .s(b"+OK maildrop locked and ready\r\n")
        .c(b"STAT\r\n")
        .s(b"+OK 2 300\r\n")
        .c(b"QUIT\r\n")
        .s(b"+OK POP3 server signing off\r\n")
        .fin_c()
        .fin_s()
    )
    return b.build()


def smtp_fragmented_conversation() -> list[PacketRecord]:
    """SMTP banner split across two TCP segments (fragmented payload)."""
    b = ConversationBuilder()
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
    return b.build()


def smtp_out_of_order_conversation() -> list[PacketRecord]:
    """Segments arriving out of sequence order (reordered by the assembler).

    The QUIT segment arrives before the EHLO segment; correct sequence
    reconstruction must still place EHLO first.
    """
    b = ConversationBuilder()
    b.syn().synack().ack()
    b.s(b"220 mail.example.org ESMTP ready\r\n")
    ehlo_seq = b.seq_c
    ehlo = b"EHLO client.example.net\r\n"
    quit_seq = ehlo_seq + len(ehlo)
    b.raw_c(b"QUIT\r\n", seq=quit_seq)  # arrives first (later sequence)
    b.raw_c(ehlo, seq=ehlo_seq)  # arrives second (earlier sequence)
    b.seq_c = quit_seq + len(b"QUIT\r\n")
    b.s(b"250 2.0.0 Ok\r\n")
    b.s(b"221 2.0.0 Bye\r\n")
    b.fin_c().fin_s()
    return b.build()


def smtp_retransmission_conversation() -> list[PacketRecord]:
    """A retransmitted client segment: overlaps sent data and extends it."""
    b = ConversationBuilder()
    (
        b.syn()
        .synack()
        .ack()
        .s(b"220 mail.example.org ESMTP ready\r\n")
        .c(b"EHLO client.example.net\r\n")
    )
    ehlo_seq = b.seq_c - len(b"EHLO client.example.net\r\n")
    b.raw_c(b"EHLO client.example.net\r\nEXTRA\r\n", seq=ehlo_seq)
    (b.s(b"250 2.0.0 Ok\r\n").c(b"QUIT\r\n").s(b"221 2.0.0 Bye\r\n").fin_c().fin_s())
    return b.build()


def incomplete_conversation() -> list[PacketRecord]:
    """SMTP stream with a missing middle segment (capture gap)."""
    packets = smtp_plain_conversation()
    # drop the server segment carrying "250 2.1.0 Ok" response
    target = next(p for p in packets if b"2.1.0" in p.payload)
    packets.remove(target)
    return packets


def unknown_protocol_conversation() -> list[PacketRecord]:
    """TCP session on a non-email port with non-email payload."""
    b = ConversationBuilder(server=("198.51.100.7", 9999))
    (
        b.syn()
        .synack()
        .ack()
        .s(b"\x00\x01\x02\x03binary-service-banner\x00")
        .c(b"\xaa\xbb\xcc\xdd")
        .fin_c()
        .fin_s()
    )
    return b.build()


def malformed_conversation() -> list[PacketRecord]:
    """SMTP-shaped port but garbage conversation (incomplete protocol data)."""
    b = ConversationBuilder()
    (b.syn().synack().ack().s(b"not-a-greeting at all\r\n").c(b"\x01\x02\x03\x04").fin_s())
    return b.build()
