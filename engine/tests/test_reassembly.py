"""Tests for TCP stream reassembly: ordering, gaps, retransmissions, termination."""

from conftest import ConversationBuilder
from engine.transport.packets import TCP_ACK, TCP_PSH, TCP_RST
from engine.transport.reassembly import StreamAssembler, StreamAssembly, assemble_direction


def assemble(packets) -> StreamAssembly:
    return assemble_direction(packets)


def test_ordered_segments_reconstruct_in_sequence_order() -> None:
    b = ConversationBuilder()
    (b.syn().ack().c(b"first ").c(b"second ").c(b"third\r\n"))

    assembly = assemble(b.build())

    assert assembly.stream() == b"first second third\r\n"
    assert assembly.complete is False  # no FIN/RST yet
    assert assembly.gap_count == 0


def test_out_of_order_segments_are_reordered(tmp_path=None) -> None:
    b = ConversationBuilder()
    b.syn().ack()
    b.c(b"AAAABBBB")
    b.c(b"CCCCDDDD")

    assembler = StreamAssembler()
    packets = b.build()
    # deliver out of order: second data segment arrives first
    for packet in [packets[3], packets[2]]:
        assembler.add_packet(packet)

    assembly = assembler.assemble()

    assert assembly.stream() == b"AAAABBBBCCCCDDDD"
    assert assembly.gap_count == 0


def test_missing_segment_records_gap_and_incompleteness() -> None:
    b = ConversationBuilder()
    b.syn().ack()
    b.c(b"AAAABBBB")
    b.c(b"CCCCDDDD")  # this segment is dropped below
    b.c(b"EEEEFFFF")
    packets = [p for p in b.build() if p.payload != b"CCCCDDDD"]

    assembly = assemble(packets)

    assert b"AAAABBBB" in assembly.stream()
    assert b"CCCCDDDD" not in assembly.stream()
    assert b"EEEEFFFF" in assembly.stream()
    assert assembly.gap_count == 1
    assert assembly.gap_bytes == 8
    assert assembly.complete is False
    assert "gap" in (assembly.completeness_reason or "")


def test_retransmitted_segment_is_counted_not_duplicated() -> None:
    b = ConversationBuilder()
    b.syn().ack()
    b.c(b"250-OK\r\n")
    duplicated_seq = b.seq_c - len(b"250-OK\r\n")
    b.c(b"250 GO\r\n")
    # re-send the first segment with extra data appended (classic retransmission)
    b.raw_c(b"250-OK\r\n250 GO\r\n", seq=duplicated_seq)

    assembly = assemble(b.build())

    assert assembly.stream() == b"250-OK\r\n250 GO\r\n"
    assert assembly.retransmitted_segments == 1
    assert assembly.duplicate_segments == 0


def test_duplicate_segment_is_counted() -> None:
    b = ConversationBuilder()
    b.syn().ack()
    seq = b.seq_c
    b.c(b"AAAABBBB")
    b.raw_c(b"AAAABBBB", seq=seq)  # exact duplicate

    assembly = assemble(b.build())

    assert assembly.stream() == b"AAAABBBB"
    assert assembly.duplicate_segments == 1


def test_fin_provides_graceful_termination() -> None:
    b = ConversationBuilder()
    b.syn().ack().c(b"data\r\n").fin_c()

    assembly = assemble(b.build())

    assert assembly.fin_seen is True
    assert assembly.complete is True


def test_rst_seen_from_same_direction_counts_as_termination() -> None:
    from engine.transport.packets import PacketRecord

    b = ConversationBuilder()
    b.syn().ack().c(b"data\r\n")
    packets = b.build()
    packets.append(
        PacketRecord(
            number=99,
            timestamp=b.timestamp,
            captured_len=0,
            original_len=0,
            src_ip=b.server[0],
            dst_ip=b.client[0],
            src_port=b.server[1],
            dst_port=b.client[1],
            tcp_flags=TCP_RST,
        )
    )

    # reassembly is per direction; assemble the client direction only here
    assembly = assemble([p for p in packets if p.src_ip == b.client[0]])

    assert assembly.rst_seen is False  # the RST came from the server direction
    assert assembly.complete is False


def test_stale_segments_below_the_isn_are_reported() -> None:
    from engine.transport.packets import PacketRecord

    b = ConversationBuilder()
    b.syn()  # ISN 1000 → data base 1001
    b.ack()
    b.c(b"later data\r\n")
    packets = b.build()

    assembler = StreamAssembler()
    for packet in packets:
        assembler.add_packet(packet)
    assembler.add_packet(
        PacketRecord(
            number=98,
            timestamp=b.timestamp - 1,
            captured_len=0,
            original_len=0,
            src_ip=b.client[0],
            dst_ip=b.server[0],
            src_port=b.client[1],
            dst_port=b.server[1],
            tcp_flags=TCP_ACK | TCP_PSH,
            tcp_seq=901,  # below the ISN-anchored base: stale data
            payload=b"pre-base bytes",
        )
    )

    assembly = assembler.assemble()

    assert assembly.ignored_segments == 1
    assert assembly.stream() == b"later data\r\n"


def test_offset_locator_maps_back_to_packets() -> None:
    b = ConversationBuilder()
    b.syn().ack().c(b"AAAABBBB").c(b"CCCCDDDD")

    assembly = assemble(b.build())

    number_a, _ = assembly.locator(0)
    number_b, _ = assembly.locator(8)  # first byte of the second segment
    assert number_a != number_b
    assert assembly.packets_covering(0, 8) == [number_a]
