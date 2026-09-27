"""Tests for TCP flow grouping and deterministic session identity."""

from conftest import DEFAULT_CLIENT, DEFAULT_SERVER, ConversationBuilder
from engine.transport.flows import FlowKey, derive_session_id


def packet(builder: ConversationBuilder):
    return builder.packets[0]


def test_bidirectional_packets_group_into_one_flow() -> None:
    b = ConversationBuilder()
    (b.syn().synack().ack().c(b"EHLO test\r\n").s(b"220 ready\r\n"))

    key_a = FlowKey.from_packet(b.packets[3])  # client → server
    key_b = FlowKey.from_packet(b.packets[4])  # server → client

    assert key_a == key_b


def test_flow_key_is_canonical_regardless_of_direction() -> None:
    b = ConversationBuilder()
    b.c(b"from client\r\n")
    b.s(b"from server\r\n")

    keys = {FlowKey.from_packet(p) for p in b.packets}

    assert len(keys) == 1
    key = keys.pop()
    # canonical endpoint order is stable (sorted), not arrival order
    assert key.endpoint_a in (DEFAULT_CLIENT, DEFAULT_SERVER)
    assert key.endpoint_b in (DEFAULT_CLIENT, DEFAULT_SERVER)


def test_session_id_is_deterministic_and_captured_context_aware() -> None:
    b = ConversationBuilder()
    b.c(b"hello\r\n")
    key = FlowKey.from_packet(b.packets[0])

    first = derive_session_id("capture_aaaaaaaaaaaa", key)
    second = derive_session_id("capture_aaaaaaaaaaaa", key)
    other_capture = derive_session_id("capture_bbbbbbbbbbbb", key)

    assert first == second
    assert first != other_capture
    assert first.startswith("session_")
    int(first.split("_")[1], 16)  # filesystem-safe hex
    assert "../" not in first and "/" not in first


def test_two_different_flows_get_different_ids() -> None:
    b1 = ConversationBuilder()
    b1.c(b"a\r\n")
    b2 = ConversationBuilder(server=("198.51.100.7", 993))
    b2.c(b"b\r\n")

    id1 = derive_session_id("capture_aaaaaaaaaaaa", FlowKey.from_packet(b1.packets[0]))
    id2 = derive_session_id("capture_aaaaaaaaaaaa", FlowKey.from_packet(b2.packets[0]))

    assert id1 != id2


def test_builder_keeps_directions_apart() -> None:
    b = ConversationBuilder()
    b.c(b"client data\r\n")
    b.s(b"server data\r\n")

    assert b.packets[0].src_ip == DEFAULT_CLIENT[0]
    assert b.packets[1].src_ip == DEFAULT_SERVER[0]
