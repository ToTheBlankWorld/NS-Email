"""Tests for capture container identification from magic bytes."""

import struct

import pytest
from engine.core.capture import CaptureFormat
from engine.ingestion.formats import sniff_capture_format


def test_identifies_pcap_in_both_byte_orders_and_resolutions() -> None:
    assert sniff_capture_format(b"\xd4\xc3\xb2\xa1") is CaptureFormat.PCAP
    assert sniff_capture_format(b"\xa1\xb2\xc3\xd4") is CaptureFormat.PCAP
    assert sniff_capture_format(b"\x4d\x3c\xb2\xa1") is CaptureFormat.PCAP
    assert sniff_capture_format(b"\xa1\xb2\x3c\x4d") is CaptureFormat.PCAP


def test_identifies_pcapng_section_header_block() -> None:
    shb = b"\x0a\x0d\x0d\x0a" + struct.pack("<I", 28)
    assert sniff_capture_format(shb) is CaptureFormat.PCAPNG


def test_identifies_format_from_padded_header() -> None:
    header = b"\xd4\xc3\xb2\xa1" + b"\x00" * 12
    assert sniff_capture_format(header) is CaptureFormat.PCAP


@pytest.mark.parametrize(
    "header",
    [
        b"",
        b"\x00\x00\x00\x00",
        b"PK\x03\x04",  # zip
        b"%PDF",  # pdf
        b"MZ",  # PE executable
        b"\xd4\xc3\xb2",  # truncated
    ],
)
def test_rejects_bytes_that_are_not_capture_containers(header: bytes) -> None:
    assert sniff_capture_format(header) is None
