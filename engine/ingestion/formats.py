"""Capture format identification from file magic bytes."""

from typing import Final

from engine.core.capture import CaptureFormat

# pcap global-header magic in both byte orders and both resolutions.
PCAP_MAGIC_LE: Final[bytes] = b"\xd4\xc3\xb2\xa1"  # little-endian, microseconds
PCAP_MAGIC_BE: Final[bytes] = b"\xa1\xb2\xc3\xd4"  # big-endian, microseconds
PCAP_MAGIC_LE_NS: Final[bytes] = b"\x4d\x3c\xb2\xa1"  # little-endian, nanoseconds
PCAP_MAGIC_BE_NS: Final[bytes] = b"\xa1\xb2\x3c\x4d"  # big-endian, nanoseconds

# pcapng Section Header Block block-type, written identically in any endianness.
PCAPNG_MAGIC: Final[bytes] = b"\x0a\x0d\x0d\x0a"

_PCAP_MAGICS: Final[frozenset[bytes]] = frozenset(
    {PCAP_MAGIC_LE, PCAP_MAGIC_BE, PCAP_MAGIC_LE_NS, PCAP_MAGIC_BE_NS}
)

SNIFF_HEADER_BYTES: Final[int] = 16


def sniff_capture_format(header: bytes) -> CaptureFormat | None:
    """Identify a capture container from its leading magic bytes.

    Returns ``None`` when the bytes do not match any supported capture
    container — the file extension alone is never trusted.
    """
    if header[: len(PCAPNG_MAGIC)] == PCAPNG_MAGIC:
        return CaptureFormat.PCAPNG
    if header[:4] in _PCAP_MAGICS:
        return CaptureFormat.PCAP
    return None
