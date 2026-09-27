"""Tests for Capture evidence validation."""

from datetime import UTC, datetime
from typing import Any

import pytest
from engine.core.capture import MAX_CAPTURE_SIZE_BYTES, Capture, CaptureFormat, CaptureStatus
from pydantic import ValidationError

INGESTED_AT = datetime(2026, 9, 27, 12, 0, 0, tzinfo=UTC)
SHA256 = "a" * 64


def build_capture(**overrides: Any) -> Capture:
    defaults: dict[str, Any] = {
        "id": f"capture_{SHA256[:12]}",
        "filename": "office-traffic.pcapng",
        "size_bytes": 1024,
        "sha256": SHA256,
        "format": CaptureFormat.PCAPNG,
        "status": CaptureStatus.READY,
        "packet_count": 42,
        "ingested_at": INGESTED_AT,
    }
    defaults.update(overrides)
    return Capture(**defaults)


def test_capture_builds_with_all_acquisition_metadata() -> None:
    capture = build_capture()

    assert capture.id == "capture_aaaaaaaaaaaa"
    assert capture.status is CaptureStatus.READY
    assert capture.packet_count == 42
    assert capture.ingested_at == INGESTED_AT
    assert capture.warnings == []


def test_sha256_is_normalized_to_lowercase_hex() -> None:
    capture = build_capture(sha256="A" * 64)

    assert capture.sha256 == "a" * 64


@pytest.mark.parametrize(
    "filename",
    [
        "../evil.pcap",
        "/etc/shadow.pcap",
        "C:\\temp\\evil.pcap",
        "..",
        "dir/evil.pcap",
        "",
        "   ",
    ],
)
def test_rejects_path_like_or_empty_filenames(filename: str) -> None:
    with pytest.raises(ValidationError, match="filename"):
        build_capture(filename=filename)


@pytest.mark.parametrize("sha256", ["", "z" * 64, "a" * 63, "a" * 65])
def test_rejects_invalid_sha256_digests(sha256: str) -> None:
    with pytest.raises(ValidationError, match="sha256"):
        build_capture(sha256=sha256)


def test_rejects_ids_that_are_not_hash_derived() -> None:
    for bad_id in ["capture_" + "g" * 12, "capture_short", "random-id", "../etc/passwd", ""]:
        with pytest.raises(ValidationError):
            build_capture(id=bad_id)


def test_rejects_oversized_and_empty_captures() -> None:
    with pytest.raises(ValidationError):
        build_capture(size_bytes=MAX_CAPTURE_SIZE_BYTES + 1)
    with pytest.raises(ValidationError):
        build_capture(size_bytes=0)


def test_accepts_maximum_boundary_size() -> None:
    capture = build_capture(size_bytes=MAX_CAPTURE_SIZE_BYTES)

    assert capture.size_bytes == MAX_CAPTURE_SIZE_BYTES


def test_packet_count_and_duration_cannot_be_negative() -> None:
    with pytest.raises(ValidationError):
        build_capture(packet_count=-1)
    with pytest.raises(ValidationError):
        build_capture(duration_seconds=-0.1)


def test_rejects_unknown_fields() -> None:
    with pytest.raises(ValidationError):
        build_capture(unexpected="value")
