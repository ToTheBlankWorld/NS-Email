"""Tests for untrusted display-filename validation."""

import pytest
from engine.ingestion.errors import UnsupportedCaptureTypeError
from engine.ingestion.validation import validate_display_filename


@pytest.mark.parametrize(
    "name",
    ["mail-traffic.pcap", "office.PCAP", "данные📊.pcapng", "capture with spaces.pcapng"],
)
def test_accepts_plain_capture_names(name: str) -> None:
    assert validate_display_filename(name) == name


@pytest.mark.parametrize(
    "name",
    [
        "../../evil.pcap",
        "..\\..\\evil.pcap",
        "/etc/passwd",
        "C:\\Windows\\System32\\config.pcap",
        "dir/evil.pcapng",
        "trap/../x.pcap",
        "trailing/slash.pcap/",
    ],
)
def test_rejects_path_traversal_and_absolute_paths(name: str) -> None:
    with pytest.raises(UnsupportedCaptureTypeError):
        validate_display_filename(name)


def test_rejects_nul_bytes_and_overlong_names() -> None:
    with pytest.raises(UnsupportedCaptureTypeError):
        validate_display_filename("evil\x00.pcap")
    with pytest.raises(UnsupportedCaptureTypeError):
        validate_display_filename("x" * 256 + ".pcap")


@pytest.mark.parametrize("name", ["notes.txt", "archive.zip", "capture.pcap.exe", "", "   "])
def test_rejects_non_capture_types(name: str) -> None:
    with pytest.raises(UnsupportedCaptureTypeError):
        validate_display_filename(name)


def test_control_characters_are_never_replayed_as_paths() -> None:
    # A control-character name may pass as display metadata, but the value
    # that comes back can never introduce path components.
    accepted = "данные\x01.pcap"
    result = validate_display_filename(accepted)
    assert "/" not in result
    assert "\\" not in result
    assert ".." not in result
