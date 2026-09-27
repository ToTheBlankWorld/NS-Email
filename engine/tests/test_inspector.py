"""Tests for the packet-tool inspection interface and tshark parsers.

tshark itself is not required to be installed: the parsers are tested
against canned tool output, and the availability path is tested with a
binary path that cannot exist.
"""

from pathlib import Path

import pytest
from engine.ingestion.errors import InspectorError
from engine.ingestion.inspector import (
    TsharkCaptureInspector,
    describe_link_type,
    parse_fields_line,
    parse_tshark_version,
)


def test_parse_tshark_version() -> None:
    line = "TShark (Wireshark) 4.2.2 (v4.2.2-0-g1a2b3c4d)"
    assert parse_tshark_version(line) == "4.2.2"
    assert parse_tshark_version("Command not found") is None


def test_parse_fields_line() -> None:
    assert parse_fields_line("1727430000.123456\t1") == (1727430000.123456, "1")
    assert parse_fields_line("1727430000\t113") == (1727430000.0, "113")
    assert parse_fields_line("") is None
    assert parse_fields_line("garbage output") is None
    assert parse_fields_line("not-a-number\t1") is None


def test_describe_link_type_maps_known_and_falls_back() -> None:
    assert describe_link_type("1") == "Ethernet"
    assert describe_link_type("113") == "Linux SLL"
    assert describe_link_type("999") == "linktype 999"


def test_missing_binary_reports_inspector_error(tmp_path: Path) -> None:
    inspector = TsharkCaptureInspector(
        str(tmp_path / "definitely-not-tshark.exe"), timeout_seconds=1.0
    )

    with pytest.raises(InspectorError):
        inspector.inspect(tmp_path / "evidence.pcap")


def test_version_is_none_when_binary_is_missing(tmp_path: Path) -> None:
    inspector = TsharkCaptureInspector(
        str(tmp_path / "definitely-not-tshark.exe"), timeout_seconds=1.0
    )

    assert inspector.version() is None
