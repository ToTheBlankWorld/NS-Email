"""Tests for the SQLite capture registry."""

from datetime import UTC, datetime
from pathlib import Path

import pytest
from engine.core.capture import Capture, CaptureFormat, CaptureStatus

from app.registry import SQLiteCaptureRegistry

NOW = datetime(2026, 9, 27, 12, 0, 0, tzinfo=UTC)
START = datetime(2026, 9, 27, 11, 58, 0, tzinfo=UTC)
END = datetime(2026, 9, 27, 12, 0, 0, tzinfo=UTC)


def build_capture(sha256: str = "a" * 64, **overrides: object) -> Capture:
    defaults: dict[str, object] = {
        "id": f"capture_{sha256[:12]}",
        "filename": "mail.pcap",
        "size_bytes": 2048,
        "sha256": sha256,
        "format": CaptureFormat.PCAP,
        "status": CaptureStatus.READY,
        "packet_count": 7,
        "capture_started_at": START,
        "capture_ended_at": END,
        "duration_seconds": 120.0,
        "link_type": "Ethernet",
        "ingested_at": NOW,
        "inspector_tool": "tshark",
        "inspector_version": "4.2.2",
        "warnings": ["first warning"],
    }
    defaults.update(overrides)
    return Capture(**defaults)


@pytest.fixture(name="registry")
def registry_fixture(tmp_path: Path):
    return SQLiteCaptureRegistry(tmp_path / "registry.sqlite3")


def test_add_and_get_round_trips_all_metadata(registry) -> None:
    capture = build_capture()
    registry.add(capture)

    loaded = registry.get(capture.id)

    assert loaded == capture
    assert loaded is not None
    assert loaded.capture_started_at == START
    assert loaded.warnings == ["first warning"]


def test_get_unknown_returns_none(registry) -> None:
    assert registry.get("capture_000000000000") is None


def test_get_by_sha256(registry) -> None:
    registry.add(build_capture())

    found = registry.get_by_sha256("a" * 64)

    assert found is not None
    assert found.id == "capture_aaaaaaaaaaaa"
    assert registry.get_by_sha256("f" * 64) is None


def test_list_all_orders_by_ingested_at_desc(registry) -> None:
    first = build_capture(sha256="1" * 64, ingested_at=datetime(2026, 9, 27, 10, 0, tzinfo=UTC))
    second = build_capture(sha256="2" * 64, ingested_at=datetime(2026, 9, 27, 11, 0, tzinfo=UTC))
    registry.add(first)
    registry.add(second)

    listed = registry.list_all()

    assert [c.id for c in listed] == [second.id, first.id]


def test_duplicate_sha256_is_rejected(registry) -> None:
    from app.registry import DuplicateCaptureError

    registry.add(build_capture())
    with pytest.raises(DuplicateCaptureError):
        registry.add(build_capture(sha256="a" * 64, id="capture_bbbbbbbbbbbb"))
