"""Shared fixtures and synthetic capture builders for backend tests.

The synthetic pcap/pcapng builders emit minimal but structurally valid
captures (global header + packet records), so tests never need real
production PCAPs or tshark.
"""

import struct
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from engine.core.capture import MAX_CAPTURE_SIZE_BYTES
from engine.ingestion.errors import InspectorError, InvalidCaptureError
from engine.ingestion.inspector import CaptureInspection, InspectionStatus
from fastapi.testclient import TestClient

from app.config import DEFAULT_CORS_ORIGINS, Settings
from app.main import create_app
from app.services.ingestion import CaptureIngestionService


def build_pcap(packets: list[tuple[int, bytes]]) -> bytes:
    """Build a minimal valid pcap (little-endian, microseconds, Ethernet)."""
    data = b"\xd4\xc3\xb2\xa1" + struct.pack("<HHiIII", 2, 4, 0, 0, 65535, 1)
    for ts_sec, payload in packets:
        data += struct.pack("<IIII", ts_sec, 0, len(payload), len(payload)) + payload
    return data


def build_pcapng(packets: list[tuple[int, bytes]]) -> bytes:
    """Build a minimal valid pcapng (SHB, Ethernet IDB, one EPB per packet)."""
    blocks = (
        b"\x0a\x0d\x0d\x0a"
        + struct.pack("<I", 28)
        + b"\x4d\x3c\x2b\x1a"
        + struct.pack("<HHq", 1, 0, -1)
        + struct.pack("<I", 28)
        + b"\x01\x00\x00\x00"
        + struct.pack("<I", 20)
        + struct.pack("<HHI", 1, 0, 65535)
        + struct.pack("<I", 20)
    )
    for ts_sec, payload in packets:
        ts_us = ts_sec * 1_000_000
        padded = payload + b"\x00" * ((4 - len(payload) % 4) % 4)
        total = 32 + len(padded)
        blocks += (
            b"\x06\x00\x00\x00"
            + struct.pack("<I", total)
            + struct.pack("<IIIII", 0, ts_us >> 32, ts_us & 0xFFFFFFFF, len(payload), len(payload))
            + padded
            + struct.pack("<I", total)
        )
    return blocks


class FakeInspector:
    """Scriptable inspector: tshark itself is unavailable on this machine."""

    tool_name = "fake-tshark"

    def __init__(self, *, packet_count: int = 2, invalid: bool = False, crash: bool = False):
        self.packet_count = packet_count
        self.invalid = invalid
        self.crash = crash
        self.seen_paths: list[Path] = []

    def inspect(self, evidence_path: Path) -> CaptureInspection:
        self.seen_paths.append(evidence_path)
        if self.crash:
            raise InspectorError("fake inspector crashed")
        if self.invalid:
            raise InvalidCaptureError("fake inspector rejected the capture")
        return CaptureInspection(
            status=InspectionStatus.INSPECTED,
            tool=self.tool_name,
            tool_version="1.0.0",
            packet_count=self.packet_count,
            first_packet_at=datetime(2026, 9, 27, 12, 0, 0, tzinfo=UTC),
            last_packet_at=datetime(2026, 9, 27, 12, 1, 30, tzinfo=UTC),
            duration_seconds=90.0,
            link_type="Ethernet",
        )


@pytest.fixture(name="client")
def client_fixture(tmp_path: Path) -> TestClient:
    """Default app client with isolated storage (for health endpoint tests)."""
    return TestClient(create_app(_isolated_settings(tmp_path)))


@pytest.fixture(name="make_api")
def make_api_fixture(tmp_path: Path) -> Callable[..., TestClient]:
    """Build isolated API clients with an injectable packet inspector."""

    def make(
        inspector: Any | None = None,
        max_capture_bytes: int = MAX_CAPTURE_SIZE_BYTES,
    ) -> TestClient:
        app = create_app(_isolated_settings(tmp_path, max_capture_bytes))
        app.state.ingestion_service = CaptureIngestionService(
            storage=app.state.capture_storage,
            registry=app.state.capture_registry,
            inspector=inspector,
            max_capture_bytes=max_capture_bytes,
        )
        return TestClient(app)

    return make


def _isolated_settings(tmp_path: Path, max_capture_bytes: int = MAX_CAPTURE_SIZE_BYTES) -> Settings:
    return Settings(
        service_name="ns-email",
        app_version="0.0.0",
        cors_origins=DEFAULT_CORS_ORIGINS,
        capture_storage_dir=tmp_path / "captures",
        max_capture_bytes=max_capture_bytes,
    )
