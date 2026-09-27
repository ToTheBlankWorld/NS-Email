"""Capture evidence: an ingested PCAP / PCAPNG file."""

import re
from enum import StrEnum
from typing import Final

from pydantic import AwareDatetime, Field, field_validator

from engine.core.base import ForensicBase, utc_now

SHA256_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[0-9a-f]{64}$")

# Filenames are untrusted display metadata only; the engine never uses them
# for filesystem access. Path components and traversal sequences are rejected.
_FORBIDDEN_FILENAME_TOKENS: Final[tuple[str, ...]] = ("/", "\\", "\x00", "..", "./")

MAX_CAPTURE_SIZE_BYTES: Final[int] = 2 * 1024 * 1024 * 1024  # 2 GiB


class CaptureFormat(StrEnum):
    """Container formats accepted for ingestion."""

    PCAP = "pcap"
    PCAPNG = "pcapng"
    UNKNOWN = "unknown"


class Capture(ForensicBase):
    """A capture file registered for analysis.

    Only metadata is recorded here. The original filename is display
    metadata and must never be used to locate files on the analysis host.
    """

    filename: str = Field(min_length=1, max_length=255)
    size_bytes: int = Field(ge=1, le=MAX_CAPTURE_SIZE_BYTES)
    sha256: str
    format: CaptureFormat = CaptureFormat.UNKNOWN
    ingested_at: AwareDatetime = Field(default_factory=utc_now)
    capture_started_at: AwareDatetime | None = None

    @field_validator("filename")
    @classmethod
    def _reject_path_components(cls, value: str) -> str:
        stripped = value.strip()
        if not stripped or any(token in stripped for token in _FORBIDDEN_FILENAME_TOKENS):
            raise ValueError("filename must be a plain name without path components")
        return stripped

    @field_validator("sha256")
    @classmethod
    def _validate_sha256(cls, value: str) -> str:
        normalized = value.strip().lower()
        if not SHA256_PATTERN.fullmatch(normalized):
            raise ValueError("sha256 must be a 64-character hex digest")
        return normalized
