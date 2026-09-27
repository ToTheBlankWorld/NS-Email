"""Capture evidence: an ingested PCAP / PCAPNG file."""

import re
from enum import StrEnum
from typing import Final

from pydantic import AwareDatetime, Field, field_validator

from engine.core.base import ForensicBase, utc_now

SHA256_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[0-9a-f]{64}$")

# Capture identifiers are derived from the evidence hash (see
# engine.ingestion.evidence.derive_capture_id) and are therefore always
# filesystem-safe; the pattern makes that invariant explicit.
CAPTURE_ID_PATTERN: Final[re.Pattern[str]] = re.compile(r"^capture_[0-9a-f]{12}$")

# Filenames are untrusted display metadata only; the engine never uses them
# for filesystem access. Path components and traversal sequences are rejected.
_FORBIDDEN_FILENAME_TOKENS: Final[tuple[str, ...]] = ("/", "\\", "\x00", "..", "./")

# Absolute ceiling for capture evidence, enforced regardless of configuration.
MAX_CAPTURE_SIZE_BYTES: Final[int] = 2 * 1024 * 1024 * 1024  # 2 GiB


class CaptureFormat(StrEnum):
    """Container formats accepted for ingestion."""

    PCAP = "pcap"
    PCAPNG = "pcapng"
    UNKNOWN = "unknown"


class CaptureStatus(StrEnum):
    """Evidence-acquisition lifecycle of a capture.

    ``registered`` — hashed and stored; packet metadata is not available
    (inspector unavailable or inspection failed).
    ``ready`` — hashed, stored, and inspected for generic packet metadata.
    """

    REGISTERED = "registered"
    READY = "ready"


class Capture(ForensicBase):
    """A capture file registered for analysis.

    The identifier is deterministic — ``capture_`` followed by the first
    12 hex characters of the SHA-256 of the evidence bytes — so identical
    evidence always maps to the same capture identity and directory. The
    original filename is display metadata and must never be used to
    locate files on the analysis host; evidence is always stored as
    ``<capture-id>/evidence.<format>``.
    """

    id: str = Field(pattern=CAPTURE_ID_PATTERN.pattern)
    filename: str = Field(min_length=1, max_length=255)
    size_bytes: int = Field(ge=1, le=MAX_CAPTURE_SIZE_BYTES)
    sha256: str
    format: CaptureFormat = CaptureFormat.UNKNOWN
    status: CaptureStatus = CaptureStatus.REGISTERED
    packet_count: int | None = Field(default=None, ge=0)
    capture_started_at: AwareDatetime | None = None
    capture_ended_at: AwareDatetime | None = None
    duration_seconds: float | None = Field(default=None, ge=0)
    link_type: str | None = None
    ingested_at: AwareDatetime = Field(default_factory=utc_now)
    inspector_tool: str | None = None
    inspector_version: str | None = None
    warnings: list[str] = Field(default_factory=list)

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
