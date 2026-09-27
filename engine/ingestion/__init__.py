"""Capture evidence acquisition: validation, hashing, storage, inspection.

Stage 1 establishes the trustworthy evidence-acquisition layer. It is
deliberately protocol-agnostic: SMTP/IMAP/POP3, TLS, and cryptographic
analysis arrive in later stages.
"""

from engine.ingestion.errors import (
    CaptureIngestionError,
    CaptureStorageError,
    CaptureTooLargeError,
    DuplicateCaptureError,
    InspectorError,
    InvalidCaptureError,
    UnsupportedCaptureTypeError,
)
from engine.ingestion.evidence import compute_sha256, derive_capture_id
from engine.ingestion.formats import sniff_capture_format
from engine.ingestion.inspector import (
    CaptureInspection,
    CaptureInspector,
    InspectionStatus,
    TsharkCaptureInspector,
    describe_link_type,
    parse_fields_line,
    parse_tshark_version,
)
from engine.ingestion.validation import ACCEPTED_CAPTURE_EXTENSIONS, validate_display_filename

__all__ = [
    "ACCEPTED_CAPTURE_EXTENSIONS",
    "CaptureIngestionError",
    "CaptureInspection",
    "CaptureInspector",
    "CaptureStorageError",
    "CaptureTooLargeError",
    "DuplicateCaptureError",
    "InspectionStatus",
    "InspectorError",
    "InvalidCaptureError",
    "TsharkCaptureInspector",
    "UnsupportedCaptureTypeError",
    "compute_sha256",
    "derive_capture_id",
    "describe_link_type",
    "parse_fields_line",
    "parse_tshark_version",
    "sniff_capture_format",
    "validate_display_filename",
]
