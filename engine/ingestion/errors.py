"""Ingestion-domain error types raised by capture evidence acquisition."""


class CaptureIngestionError(Exception):
    """Base class for capture ingestion failures."""


class UnsupportedCaptureTypeError(CaptureIngestionError):
    """The uploaded filename is not an accepted capture type."""


class CaptureTooLargeError(CaptureIngestionError):
    """The upload exceeds the configured maximum capture size."""


class InvalidCaptureError(CaptureIngestionError):
    """The uploaded bytes are not a structurally valid capture."""


class CaptureStorageError(CaptureIngestionError):
    """Writing or reading capture evidence failed."""


class DuplicateCaptureError(CaptureIngestionError):
    """Evidence with this hash is already registered (concurrent ingest race)."""


class InspectorError(CaptureIngestionError):
    """Packet inspection failed for a non-validity reason (crash or timeout)."""


__all__ = [
    "CaptureIngestionError",
    "CaptureStorageError",
    "CaptureTooLargeError",
    "DuplicateCaptureError",
    "InspectorError",
    "InvalidCaptureError",
    "UnsupportedCaptureTypeError",
]
