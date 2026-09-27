"""Display-filename validation for uploaded captures.

Filenames are untrusted display metadata: the engine never derives
filesystem paths from them. Validation guarantees that stored metadata is
sane and rejects obvious traversal payloads early, before any byte is
written to disk.
"""

from typing import Final

from engine.ingestion.errors import UnsupportedCaptureTypeError

ACCEPTED_CAPTURE_EXTENSIONS: Final[tuple[str, ...]] = (".pcap", ".pcapng")

MAX_FILENAME_LENGTH: Final[int] = 255

_FORBIDDEN_TOKENS: Final[tuple[str, ...]] = ("/", "\\", "\x00", "..", "./")


def validate_display_filename(filename: str) -> str:
    """Return the normalized display filename or raise UnsupportedCaptureTypeError.

    The returned name is display metadata only; evidence files are stored
    under their deterministic capture id, never under this name.
    """
    name = filename.strip()
    if not name:
        raise UnsupportedCaptureTypeError("a capture filename is required")
    if len(name) > MAX_FILENAME_LENGTH:
        raise UnsupportedCaptureTypeError("capture filename is too long")
    if any(token in name for token in _FORBIDDEN_TOKENS):
        raise UnsupportedCaptureTypeError("capture filename must not contain path components")
    if not name.lower().endswith(ACCEPTED_CAPTURE_EXTENSIONS):
        raise UnsupportedCaptureTypeError("only .pcap and .pcapng captures are accepted")
    return name
