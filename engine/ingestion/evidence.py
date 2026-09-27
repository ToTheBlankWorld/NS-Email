"""Evidence hashing and deterministic capture identity."""

import hashlib
from typing import Final, Protocol

_HASH_CHUNK_SIZE: Final[int] = 1024 * 1024
CAPTURE_ID_PREFIX: Final[str] = "capture"
CAPTURE_ID_HEX_LENGTH: Final[int] = 12


class ReadableBinary(Protocol):
    """Minimal readable binary stream interface (synchronous)."""

    def read(self, size: int, /) -> bytes: ...


def compute_sha256(stream: ReadableBinary) -> str:
    """Hash a binary stream in fixed-size chunks.

    Never loads the whole capture into memory, so evidence of any
    permitted size can be hashed with constant memory use.
    """
    digest = hashlib.sha256()
    while chunk := stream.read(_HASH_CHUNK_SIZE):
        digest.update(chunk)
    return digest.hexdigest()


def derive_capture_id(sha256: str) -> str:
    """Derive the deterministic, filesystem-safe identifier for evidence.

    ``capture_<first 12 hex chars of the SHA-256>`` — independent of the
    original filename, stable across repeated ingestion of the same
    evidence, and safe to use as a single directory name.
    """
    return f"{CAPTURE_ID_PREFIX}_{sha256[:CAPTURE_ID_HEX_LENGTH]}"
