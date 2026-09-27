"""Controlled capture evidence storage.

Evidence files are always addressed by the deterministic capture id that
the engine derives from the SHA-256 of the uploaded bytes. User-supplied
filenames never touch the filesystem. Layout under the controlled root::

    <root>/
      .staging/                 transient upload staging (cleaned after use)
      registry.sqlite3          capture registry (Stage 1 persistence)
      <capture-id>/
        evidence.pcap|pcapng    the evidence bytes
        metadata.json           human-portable evidence metadata
"""

import os
import shutil
import tempfile
from contextlib import suppress
from pathlib import Path

from engine.core.capture import CAPTURE_ID_PATTERN
from engine.ingestion.errors import CaptureStorageError

STAGING_DIR_NAME = ".staging"
REGISTRY_FILENAME = "registry.sqlite3"


class CaptureStorage:
    """Filesystem layout for capture evidence under a controlled root."""

    def __init__(self, root: Path) -> None:
        self._root = root.resolve()
        try:
            (self._root / STAGING_DIR_NAME).mkdir(parents=True, exist_ok=True)
        except OSError as error:
            raise CaptureStorageError(
                f"cannot create capture storage root {self._root}: {error}"
            ) from error

    @property
    def root(self) -> Path:
        """The resolved storage root (internal use and diagnostics only)."""
        return self._root

    def capture_dir(self, capture_id: str) -> Path:
        """Return the directory for a capture, refusing ids that could escape."""
        if not CAPTURE_ID_PATTERN.fullmatch(capture_id):
            raise CaptureStorageError(f"invalid capture id: {capture_id!r}")
        path = (self._root / capture_id).resolve()
        if not path.is_relative_to(self._root):  # defense in depth
            raise CaptureStorageError("capture id escaped the storage root")
        return path

    def evidence_path(self, capture_id: str, extension: str) -> Path:
        return self.capture_dir(capture_id) / f"evidence.{extension}"

    def metadata_path(self, capture_id: str) -> Path:
        return self.capture_dir(capture_id) / "metadata.json"

    def registry_path(self) -> Path:
        return self._root / REGISTRY_FILENAME

    def create_staging_file(self) -> tuple[int, Path]:
        """Create a staging file inside the storage root; returns (fd, path).

        The caller owns the file descriptor and must close it (typically
        via ``os.fdopen``) and then either ``store_evidence`` or
        ``discard_staging``.
        """
        try:
            fd, raw_path = tempfile.mkstemp(
                dir=self._root / STAGING_DIR_NAME, prefix="upload-", suffix=".tmp"
            )
        except OSError as error:
            raise CaptureStorageError(f"cannot create staging file: {error}") from error
        return fd, Path(raw_path)

    def store_evidence(self, staging_path: Path, capture_id: str, extension: str) -> Path:
        """Move a staged file into its permanent evidence location.

        ``os.replace`` is atomic within the storage root, so a crash can
        never leave a half-written evidence file under a capture id.
        """
        target = self.evidence_path(capture_id, extension)
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            os.replace(staging_path, target)
        except OSError as error:
            raise CaptureStorageError(f"cannot store capture evidence: {error}") from error
        return target

    def discard_staging(self, staging_path: Path) -> None:
        """Best-effort removal of a staging file (missing is fine)."""
        with suppress(OSError):
            staging_path.unlink()

    def discard_capture(self, capture_id: str) -> None:
        """Best-effort removal of a complete capture directory (rollback)."""
        shutil.rmtree(self.capture_dir(capture_id), ignore_errors=True)
