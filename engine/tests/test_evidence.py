"""Tests for evidence hashing and deterministic capture identity."""

import hashlib
import io
import os
import tempfile
from pathlib import Path

from engine.ingestion.evidence import compute_sha256, derive_capture_id


def test_streaming_hash_matches_whole_file_hash() -> None:
    payload = os.urandom(3 * 1024 * 1024 + 17)  # spans multiple chunks

    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "evidence.bin"
        path.write_bytes(payload)
        with path.open("rb") as stream:
            streamed = compute_sha256(stream)

    assert streamed == hashlib.sha256(payload).hexdigest()


def test_hash_of_small_stream() -> None:
    assert compute_sha256(io.BytesIO(b"ns-email")) == hashlib.sha256(b"ns-email").hexdigest()


def test_capture_id_is_deterministic_and_hash_derived() -> None:
    sha256 = hashlib.sha256(b"evidence").hexdigest()

    assert derive_capture_id(sha256) == derive_capture_id(sha256)
    assert derive_capture_id(sha256) == f"capture_{sha256[:12]}"


def test_capture_id_does_not_depend_on_filename() -> None:
    sha256 = "b" * 64

    assert "mail" not in derive_capture_id(sha256)
    assert derive_capture_id(sha256) == "capture_bbbbbbbbbbbb"
