"""SQLite-backed capture registry — Stage 1 persistence.

Deliberately simple, single-process, file-based persistence: the registry
lives inside the capture storage root and answers what evidence exists,
what its hash is, what status it has, and what metadata was extracted.
Internal storage paths are never exposed through the public API; evidence
locations are always derived from the deterministic capture id.
"""

import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Protocol

from engine.core.capture import Capture, CaptureFormat, CaptureStatus
from engine.ingestion.errors import CaptureStorageError, DuplicateCaptureError

_SCHEMA = """
CREATE TABLE IF NOT EXISTS captures (
    id TEXT PRIMARY KEY,
    filename TEXT NOT NULL,
    format TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    sha256 TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL,
    packet_count INTEGER,
    capture_started_at TEXT,
    capture_ended_at TEXT,
    duration_seconds REAL,
    link_type TEXT,
    inspector_tool TEXT,
    inspector_version TEXT,
    warnings TEXT NOT NULL DEFAULT '[]',
    ingested_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_captures_ingested_at ON captures(ingested_at);
"""

_INSERT = """
INSERT INTO captures (
    id, filename, format, size_bytes, sha256, status, packet_count,
    capture_started_at, capture_ended_at, duration_seconds, link_type,
    inspector_tool, inspector_version, warnings, ingested_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
"""


class CaptureRegistry(Protocol):
    """Persistence boundary for capture evidence records."""

    def add(self, capture: Capture) -> None: ...

    def get(self, capture_id: str) -> Capture | None: ...

    def get_by_sha256(self, sha256: str) -> Capture | None: ...

    def list_all(self) -> list[Capture]: ...


def _iso(value: datetime) -> str:
    return value.isoformat()


def _from_iso(raw: str | None) -> datetime | None:
    return datetime.fromisoformat(raw) if raw else None


def _to_row(capture: Capture) -> tuple[object, ...]:
    return (
        capture.id,
        capture.filename,
        capture.format.value,
        capture.size_bytes,
        capture.sha256,
        capture.status.value,
        capture.packet_count,
        _iso(capture.capture_started_at) if capture.capture_started_at else None,
        _iso(capture.capture_ended_at) if capture.capture_ended_at else None,
        capture.duration_seconds,
        capture.link_type,
        capture.inspector_tool,
        capture.inspector_version,
        json.dumps(capture.warnings),
        _iso(capture.ingested_at),
    )


def _from_row(row: sqlite3.Row) -> Capture:
    ingested_at = _from_iso(row["ingested_at"])
    if ingested_at is None:
        raise CaptureStorageError("registry row is missing its ingestion timestamp")
    return Capture(
        id=row["id"],
        filename=row["filename"],
        format=CaptureFormat(row["format"]),
        size_bytes=row["size_bytes"],
        sha256=row["sha256"],
        status=CaptureStatus(row["status"]),
        packet_count=row["packet_count"],
        capture_started_at=_from_iso(row["capture_started_at"]),
        capture_ended_at=_from_iso(row["capture_ended_at"]),
        duration_seconds=row["duration_seconds"],
        link_type=row["link_type"],
        inspector_tool=row["inspector_tool"],
        inspector_version=row["inspector_version"],
        warnings=json.loads(row["warnings"]),
        ingested_at=ingested_at,
    )


def _connect(db_path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(db_path, timeout=10.0)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA journal_mode=WAL")
    return connection


class SQLiteCaptureRegistry:
    """Concrete registry: one SQLite database inside the storage root."""

    def __init__(self, db_path: Path) -> None:
        self._db_path = db_path
        try:
            db_path.parent.mkdir(parents=True, exist_ok=True)
            with self._session() as connection:
                connection.executescript(_SCHEMA)
        except sqlite3.Error as error:
            raise CaptureStorageError(f"cannot initialize capture registry: {error}") from error

    @contextmanager
    def _session(self) -> Iterator[sqlite3.Connection]:
        connection = _connect(self._db_path)
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def add(self, capture: Capture) -> None:
        try:
            with self._session() as connection:
                connection.execute(_INSERT, _to_row(capture))
        except sqlite3.IntegrityError as error:
            # UNIQUE constraint on sha256: same evidence registered in a race.
            raise DuplicateCaptureError(
                f"capture with sha256 {capture.sha256} already exists"
            ) from error
        except sqlite3.Error as error:
            raise CaptureStorageError(f"cannot register capture: {error}") from error

    def get(self, capture_id: str) -> Capture | None:
        return self._query_one("SELECT * FROM captures WHERE id = ?", (capture_id,))

    def get_by_sha256(self, sha256: str) -> Capture | None:
        return self._query_one("SELECT * FROM captures WHERE sha256 = ?", (sha256,))

    def list_all(self) -> list[Capture]:
        try:
            with self._session() as connection:
                rows = connection.execute(
                    "SELECT * FROM captures ORDER BY ingested_at DESC, id ASC"
                ).fetchall()
        except sqlite3.Error as error:
            raise CaptureStorageError(f"cannot list captures: {error}") from error
        return [_from_row(row) for row in rows]

    def _query_one(self, query: str, params: tuple[object, ...]) -> Capture | None:
        try:
            with self._session() as connection:
                row = connection.execute(query, params).fetchone()
        except sqlite3.Error as error:
            raise CaptureStorageError(f"cannot query capture registry: {error}") from error
        return _from_row(row) if row is not None else None
