"""Longitudinal baseline persistence (Stage 14).

The drift layer derives observations, comparisons, and drift records
on demand from immutable analysis output (Stage 12 precedent: derived
intelligence is never persisted, so it can never go stale). The only
persisted longitudinal state is the analyst-selected baseline capture
per case — workflow metadata, like any other case-level choice.

The baseline record carries no timestamps, keeping exports fully
deterministic. Baseline selection/clearing is audited through the
existing case timeline (``baseline_selected`` / ``baseline_cleared``
events, whose wall-clock stamps are already accepted as explicitly
dynamic metadata).
"""

import re
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from engine.ingestion.errors import CaptureStorageError

BASELINE_CAPTURE_PATTERN = re.compile(r"^capture_[0-9a-f]{12}$")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS case_baselines (
    case_id TEXT PRIMARY KEY,
    baseline_capture_id TEXT NOT NULL
);
"""


@dataclass(frozen=True, slots=True)
class BaselineRecord:
    """The analyst-selected baseline capture for one case."""

    case_id: str
    baseline_capture_id: str


def _connect(db_path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(db_path, timeout=10.0)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA journal_mode=WAL")
    return connection


class DriftStore:
    """Persistence for longitudinal baseline selections (metadata only)."""

    def __init__(self, db_path: Path) -> None:
        self._db_path = db_path
        try:
            db_path.parent.mkdir(parents=True, exist_ok=True)
            with self._session() as connection:
                connection.executescript(_SCHEMA)
        except sqlite3.Error as error:
            raise CaptureStorageError(f"cannot initialize drift store: {error}") from error

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

    def get_baseline(self, case_id: str) -> BaselineRecord | None:
        """Return the baseline selection for a case, if any."""
        try:
            with self._session() as connection:
                row = connection.execute(
                    "SELECT case_id, baseline_capture_id FROM case_baselines WHERE case_id = ?",
                    (case_id,),
                ).fetchone()
        except sqlite3.Error as error:
            raise CaptureStorageError(f"cannot load baseline: {error}") from error
        if row is None:
            return None
        return BaselineRecord(
            case_id=row["case_id"], baseline_capture_id=row["baseline_capture_id"]
        )

    def set_baseline(self, case_id: str, baseline_capture_id: str) -> BaselineRecord:
        """Record (or replace) the baseline capture for a case."""
        try:
            with self._session() as connection:
                connection.execute(
                    "INSERT INTO case_baselines (case_id, baseline_capture_id)"
                    " VALUES (?, ?)"
                    " ON CONFLICT(case_id) DO UPDATE SET"
                    " baseline_capture_id=excluded.baseline_capture_id",
                    (case_id, baseline_capture_id),
                )
        except sqlite3.Error as error:
            raise CaptureStorageError(f"cannot set baseline: {error}") from error
        return BaselineRecord(case_id=case_id, baseline_capture_id=baseline_capture_id)

    def clear_baseline(self, case_id: str) -> bool:
        """Remove the baseline selection for a case; returns True if one existed."""
        try:
            with self._session() as connection:
                cursor = connection.execute(
                    "DELETE FROM case_baselines WHERE case_id = ?", (case_id,)
                )
                return (cursor.rowcount or 0) > 0
        except sqlite3.Error as error:
            raise CaptureStorageError(f"cannot clear baseline: {error}") from error

    def clear_baseline_if_match(self, case_id: str, capture_id: str) -> bool:
        """Clear the baseline only when it references the given capture."""
        current = self.get_baseline(case_id)
        if current is None or current.baseline_capture_id != capture_id:
            return False
        return self.clear_baseline(case_id)
