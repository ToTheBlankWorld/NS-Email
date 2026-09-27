"""SQLite persistence for analysis results: sessions, events, analysis status.

Kept deliberately separate from the capture registry (Stage 1): captures
are evidence, sessions are derived analysis results that can be replaced
whenever a capture is re-analyzed. Event ``detail`` JSON is written after
redaction — the store never sees raw payload bytes.
"""

import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol

from engine.core.events import EventDirection, EventType, SessionEvent
from engine.core.session import (
    Confidence,
    EmailProtocol,
    Orientation,
    Session,
    StarttlsObservation,
)
from engine.ingestion.errors import CaptureStorageError

_SCHEMA = """
CREATE TABLE IF NOT EXISTS analysis (
    capture_id TEXT PRIMARY KEY,
    status TEXT NOT NULL,
    analyzed_at TEXT NOT NULL,
    session_count INTEGER NOT NULL DEFAULT 0,
    error_code TEXT,
    error_message TEXT,
    warnings TEXT NOT NULL DEFAULT '[]'
);
CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    capture_id TEXT NOT NULL,
    protocol TEXT,
    confidence TEXT NOT NULL,
    orientation TEXT NOT NULL,
    client_ip TEXT NOT NULL,
    client_port INTEGER NOT NULL,
    server_ip TEXT NOT NULL,
    server_port INTEGER NOT NULL,
    implicit_tls INTEGER,
    started_at TEXT,
    ended_at TEXT,
    duration_seconds REAL,
    packet_count INTEGER NOT NULL DEFAULT 0,
    bytes_client_to_server INTEGER NOT NULL DEFAULT 0,
    bytes_server_to_client INTEGER NOT NULL DEFAULT 0,
    complete INTEGER NOT NULL DEFAULT 0,
    completeness_reason TEXT,
    retransmissions INTEGER NOT NULL DEFAULT 0,
    gap_count INTEGER NOT NULL DEFAULT 0,
    gap_bytes INTEGER NOT NULL DEFAULT 0,
    starttls_advertised INTEGER,
    starttls_requested INTEGER,
    starttls_response_seen INTEGER,
    starttls_packet_number INTEGER,
    starttls_at TEXT,
    warnings TEXT NOT NULL DEFAULT '[]'
);
CREATE INDEX IF NOT EXISTS idx_sessions_capture ON sessions(capture_id);
CREATE TABLE IF NOT EXISTS session_events (
    session_id TEXT NOT NULL,
    seq INTEGER NOT NULL,
    type TEXT NOT NULL,
    direction TEXT NOT NULL,
    timestamp TEXT,
    packet_numbers TEXT NOT NULL DEFAULT '[]',
    detail TEXT NOT NULL DEFAULT '{}',
    PRIMARY KEY (session_id, seq)
);
"""

_ANALYSIS_COMPLETED = "completed"
_ANALYSIS_FAILED = "failed"


@dataclass(frozen=True, slots=True)
class AnalysisRecord:
    """Analysis run status for one capture."""

    capture_id: str
    status: str  # not_analyzed | completed | failed
    analyzed_at: datetime | None = None
    session_count: int = 0
    error_code: str | None = None
    error_message: str | None = None
    warnings: list[str] = field(default_factory=list)


class SessionStore(Protocol):
    """Persistence boundary for analysis results."""

    def replace_for_capture(self, capture_id: str, sessions: list[Session]) -> None: ...

    def list_for_capture(self, capture_id: str) -> list[Session]: ...

    def get(self, session_id: str) -> Session | None: ...

    def analysis_status(self, capture_id: str) -> AnalysisRecord: ...

    def record_completed(
        self, capture_id: str, session_count: int, warnings: list[str]
    ) -> None: ...

    def record_failed(self, capture_id: str, code: str, message: str) -> None: ...


def _iso(value: datetime) -> str:
    return value.isoformat()


def _from_iso(raw: str | None) -> datetime | None:
    return datetime.fromisoformat(raw) if raw else None


def _connect(db_path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(db_path, timeout=10.0)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA journal_mode=WAL")
    return connection


def _session_to_row(session: Session) -> tuple[object, ...]:
    starttls = session.starttls
    return (
        session.id,
        session.capture_id,
        session.protocol.value if session.protocol else None,
        session.confidence.value,
        session.orientation.value,
        str(session.client_ip),
        session.client_port,
        str(session.server_ip),
        session.server_port,
        session.implicit_tls,
        _iso(session.started_at) if session.started_at else None,
        _iso(session.ended_at) if session.ended_at else None,
        session.duration_seconds,
        session.packet_count,
        session.bytes_client_to_server,
        session.bytes_server_to_client,
        1 if session.complete else 0,
        session.completeness_reason,
        session.retransmissions,
        session.gap_count,
        session.gap_bytes,
        starttls.advertised if starttls else None,
        starttls.requested if starttls else None,
        starttls.response_seen if starttls else None,
        starttls.packet_number if starttls else None,
        _iso(starttls.timestamp) if starttls and starttls.timestamp else None,
        json.dumps(session.warnings),
    )


def _event_to_row(session_id: str, event: SessionEvent) -> tuple[object, ...]:
    return (
        session_id,
        event.seq,
        event.type.value,
        event.direction.value,
        _iso(event.timestamp) if event.timestamp else None,
        json.dumps(event.packet_numbers),
        json.dumps(event.detail),
    )


def _session_from_row(row: sqlite3.Row, events: list[SessionEvent]) -> Session:
    starttls = None
    if row["starttls_advertised"] or row["starttls_requested"] or row["starttls_response_seen"]:
        starttls = StarttlsObservation(
            advertised=bool(row["starttls_advertised"]),
            requested=bool(row["starttls_requested"]),
            response_seen=bool(row["starttls_response_seen"]),
            packet_number=row["starttls_packet_number"],
            timestamp=_from_iso(row["starttls_at"]),
        )
    return Session(
        id=row["id"],
        capture_id=row["capture_id"],
        protocol=EmailProtocol(row["protocol"]) if row["protocol"] else None,
        confidence=Confidence(row["confidence"]),
        orientation=Orientation(row["orientation"]),
        client_ip=row["client_ip"],
        client_port=row["client_port"],
        server_ip=row["server_ip"],
        server_port=row["server_port"],
        implicit_tls=row["implicit_tls"],
        started_at=_from_iso(row["started_at"]),
        ended_at=_from_iso(row["ended_at"]),
        duration_seconds=row["duration_seconds"],
        packet_count=row["packet_count"],
        bytes_client_to_server=row["bytes_client_to_server"],
        bytes_server_to_client=row["bytes_server_to_client"],
        complete=bool(row["complete"]),
        completeness_reason=row["completeness_reason"],
        retransmissions=row["retransmissions"],
        gap_count=row["gap_count"],
        gap_bytes=row["gap_bytes"],
        starttls=starttls,
        warnings=json.loads(row["warnings"]),
        events=events,
    )


def _event_from_row(row: sqlite3.Row) -> SessionEvent:
    return SessionEvent(
        seq=row["seq"],
        type=EventType(row["type"]),
        direction=EventDirection(row["direction"]),
        timestamp=_from_iso(row["timestamp"]),
        packet_numbers=json.loads(row["packet_numbers"]),
        detail=json.loads(row["detail"]),
    )


class SQLiteSessionStore:
    """Concrete store: sessions/events/analysis tables next to the registry."""

    def __init__(self, db_path: Path) -> None:
        self._db_path = db_path
        try:
            db_path.parent.mkdir(parents=True, exist_ok=True)
            with self._session() as connection:
                connection.executescript(_SCHEMA)
        except sqlite3.Error as error:
            raise CaptureStorageError(f"cannot initialize session store: {error}") from error

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

    def replace_for_capture(self, capture_id: str, sessions: list[Session]) -> None:
        """Atomically replace all analysis results for one capture."""
        try:
            with self._session() as connection:
                connection.execute(
                    "DELETE FROM session_events WHERE session_id IN "
                    "(SELECT id FROM sessions WHERE capture_id = ?)",
                    (capture_id,),
                )
                connection.execute("DELETE FROM sessions WHERE capture_id = ?", (capture_id,))
                for session in sessions:
                    connection.execute(
                        """INSERT INTO sessions (
                            id, capture_id, protocol, confidence, orientation,
                            client_ip, client_port, server_ip, server_port, implicit_tls,
                            started_at, ended_at, duration_seconds, packet_count,
                            bytes_client_to_server, bytes_server_to_client, complete,
                            completeness_reason, retransmissions, gap_count, gap_bytes,
                            starttls_advertised, starttls_requested, starttls_response_seen,
                            starttls_packet_number, starttls_at, warnings
                        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                        _session_to_row(session),
                    )
                    for event in session.events:
                        connection.execute(
                            "INSERT INTO session_events"
                            "(session_id, seq, type, direction, timestamp, packet_numbers, detail)"
                            "VALUES (?,?,?,?,?,?,?)",
                            _event_to_row(session.id, event),
                        )
        except sqlite3.Error as error:
            raise CaptureStorageError(f"cannot persist analysis results: {error}") from error

    def list_for_capture(self, capture_id: str) -> list[Session]:
        try:
            with self._session() as connection:
                rows = connection.execute(
                    "SELECT * FROM sessions WHERE capture_id = ? ORDER BY started_at ASC, id ASC",
                    (capture_id,),
                ).fetchall()
                events = connection.execute(
                    "SELECT * FROM session_events WHERE session_id IN "
                    "(SELECT id FROM sessions WHERE capture_id = ?) "
                    "ORDER BY session_id, seq",
                    (capture_id,),
                ).fetchall()
        except sqlite3.Error as error:
            raise CaptureStorageError(f"cannot list sessions: {error}") from error
        events_by_session: dict[str, list[SessionEvent]] = {}
        for row in events:
            events_by_session.setdefault(row["session_id"], []).append(_event_from_row(row))
        return [_session_from_row(row, events_by_session.get(row["id"], [])) for row in rows]

    def get(self, session_id: str) -> Session | None:
        try:
            with self._session() as connection:
                row = connection.execute(
                    "SELECT * FROM sessions WHERE id = ?", (session_id,)
                ).fetchone()
                events = connection.execute(
                    "SELECT * FROM session_events WHERE session_id = ? ORDER BY seq",
                    (session_id,),
                ).fetchall()
        except sqlite3.Error as error:
            raise CaptureStorageError(f"cannot load session: {error}") from error
        if row is None:
            return None
        return _session_from_row(row, [_event_from_row(event) for event in events])

    def analysis_status(self, capture_id: str) -> AnalysisRecord:
        try:
            with self._session() as connection:
                row = connection.execute(
                    "SELECT * FROM analysis WHERE capture_id = ?", (capture_id,)
                ).fetchone()
        except sqlite3.Error as error:
            raise CaptureStorageError(f"cannot read analysis status: {error}") from error
        if row is None:
            return AnalysisRecord(capture_id=capture_id, status="not_analyzed")
        return AnalysisRecord(
            capture_id=row["capture_id"],
            status=row["status"],
            analyzed_at=_from_iso(row["analyzed_at"]),
            session_count=row["session_count"],
            error_code=row["error_code"],
            error_message=row["error_message"],
            warnings=json.loads(row["warnings"]),
        )

    def record_completed(self, capture_id: str, session_count: int, warnings: list[str]) -> None:
        try:
            with self._session() as connection:
                connection.execute(
                    """INSERT INTO analysis
                    (capture_id, status, analyzed_at, session_count, warnings)
                       VALUES (?, ?, ?, ?, ?)
                       ON CONFLICT(capture_id) DO UPDATE SET
                         status=excluded.status, analyzed_at=excluded.analyzed_at,
                         session_count=excluded.session_count, warnings=excluded.warnings,
                         error_code=NULL, error_message=NULL""",
                    (
                        capture_id,
                        _ANALYSIS_COMPLETED,
                        _iso(datetime.now(UTC)),
                        session_count,
                        json.dumps(warnings),
                    ),
                )
        except sqlite3.Error as error:
            raise CaptureStorageError(f"cannot record analysis status: {error}") from error

    def record_failed(self, capture_id: str, code: str, message: str) -> None:
        try:
            with self._session() as connection:
                connection.execute(
                    """INSERT INTO analysis
                       (capture_id, status, analyzed_at, session_count, error_code, error_message)
                       VALUES (?, ?, ?, 0, ?, ?)
                       ON CONFLICT(capture_id) DO UPDATE SET
                         status=excluded.status, analyzed_at=excluded.analyzed_at,
                         session_count=0, error_code=excluded.error_code,
                         error_message=excluded.error_message, warnings='[]'""",
                    (capture_id, _ANALYSIS_FAILED, _iso(datetime.now(UTC)), code, message),
                )
        except sqlite3.Error as error:
            raise CaptureStorageError(f"cannot record analysis failure: {error}") from error
