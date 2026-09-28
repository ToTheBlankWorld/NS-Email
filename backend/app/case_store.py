"""Forensic case management persistence (Stage 11).

Cases are an organizational and evidence-preservation layer over the
immutable forensic outputs of Stages 1-9. This store holds analyst
workflow metadata only — case records, capture references, notes, tags,
bookmarks, investigation-timeline events, and report history — and never
mutates sessions, findings, posture snapshots, anomaly results, or graph
records, which live in the session store and capture registry.

Case identifiers are secure random values (``case_`` + 16 hex digits),
never sequential. The human-readable ``case_number`` (``CASE-XXXXXXXX``)
is derived deterministically from the id and is display metadata only.
"""

import json
import re
import secrets
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from engine.ingestion.errors import CaptureStorageError

CASE_SCHEMA_VERSION = "1.0"

CASE_ID_PATTERN = re.compile(r"^case_[0-9a-f]{16}$")
NOTE_ID_PATTERN = re.compile(r"^note_[0-9a-f]{16}$")
BOOKMARK_ID_PATTERN = re.compile(r"^bookmark_[0-9a-f]{16}$")
TIMELINE_ID_PATTERN = re.compile(r"^timeline_[0-9a-f]{16}$")
CASE_REPORT_ID_PATTERN = re.compile(r"^casereport_[0-9a-f]{16}$")

CASE_STATUSES: tuple[str, ...] = ("OPEN", "IN_REVIEW", "CLOSED", "ARCHIVED")
CASE_PRIORITIES: tuple[str, ...] = ("LOW", "MEDIUM", "HIGH", "CRITICAL")

# Targets an analyst note may annotate. Notes are free-form analyst
# content attached to a reference — never forensic evidence itself.
NOTE_TARGET_TYPES: tuple[str, ...] = (
    "case",
    "capture",
    "session",
    "finding",
    "anomaly",
    "graph_node",
    "remediation",
)

# Evidence kinds a bookmark may reference. Bookmarks store references
# (type + id), never copies of the underlying evidence.
BOOKMARK_TARGET_TYPES: tuple[str, ...] = (
    "finding",
    "anomaly",
    "session",
    "certificate",
    "tls_handshake",
    "graph_node",
    "timeline_event",
)

# Investigation-timeline event types. This timeline records what the
# analyst DID (case timeline) and is kept strictly separate from the
# forensic timeline reconstructed from captured packets.
TIMELINE_EVENT_TYPES: tuple[str, ...] = (
    "case_created",
    "case_imported",
    "capture_attached",
    "capture_detached",
    "finding_bookmarked",
    "anomaly_bookmarked",
    "bookmark_added",
    "bookmark_removed",
    "note_created",
    "note_updated",
    "note_deleted",
    "tag_added",
    "tag_removed",
    "report_generated",
    "case_exported",
    "status_changed",
    "baseline_selected",
    "baseline_cleared",
)

MAX_TITLE_LENGTH = 200
MAX_DESCRIPTION_LENGTH = 5000
MAX_NOTE_LENGTH = 10000
MAX_TAG_LENGTH = 64
MAX_TAGS_PER_CASE = 50
MAX_LABEL_LENGTH = 200
MAX_BOOKMARK_NOTE_LENGTH = 2000
MAX_TARGET_ID_LENGTH = 256

# Analyst-defined tags: lowercase, URL-path safe (tags travel in DELETE
# paths), no control characters, no whitespace.
_TAG_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._\-]{0,63}$")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS cases (
    case_id TEXT PRIMARY KEY,
    case_number TEXT NOT NULL UNIQUE,
    title TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL,
    priority TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    closed_at TEXT,
    schema_version TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS case_captures (
    case_id TEXT NOT NULL,
    capture_id TEXT NOT NULL,
    attached_at TEXT NOT NULL,
    PRIMARY KEY (case_id, capture_id)
);
CREATE INDEX IF NOT EXISTS idx_case_captures_case ON case_captures(case_id);
CREATE TABLE IF NOT EXISTS case_notes (
    note_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
    target_type TEXT NOT NULL,
    target_id TEXT NOT NULL,
    content TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_case_notes_case ON case_notes(case_id);
CREATE TABLE IF NOT EXISTS case_tags (
    case_id TEXT NOT NULL,
    tag TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (case_id, tag)
);
CREATE INDEX IF NOT EXISTS idx_case_tags_case ON case_tags(case_id);
CREATE TABLE IF NOT EXISTS case_bookmarks (
    bookmark_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
    target_type TEXT NOT NULL,
    target_id TEXT NOT NULL,
    label TEXT NOT NULL DEFAULT '',
    note TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    UNIQUE (case_id, target_type, target_id)
);
CREATE INDEX IF NOT EXISTS idx_case_bookmarks_case ON case_bookmarks(case_id);
CREATE TABLE IF NOT EXISTS case_timeline (
    entry_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    detail TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_case_timeline_case ON case_timeline(case_id, created_at);
CREATE TABLE IF NOT EXISTS case_reports (
    report_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
    format TEXT NOT NULL,
    generated_at TEXT NOT NULL,
    evidence_digest TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_case_reports_case ON case_reports(case_id, generated_at);
"""


@dataclass(frozen=True, slots=True)
class CaseRecord:
    """One forensic investigation case (analyst metadata, not evidence)."""

    case_id: str
    case_number: str
    title: str
    description: str
    status: str
    priority: str
    created_at: datetime | None = None
    updated_at: datetime | None = None
    closed_at: datetime | None = None
    schema_version: str = CASE_SCHEMA_VERSION


@dataclass(frozen=True, slots=True)
class CaptureAttachment:
    """A reference from a case to an ingested capture (no data copied)."""

    case_id: str
    capture_id: str
    attached_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class NoteRecord:
    """Analyst-authored content attached to a case or evidence reference."""

    note_id: str
    case_id: str
    target_type: str
    target_id: str
    content: str
    created_at: datetime | None = None
    updated_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class BookmarkRecord:
    """A named reference from a case back to one evidence item."""

    bookmark_id: str
    case_id: str
    target_type: str
    target_id: str
    label: str = ""
    note: str = ""
    created_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class TimelineEntry:
    """One investigation event (what the analyst did, not packet truth)."""

    entry_id: str
    case_id: str
    event_type: str
    detail: dict[str, str] = field(default_factory=dict)
    created_at: datetime | None = None


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _from_iso(raw: str | None) -> datetime | None:
    return datetime.fromisoformat(raw) if raw else None


def _connect(db_path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(db_path, timeout=10.0)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA journal_mode=WAL")
    return connection


def _has_control_chars(value: str) -> bool:
    return any((ord(ch) < 32 and ch not in ("\n", "\t")) or ord(ch) == 127 for ch in value)


def validate_title(title: str) -> str:
    """Validate a case title; returns the stripped value."""
    cleaned = title.strip()
    if not cleaned:
        raise ValueError("title must not be empty")
    if len(cleaned) > MAX_TITLE_LENGTH:
        raise ValueError(f"title must be at most {MAX_TITLE_LENGTH} characters")
    if _has_control_chars(cleaned):
        raise ValueError("title must not contain control characters")
    return cleaned


def validate_description(description: str) -> str:
    """Validate a case description; returns the stripped value."""
    cleaned = description.strip()
    if len(cleaned) > MAX_DESCRIPTION_LENGTH:
        raise ValueError(f"description must be at most {MAX_DESCRIPTION_LENGTH} characters")
    if _has_control_chars(cleaned):
        raise ValueError("description must not contain control characters")
    return cleaned


def validate_status(status: str) -> str:
    if status not in CASE_STATUSES:
        raise ValueError(f"status must be one of {', '.join(CASE_STATUSES)}")
    return status


def validate_priority(priority: str) -> str:
    if priority not in CASE_PRIORITIES:
        raise ValueError(f"priority must be one of {', '.join(CASE_PRIORITIES)}")
    return priority


def validate_note_content(content: str) -> str:
    cleaned = content.strip()
    if not cleaned:
        raise ValueError("note content must not be empty")
    if len(cleaned) > MAX_NOTE_LENGTH:
        raise ValueError(f"note content must be at most {MAX_NOTE_LENGTH} characters")
    if "\x00" in cleaned:
        raise ValueError("note content must not contain NUL bytes")
    return cleaned


def validate_tag(tag: str) -> str:
    """Normalize and validate an analyst-defined tag."""
    normalized = tag.strip().lower()
    if not normalized:
        raise ValueError("tag must not be empty")
    if len(normalized) > MAX_TAG_LENGTH:
        raise ValueError(f"tag must be at most {MAX_TAG_LENGTH} characters")
    if not _TAG_PATTERN.fullmatch(normalized):
        raise ValueError(
            "tag must start with a letter or digit and contain only "
            "lowercase letters, digits, '.', '_' or '-'"
        )
    return normalized


def validate_note_target(target_type: str) -> str:
    if target_type not in NOTE_TARGET_TYPES:
        raise ValueError(f"note target_type must be one of {', '.join(NOTE_TARGET_TYPES)}")
    return target_type


def validate_bookmark_target(target_type: str) -> str:
    if target_type not in BOOKMARK_TARGET_TYPES:
        raise ValueError(f"bookmark target_type must be one of {', '.join(BOOKMARK_TARGET_TYPES)}")
    return target_type


def validate_target_id(target_id: str) -> str:
    cleaned = target_id.strip()
    if not cleaned:
        raise ValueError("target_id must not be empty")
    if len(cleaned) > MAX_TARGET_ID_LENGTH:
        raise ValueError(f"target_id must be at most {MAX_TARGET_ID_LENGTH} characters")
    if _has_control_chars(cleaned) or any(ch.isspace() and ch not in (" ",) for ch in cleaned):
        raise ValueError("target_id must not contain control characters or whitespace")
    if "/" in cleaned or "\\" in cleaned or ".." in cleaned:
        raise ValueError("target_id must not contain path components")
    return cleaned


def validate_label(label: str) -> str:
    cleaned = label.strip()
    if len(cleaned) > MAX_LABEL_LENGTH:
        raise ValueError(f"label must be at most {MAX_LABEL_LENGTH} characters")
    if _has_control_chars(cleaned):
        raise ValueError("label must not contain control characters")
    return cleaned


def validate_bookmark_note(note: str) -> str:
    cleaned = note.strip()
    if len(cleaned) > MAX_BOOKMARK_NOTE_LENGTH:
        raise ValueError(f"bookmark note must be at most {MAX_BOOKMARK_NOTE_LENGTH} characters")
    if "\x00" in cleaned:
        raise ValueError("bookmark note must not contain NUL bytes")
    return cleaned


def validate_timeline_event(event_type: str) -> str:
    if event_type not in TIMELINE_EVENT_TYPES:
        raise ValueError(f"event_type must be one of {', '.join(TIMELINE_EVENT_TYPES)}")
    return event_type


def _case_from_row(row: sqlite3.Row) -> CaseRecord:
    return CaseRecord(
        case_id=row["case_id"],
        case_number=row["case_number"],
        title=row["title"],
        description=row["description"],
        status=row["status"],
        priority=row["priority"],
        created_at=_from_iso(row["created_at"]),
        updated_at=_from_iso(row["updated_at"]),
        closed_at=_from_iso(row["closed_at"]),
        schema_version=row["schema_version"],
    )


def _note_from_row(row: sqlite3.Row) -> NoteRecord:
    return NoteRecord(
        note_id=row["note_id"],
        case_id=row["case_id"],
        target_type=row["target_type"],
        target_id=row["target_id"],
        content=row["content"],
        created_at=_from_iso(row["created_at"]),
        updated_at=_from_iso(row["updated_at"]),
    )


def _bookmark_from_row(row: sqlite3.Row) -> BookmarkRecord:
    return BookmarkRecord(
        bookmark_id=row["bookmark_id"],
        case_id=row["case_id"],
        target_type=row["target_type"],
        target_id=row["target_id"],
        label=row["label"],
        note=row["note"],
        created_at=_from_iso(row["created_at"]),
    )


def _timeline_from_row(row: sqlite3.Row) -> TimelineEntry:
    raw_detail = row["detail"]
    try:
        parsed = json.loads(raw_detail)
        detail = {str(k): str(v) for k, v in parsed.items()} if isinstance(parsed, dict) else {}
    except (json.JSONDecodeError, AttributeError):
        detail = {}
    return TimelineEntry(
        entry_id=row["entry_id"],
        case_id=row["case_id"],
        event_type=row["event_type"],
        detail=detail,
        created_at=_from_iso(row["created_at"]),
    )


class CaseStore:
    """Persistence for case metadata; shares the registry database file."""

    def __init__(self, db_path: Path) -> None:
        self._db_path = db_path
        try:
            db_path.parent.mkdir(parents=True, exist_ok=True)
            with self._session() as connection:
                connection.executescript(_SCHEMA)
        except sqlite3.Error as error:
            raise CaptureStorageError(f"cannot initialize case store: {error}") from error

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

    # -- cases -----------------------------------------------------------

    def create_case(self, title: str, description: str, priority: str) -> CaseRecord:
        """Create a case with a fresh secure-random id."""
        clean_title = validate_title(title)
        clean_description = validate_description(description)
        clean_priority = validate_priority(priority)
        now = _now_iso()
        for _ in range(3):
            suffix = secrets.token_hex(8)
            case_id = f"case_{suffix}"
            case_number = f"CASE-{suffix[:8].upper()}"
            try:
                with self._session() as connection:
                    connection.execute(
                        "INSERT INTO cases (case_id, case_number, title, description, status,"
                        " priority, created_at, updated_at, closed_at, schema_version)"
                        " VALUES (?,?,?,?,?,?,?,?,?,?)",
                        (
                            case_id,
                            case_number,
                            clean_title,
                            clean_description,
                            "OPEN",
                            clean_priority,
                            now,
                            now,
                            None,
                            CASE_SCHEMA_VERSION,
                        ),
                    )
                    row = connection.execute(
                        "SELECT * FROM cases WHERE case_id = ?", (case_id,)
                    ).fetchone()
                if row is None:  # pragma: no cover - insert-then-read invariant
                    raise CaptureStorageError("case creation did not persist")
                return _case_from_row(row)
            except sqlite3.IntegrityError:
                continue  # id/number collision: retry with fresh randomness
            except sqlite3.Error as error:
                raise CaptureStorageError(f"cannot create case: {error}") from error
        raise CaptureStorageError("cannot create case: identifier collision")

    def get_case(self, case_id: str) -> CaseRecord | None:
        try:
            with self._session() as connection:
                row = connection.execute(
                    "SELECT * FROM cases WHERE case_id = ?", (case_id,)
                ).fetchone()
        except sqlite3.Error as error:
            raise CaptureStorageError(f"cannot load case: {error}") from error
        return _case_from_row(row) if row is not None else None

    def list_cases(self, status: str | None = None) -> list[CaseRecord]:
        if status is not None:
            validate_status(status)
        try:
            with self._session() as connection:
                if status is None:
                    rows = connection.execute("SELECT * FROM cases ORDER BY rowid DESC").fetchall()
                else:
                    rows = connection.execute(
                        "SELECT * FROM cases WHERE status = ? ORDER BY rowid DESC",
                        (status,),
                    ).fetchall()
        except sqlite3.Error as error:
            raise CaptureStorageError(f"cannot list cases: {error}") from error
        return [_case_from_row(row) for row in rows]

    def update_case(
        self,
        case_id: str,
        *,
        title: str | None = None,
        description: str | None = None,
        status: str | None = None,
        priority: str | None = None,
    ) -> CaseRecord | None:
        """Update analyst-controlled metadata; returns None when unknown."""
        current = self.get_case(case_id)
        if current is None:
            return None
        clean_title = validate_title(title) if title is not None else current.title
        clean_description = (
            validate_description(description) if description is not None else current.description
        )
        clean_status = validate_status(status) if status is not None else current.status
        clean_priority = validate_priority(priority) if priority is not None else current.priority
        now = _now_iso()
        if clean_status == "CLOSED" and current.status != "CLOSED":
            closed_at: str | None = now
        elif clean_status != "CLOSED":
            closed_at = None
        else:
            closed_at = current.closed_at.isoformat() if current.closed_at else now
        try:
            with self._session() as connection:
                connection.execute(
                    "UPDATE cases SET title = ?, description = ?, status = ?, priority = ?,"
                    " updated_at = ?, closed_at = ? WHERE case_id = ?",
                    (
                        clean_title,
                        clean_description,
                        clean_status,
                        clean_priority,
                        now,
                        closed_at,
                        case_id,
                    ),
                )
                row = connection.execute(
                    "SELECT * FROM cases WHERE case_id = ?", (case_id,)
                ).fetchone()
        except sqlite3.Error as error:
            raise CaptureStorageError(f"cannot update case: {error}") from error
        return _case_from_row(row) if row is not None else None

    def delete_case(self, case_id: str) -> bool:
        """Delete a case and all of its metadata; evidence is untouched."""
        try:
            with self._session() as connection:
                cursor = connection.execute("DELETE FROM cases WHERE case_id = ?", (case_id,))
                deleted = (cursor.rowcount or 0) > 0
                if deleted:
                    connection.execute("DELETE FROM case_captures WHERE case_id = ?", (case_id,))
                    connection.execute("DELETE FROM case_notes WHERE case_id = ?", (case_id,))
                    connection.execute("DELETE FROM case_tags WHERE case_id = ?", (case_id,))
                    connection.execute("DELETE FROM case_bookmarks WHERE case_id = ?", (case_id,))
                    connection.execute("DELETE FROM case_timeline WHERE case_id = ?", (case_id,))
                    connection.execute("DELETE FROM case_reports WHERE case_id = ?", (case_id,))
        except sqlite3.Error as error:
            raise CaptureStorageError(f"cannot delete case: {error}") from error
        return deleted

    # -- capture references ----------------------------------------------

    def attach_capture(self, case_id: str, capture_id: str) -> CaptureAttachment:
        """Reference a capture from a case; idempotent (re-attach is a no-op)."""
        now = _now_iso()
        try:
            with self._session() as connection:
                connection.execute(
                    "INSERT OR IGNORE INTO case_captures (case_id, capture_id, attached_at)"
                    " VALUES (?,?,?)",
                    (case_id, capture_id, now),
                )
                row = connection.execute(
                    "SELECT * FROM case_captures WHERE case_id = ? AND capture_id = ?",
                    (case_id, capture_id),
                ).fetchone()
        except sqlite3.Error as error:
            raise CaptureStorageError(f"cannot attach capture: {error}") from error
        if row is None:  # pragma: no cover - insert-then-read invariant
            raise CaptureStorageError("capture attachment did not persist")
        return CaptureAttachment(
            case_id=row["case_id"],
            capture_id=row["capture_id"],
            attached_at=_from_iso(row["attached_at"]),
        )

    def is_attached(self, case_id: str, capture_id: str) -> bool:
        try:
            with self._session() as connection:
                row = connection.execute(
                    "SELECT 1 FROM case_captures WHERE case_id = ? AND capture_id = ?",
                    (case_id, capture_id),
                ).fetchone()
        except sqlite3.Error as error:
            raise CaptureStorageError(f"cannot read case captures: {error}") from error
        return row is not None

    def detach_capture(self, case_id: str, capture_id: str) -> bool:
        try:
            with self._session() as connection:
                cursor = connection.execute(
                    "DELETE FROM case_captures WHERE case_id = ? AND capture_id = ?",
                    (case_id, capture_id),
                )
                deleted = (cursor.rowcount or 0) > 0
        except sqlite3.Error as error:
            raise CaptureStorageError(f"cannot detach capture: {error}") from error
        return deleted

    def list_attachments(self, case_id: str) -> list[CaptureAttachment]:
        try:
            with self._session() as connection:
                rows = connection.execute(
                    "SELECT * FROM case_captures WHERE case_id = ? ORDER BY rowid ASC",
                    (case_id,),
                ).fetchall()
        except sqlite3.Error as error:
            raise CaptureStorageError(f"cannot list case captures: {error}") from error
        return [
            CaptureAttachment(
                case_id=row["case_id"],
                capture_id=row["capture_id"],
                attached_at=_from_iso(row["attached_at"]),
            )
            for row in rows
        ]

    # -- notes -----------------------------------------------------------

    def add_note(self, case_id: str, target_type: str, target_id: str, content: str) -> NoteRecord:
        clean_target = validate_note_target(target_type)
        clean_target_id = validate_target_id(target_id)
        clean_content = validate_note_content(content)
        note_id = f"note_{secrets.token_hex(8)}"
        now = _now_iso()
        try:
            with self._session() as connection:
                connection.execute(
                    "INSERT INTO case_notes (note_id, case_id, target_type, target_id, content,"
                    " created_at, updated_at) VALUES (?,?,?,?,?,?,?)",
                    (note_id, case_id, clean_target, clean_target_id, clean_content, now, now),
                )
                row = connection.execute(
                    "SELECT * FROM case_notes WHERE note_id = ?", (note_id,)
                ).fetchone()
        except sqlite3.Error as error:
            raise CaptureStorageError(f"cannot create note: {error}") from error
        if row is None:  # pragma: no cover - insert-then-read invariant
            raise CaptureStorageError("note creation did not persist")
        return _note_from_row(row)

    def get_note(self, case_id: str, note_id: str) -> NoteRecord | None:
        """Fetch a note scoped to its case; cross-case access never resolves."""
        try:
            with self._session() as connection:
                row = connection.execute(
                    "SELECT * FROM case_notes WHERE note_id = ? AND case_id = ?",
                    (note_id, case_id),
                ).fetchone()
        except sqlite3.Error as error:
            raise CaptureStorageError(f"cannot load note: {error}") from error
        return _note_from_row(row) if row is not None else None

    def list_notes(self, case_id: str) -> list[NoteRecord]:
        try:
            with self._session() as connection:
                rows = connection.execute(
                    "SELECT * FROM case_notes WHERE case_id = ? ORDER BY rowid ASC",
                    (case_id,),
                ).fetchall()
        except sqlite3.Error as error:
            raise CaptureStorageError(f"cannot list notes: {error}") from error
        return [_note_from_row(row) for row in rows]

    def update_note(self, case_id: str, note_id: str, content: str) -> NoteRecord | None:
        clean_content = validate_note_content(content)
        try:
            with self._session() as connection:
                cursor = connection.execute(
                    "UPDATE case_notes SET content = ?, updated_at = ?"
                    " WHERE note_id = ? AND case_id = ?",
                    (clean_content, _now_iso(), note_id, case_id),
                )
                if (cursor.rowcount or 0) == 0:
                    return None
                row = connection.execute(
                    "SELECT * FROM case_notes WHERE note_id = ? AND case_id = ?",
                    (note_id, case_id),
                ).fetchone()
        except sqlite3.Error as error:
            raise CaptureStorageError(f"cannot update note: {error}") from error
        return _note_from_row(row) if row is not None else None

    def delete_note(self, case_id: str, note_id: str) -> bool:
        try:
            with self._session() as connection:
                cursor = connection.execute(
                    "DELETE FROM case_notes WHERE note_id = ? AND case_id = ?",
                    (note_id, case_id),
                )
                deleted = (cursor.rowcount or 0) > 0
        except sqlite3.Error as error:
            raise CaptureStorageError(f"cannot delete note: {error}") from error
        return deleted

    # -- tags ------------------------------------------------------------

    def add_tag(self, case_id: str, tag: str) -> str:
        """Add a tag; idempotent (re-adding is a no-op)."""
        normalized = validate_tag(tag)
        try:
            with self._session() as connection:
                count = connection.execute(
                    "SELECT COUNT(*) AS n FROM case_tags WHERE case_id = ?", (case_id,)
                ).fetchone()["n"]
                exists = connection.execute(
                    "SELECT 1 FROM case_tags WHERE case_id = ? AND tag = ?", (case_id, normalized)
                ).fetchone()
                if exists is None and int(count) >= MAX_TAGS_PER_CASE:
                    raise CaptureStorageError(f"case already has {MAX_TAGS_PER_CASE} tags")
                connection.execute(
                    "INSERT OR IGNORE INTO case_tags (case_id, tag, created_at) VALUES (?,?,?)",
                    (case_id, normalized, _now_iso()),
                )
        except sqlite3.Error as error:
            raise CaptureStorageError(f"cannot add tag: {error}") from error
        return normalized

    def remove_tag(self, case_id: str, tag: str) -> bool:
        normalized = validate_tag(tag)
        try:
            with self._session() as connection:
                cursor = connection.execute(
                    "DELETE FROM case_tags WHERE case_id = ? AND tag = ?", (case_id, normalized)
                )
                deleted = (cursor.rowcount or 0) > 0
        except sqlite3.Error as error:
            raise CaptureStorageError(f"cannot remove tag: {error}") from error
        return deleted

    def list_tags(self, case_id: str) -> list[str]:
        try:
            with self._session() as connection:
                rows = connection.execute(
                    "SELECT tag FROM case_tags WHERE case_id = ? ORDER BY tag ASC", (case_id,)
                ).fetchall()
        except sqlite3.Error as error:
            raise CaptureStorageError(f"cannot list tags: {error}") from error
        return [str(row["tag"]) for row in rows]

    # -- bookmarks -------------------------------------------------------

    def add_bookmark(
        self,
        case_id: str,
        target_type: str,
        target_id: str,
        label: str = "",
        note: str = "",
    ) -> BookmarkRecord:
        """Bookmark an evidence reference; duplicate references are idempotent."""
        clean_target = validate_bookmark_target(target_type)
        clean_target_id = validate_target_id(target_id)
        clean_label = validate_label(label)
        clean_note = validate_bookmark_note(note)
        try:
            with self._session() as connection:
                existing = connection.execute(
                    "SELECT * FROM case_bookmarks WHERE case_id = ? AND target_type = ?"
                    " AND target_id = ?",
                    (case_id, clean_target, clean_target_id),
                ).fetchone()
                if existing is not None:
                    return _bookmark_from_row(existing)
                bookmark_id = f"bookmark_{secrets.token_hex(8)}"
                connection.execute(
                    "INSERT INTO case_bookmarks (bookmark_id, case_id, target_type, target_id,"
                    " label, note, created_at) VALUES (?,?,?,?,?,?,?)",
                    (
                        bookmark_id,
                        case_id,
                        clean_target,
                        clean_target_id,
                        clean_label,
                        clean_note,
                        _now_iso(),
                    ),
                )
                row = connection.execute(
                    "SELECT * FROM case_bookmarks WHERE bookmark_id = ?", (bookmark_id,)
                ).fetchone()
        except sqlite3.Error as error:
            raise CaptureStorageError(f"cannot create bookmark: {error}") from error
        if row is None:  # pragma: no cover - insert-then-read invariant
            raise CaptureStorageError("bookmark creation did not persist")
        return _bookmark_from_row(row)

    def get_bookmark(self, case_id: str, bookmark_id: str) -> BookmarkRecord | None:
        try:
            with self._session() as connection:
                row = connection.execute(
                    "SELECT * FROM case_bookmarks WHERE bookmark_id = ? AND case_id = ?",
                    (bookmark_id, case_id),
                ).fetchone()
        except sqlite3.Error as error:
            raise CaptureStorageError(f"cannot load bookmark: {error}") from error
        return _bookmark_from_row(row) if row is not None else None

    def list_bookmarks(self, case_id: str) -> list[BookmarkRecord]:
        try:
            with self._session() as connection:
                rows = connection.execute(
                    "SELECT * FROM case_bookmarks WHERE case_id = ? ORDER BY rowid ASC",
                    (case_id,),
                ).fetchall()
        except sqlite3.Error as error:
            raise CaptureStorageError(f"cannot list bookmarks: {error}") from error
        return [_bookmark_from_row(row) for row in rows]

    def delete_bookmark(self, case_id: str, bookmark_id: str) -> bool:
        try:
            with self._session() as connection:
                cursor = connection.execute(
                    "DELETE FROM case_bookmarks WHERE bookmark_id = ? AND case_id = ?",
                    (bookmark_id, case_id),
                )
                deleted = (cursor.rowcount or 0) > 0
        except sqlite3.Error as error:
            raise CaptureStorageError(f"cannot delete bookmark: {error}") from error
        return deleted

    # -- investigation timeline ------------------------------------------

    def append_timeline(
        self, case_id: str, event_type: str, detail: dict[str, str] | None = None
    ) -> TimelineEntry:
        """Append an analyst-action event; the timeline is append-only."""
        clean_event = validate_timeline_event(event_type)
        clean_detail = {str(k): str(v) for k, v in (detail or {}).items()}
        entry_id = f"timeline_{secrets.token_hex(8)}"
        now = _now_iso()
        try:
            with self._session() as connection:
                connection.execute(
                    "INSERT INTO case_timeline (entry_id, case_id, event_type, detail, created_at)"
                    " VALUES (?,?,?,?,?)",
                    (entry_id, case_id, clean_event, json.dumps(clean_detail), now),
                )
                row = connection.execute(
                    "SELECT * FROM case_timeline WHERE entry_id = ?", (entry_id,)
                ).fetchone()
        except sqlite3.Error as error:
            raise CaptureStorageError(f"cannot append timeline event: {error}") from error
        if row is None:  # pragma: no cover - insert-then-read invariant
            raise CaptureStorageError("timeline event did not persist")
        return _timeline_from_row(row)

    def list_timeline(self, case_id: str) -> list[TimelineEntry]:
        # Insertion order (rowid), not wall-clock: coarse host clocks can
        # stamp consecutive events identically, but the log is append-only
        # and must read back in append order.
        try:
            with self._session() as connection:
                rows = connection.execute(
                    "SELECT * FROM case_timeline WHERE case_id = ? ORDER BY rowid ASC",
                    (case_id,),
                ).fetchall()
        except sqlite3.Error as error:
            raise CaptureStorageError(f"cannot list timeline: {error}") from error
        return [_timeline_from_row(row) for row in rows]

    # -- report history --------------------------------------------------

    def record_report(
        self, case_id: str, report_format: str, evidence_digest: str
    ) -> dict[str, str]:
        """Record that a case report was generated (metadata only, no blob)."""
        if report_format not in ("json", "html", "pdf"):
            raise ValueError("report format must be one of json, html, pdf")
        report_id = f"casereport_{secrets.token_hex(8)}"
        now = _now_iso()
        try:
            with self._session() as connection:
                connection.execute(
                    "INSERT INTO case_reports (report_id, case_id, format, generated_at,"
                    " evidence_digest) VALUES (?,?,?,?,?)",
                    (report_id, case_id, report_format, now, evidence_digest[:128]),
                )
        except sqlite3.Error as error:
            raise CaptureStorageError(f"cannot record report: {error}") from error
        return {"report_id": report_id, "generated_at": now}

    def list_reports(self, case_id: str) -> list[dict[str, str]]:
        try:
            with self._session() as connection:
                rows = connection.execute(
                    "SELECT * FROM case_reports WHERE case_id = ? ORDER BY rowid ASC",
                    (case_id,),
                ).fetchall()
        except sqlite3.Error as error:
            raise CaptureStorageError(f"cannot list reports: {error}") from error
        return [dict(row) for row in rows]
