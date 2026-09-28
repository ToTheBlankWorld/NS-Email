"""Remediation workflow persistence (Stage 13).

Remediation records are analyst workflow state layered over immutable
forensic findings — they describe what was planned and done about a
finding, never what the finding was. Findings, sessions, posture, and
graphs are never written here; verification records quote later
evidence without mutating earlier results.

Identifiers are secure random values (``rem_`` / ``verif_`` /
``remtime_`` + 16 hex digits), never sequential. Timelines read back
in database insertion order (rowid), which stays authoritative where
event order matters.
"""

import json
import re
import secrets
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from pathlib import Path

from engine.ingestion.errors import CaptureStorageError

from app.case_store import MAX_TARGET_ID_LENGTH, validate_priority, validate_target_id

REMEDIATION_ID_PATTERN = re.compile(r"^rem_[0-9a-f]{16}$")
VERIFICATION_ID_PATTERN = re.compile(r"^verif_[0-9a-f]{16}$")
REMTIME_ID_PATTERN = re.compile(r"^remtime_[0-9a-f]{16}$")

REMEDIATION_STATUSES: tuple[str, ...] = (
    "OPEN",
    "PLANNED",
    "IN_PROGRESS",
    "BLOCKED",
    "COMPLETED",
    "CANCELLED",
)

# Explicit state machine: nonsensical transitions are rejected.
# Completed and cancelled remediations are terminal but retain history.
REMEDIATION_TRANSITIONS: dict[str, tuple[str, ...]] = {
    "OPEN": ("PLANNED", "CANCELLED"),
    "PLANNED": ("IN_PROGRESS", "CANCELLED"),
    "IN_PROGRESS": ("BLOCKED", "COMPLETED", "CANCELLED"),
    "BLOCKED": ("IN_PROGRESS", "CANCELLED"),
    "COMPLETED": (),
    "CANCELLED": (),
}

VERIFICATION_STATUSES: tuple[str, ...] = (
    "NOT_VERIFIED",
    "PENDING",
    "VERIFIED",
    "FAILED",
    "INCONCLUSIVE",
)

REMEDIATION_TARGET_TYPES: tuple[str, ...] = (
    "finding",
    "session",
    "host",
    "certificate",
    "tls_configuration",
    "case",
)

REMEDIATION_TIMELINE_EVENTS: tuple[str, ...] = (
    "remediation_created",
    "status_changed",
    "owner_changed",
    "priority_changed",
    "note_added",
    "verification_requested",
    "verification_completed",
    "verification_failed",
)

MAX_TITLE_LENGTH = 200
MAX_DESCRIPTION_LENGTH = 5000
MAX_ACTION_LENGTH = 2000
MAX_OWNER_LENGTH = 128
MAX_NOTE_LENGTH = 10000
MAX_REMEDIATIONS_PER_CASE = 500

_HOST_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.\-]{0,253}$")
_FINGERPRINT_PATTERN = re.compile(r"^[0-9a-f]{32,128}$")
_TLS_CONFIG_PATTERN = re.compile(r"^tlscfg_[0-9a-f]{12}$")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS remediations (
    remediation_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
    target_type TEXT NOT NULL,
    target_id TEXT NOT NULL,
    rule_id TEXT,
    title TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    recommended_action TEXT NOT NULL DEFAULT '',
    recommended_action_source TEXT NOT NULL DEFAULT 'analyst',
    status TEXT NOT NULL,
    priority TEXT NOT NULL,
    owner TEXT NOT NULL DEFAULT '',
    due_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    completed_at TEXT,
    verification_status TEXT NOT NULL DEFAULT 'NOT_VERIFIED',
    verification_capture_id TEXT,
    verification_method TEXT
);
CREATE INDEX IF NOT EXISTS idx_remediations_case ON remediations(case_id);
CREATE TABLE IF NOT EXISTS remediation_timeline (
    entry_id TEXT PRIMARY KEY,
    remediation_id TEXT NOT NULL,
    case_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    detail TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_remediation_timeline_rem ON remediation_timeline(remediation_id);
CREATE TABLE IF NOT EXISTS verifications (
    verification_id TEXT PRIMARY KEY,
    remediation_id TEXT NOT NULL,
    case_id TEXT NOT NULL,
    method TEXT NOT NULL,
    baseline_capture_id TEXT NOT NULL DEFAULT '',
    baseline_session_id TEXT,
    rule_id TEXT NOT NULL DEFAULT '',
    verification_capture_id TEXT,
    result TEXT NOT NULL,
    comparison TEXT NOT NULL DEFAULT '{}',
    notes TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    completed_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_verifications_rem ON verifications(remediation_id);
"""


@dataclass(frozen=True, slots=True)
class RemediationRecord:
    """One analyst-controlled remediation plan for a finding or target."""

    remediation_id: str
    case_id: str
    target_type: str
    target_id: str
    rule_id: str | None = None
    title: str = ""
    description: str = ""
    recommended_action: str = ""
    recommended_action_source: str = "analyst"
    status: str = "OPEN"
    priority: str = "MEDIUM"
    owner: str = ""
    due_at: str | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None
    completed_at: datetime | None = None
    verification_status: str = "NOT_VERIFIED"
    verification_capture_id: str | None = None
    verification_method: str | None = None


@dataclass(frozen=True, slots=True)
class RemediationTimelineEntry:
    """One remediation workflow event in insertion order."""

    entry_id: str
    remediation_id: str
    case_id: str
    event_type: str
    detail: dict[str, str] = field(default_factory=dict)
    created_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class VerificationRecord:
    """One verification attempt: evidence comparison or asserted note."""

    verification_id: str
    remediation_id: str
    case_id: str
    method: str
    baseline_capture_id: str = ""
    baseline_session_id: str | None = None
    rule_id: str = ""
    verification_capture_id: str | None = None
    result: str = "PENDING"
    comparison: dict[str, object] = field(default_factory=dict)
    notes: str = ""
    created_at: datetime | None = None
    completed_at: datetime | None = None


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


def validate_remediation_status(status: str) -> str:
    if status not in REMEDIATION_STATUSES:
        raise ValueError(f"status must be one of {', '.join(REMEDIATION_STATUSES)}")
    return status


def validate_transition(from_status: str, to_status: str) -> str:
    """Validate a status transition; returns the target status."""
    validate_remediation_status(from_status)
    validate_remediation_status(to_status)
    if to_status not in REMEDIATION_TRANSITIONS[from_status]:
        allowed = ", ".join(REMEDIATION_TRANSITIONS[from_status]) or "(terminal — no transitions)"
        raise ValueError(f"cannot transition from {from_status} to {to_status}; allowed: {allowed}")
    return to_status


def validate_verification_status(status: str) -> str:
    if status not in VERIFICATION_STATUSES:
        raise ValueError(f"verification status must be one of {', '.join(VERIFICATION_STATUSES)}")
    return status


def validate_remediation_target(target_type: str) -> str:
    if target_type not in REMEDIATION_TARGET_TYPES:
        raise ValueError(
            f"remediation target_type must be one of {', '.join(REMEDIATION_TARGET_TYPES)}"
        )
    return target_type


def validate_remediation_target_id(target_type: str, target_id: str) -> str:
    """Shape-validate a remediation target id (existence checked by the service)."""
    cleaned = validate_target_id(target_id)
    if target_type == "host":
        candidate = cleaned.lower().rstrip(".")
        if not _HOST_PATTERN.fullmatch(candidate):
            # Fall back to IP canonicalization for literal addresses.
            import ipaddress

            try:
                ipaddress.ip_address(cleaned)
            except ValueError as error:
                raise ValueError("host target must be a hostname or IP address") from error
    elif target_type == "certificate":
        candidate = cleaned.lower().replace(":", "").replace(" ", "")
        if not _FINGERPRINT_PATTERN.fullmatch(candidate):
            raise ValueError("certificate target must be a hex fingerprint")
    elif target_type == "tls_configuration":
        if not _TLS_CONFIG_PATTERN.fullmatch(cleaned):
            raise ValueError("TLS configuration target must be a tlscfg_ fingerprint")
    return cleaned


def validate_title(title: str) -> str:
    cleaned = title.strip()
    if not cleaned:
        raise ValueError("title must not be empty")
    if len(cleaned) > MAX_TITLE_LENGTH:
        raise ValueError(f"title must be at most {MAX_TITLE_LENGTH} characters")
    if _has_control_chars(cleaned):
        raise ValueError("title must not contain control characters")
    return cleaned


def validate_description(description: str) -> str:
    cleaned = description.strip()
    if len(cleaned) > MAX_DESCRIPTION_LENGTH:
        raise ValueError(f"description must be at most {MAX_DESCRIPTION_LENGTH} characters")
    if _has_control_chars(cleaned):
        raise ValueError("description must not contain control characters")
    return cleaned


def validate_action(action: str) -> str:
    cleaned = action.strip()
    if len(cleaned) > MAX_ACTION_LENGTH:
        raise ValueError(f"recommended action must be at most {MAX_ACTION_LENGTH} characters")
    if "\x00" in cleaned:
        raise ValueError("recommended action must not contain NUL bytes")
    return cleaned


def validate_owner(owner: str) -> str:
    """Free-form display name / team / identifier — workflow metadata only."""
    cleaned = owner.strip()
    if len(cleaned) > MAX_OWNER_LENGTH:
        raise ValueError(f"owner must be at most {MAX_OWNER_LENGTH} characters")
    if _has_control_chars(cleaned):
        raise ValueError("owner must not contain control characters")
    return cleaned


def validate_due_date(due_at: str | None) -> str | None:
    if due_at is None:
        return None
    cleaned = due_at.strip()
    if not cleaned:
        return None
    try:
        parsed = date.fromisoformat(cleaned)
    except ValueError as error:
        raise ValueError("due date must use YYYY-MM-DD format") from error
    return parsed.isoformat()


def validate_verification_notes(notes: str) -> str:
    cleaned = notes.strip()
    if len(cleaned) > MAX_NOTE_LENGTH:
        raise ValueError(f"verification notes must be at most {MAX_NOTE_LENGTH} characters")
    if "\x00" in cleaned:
        raise ValueError("verification notes must not contain NUL bytes")
    return cleaned


def _remediation_from_row(row: sqlite3.Row) -> RemediationRecord:
    return RemediationRecord(
        remediation_id=row["remediation_id"],
        case_id=row["case_id"],
        target_type=row["target_type"],
        target_id=row["target_id"],
        rule_id=row["rule_id"],
        title=row["title"],
        description=row["description"],
        recommended_action=row["recommended_action"],
        recommended_action_source=row["recommended_action_source"],
        status=row["status"],
        priority=row["priority"],
        owner=row["owner"],
        due_at=row["due_at"],
        created_at=_from_iso(row["created_at"]),
        updated_at=_from_iso(row["updated_at"]),
        completed_at=_from_iso(row["completed_at"]),
        verification_status=row["verification_status"],
        verification_capture_id=row["verification_capture_id"],
        verification_method=row["verification_method"],
    )


def _timeline_from_row(row: sqlite3.Row) -> RemediationTimelineEntry:
    raw_detail = row["detail"]
    try:
        parsed = json.loads(raw_detail)
        detail = {str(k): str(v) for k, v in parsed.items()} if isinstance(parsed, dict) else {}
    except (json.JSONDecodeError, AttributeError):
        detail = {}
    return RemediationTimelineEntry(
        entry_id=row["entry_id"],
        remediation_id=row["remediation_id"],
        case_id=row["case_id"],
        event_type=row["event_type"],
        detail=detail,
        created_at=_from_iso(row["created_at"]),
    )


def _verification_from_row(row: sqlite3.Row) -> VerificationRecord:
    raw_comparison = row["comparison"]
    try:
        parsed = json.loads(raw_comparison)
        comparison = dict(parsed) if isinstance(parsed, dict) else {}
    except (json.JSONDecodeError, AttributeError):
        comparison = {}
    return VerificationRecord(
        verification_id=row["verification_id"],
        remediation_id=row["remediation_id"],
        case_id=row["case_id"],
        method=row["method"],
        baseline_capture_id=row["baseline_capture_id"],
        baseline_session_id=row["baseline_session_id"],
        rule_id=row["rule_id"],
        verification_capture_id=row["verification_capture_id"],
        result=row["result"],
        comparison=comparison,
        notes=row["notes"],
        created_at=_from_iso(row["created_at"]),
        completed_at=_from_iso(row["completed_at"]),
    )


class RemediationStore:
    """Persistence for remediation workflow state; shares the registry database file."""

    def __init__(self, db_path: Path) -> None:
        self._db_path = db_path
        try:
            db_path.parent.mkdir(parents=True, exist_ok=True)
            with self._session() as connection:
                connection.executescript(_SCHEMA)
        except sqlite3.Error as error:
            raise CaptureStorageError(f"cannot initialize remediation store: {error}") from error

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

    # -- remediations --------------------------------------------------------

    def create_remediation(
        self,
        case_id: str,
        target_type: str,
        target_id: str,
        title: str,
        description: str = "",
        recommended_action: str = "",
        recommended_action_source: str = "analyst",
        rule_id: str | None = None,
        priority: str = "MEDIUM",
        owner: str = "",
        due_at: str | None = None,
    ) -> RemediationRecord:
        """Create a remediation with a fresh secure-random id."""
        clean_target = validate_remediation_target(target_type)
        clean_target_id = validate_remediation_target_id(clean_target, target_id)
        clean_title = validate_title(title)
        clean_description = validate_description(description)
        clean_action = validate_action(recommended_action)
        clean_priority = validate_priority(priority)
        clean_owner = validate_owner(owner)
        clean_due = validate_due_date(due_at)
        if recommended_action_source not in ("policy", "analyst"):
            raise ValueError("recommended action source must be policy or analyst")
        if rule_id is not None and (
            not rule_id.strip()
            or len(rule_id) > MAX_TARGET_ID_LENGTH
            or _has_control_chars(rule_id)
        ):
            raise ValueError("rule id must be a non-empty identifier")
        remediation_id = f"rem_{secrets.token_hex(8)}"
        now = _now_iso()
        try:
            with self._session() as connection:
                existing = connection.execute(
                    "SELECT COUNT(*) AS n FROM remediations WHERE case_id = ?", (case_id,)
                ).fetchone()["n"]
                if int(existing) >= MAX_REMEDIATIONS_PER_CASE:
                    raise CaptureStorageError(
                        f"case already has {MAX_REMEDIATIONS_PER_CASE} remediations"
                    )
                connection.execute(
                    "INSERT INTO remediations (remediation_id, case_id, target_type, target_id,"
                    " rule_id, title, description, recommended_action, recommended_action_source,"
                    " status, priority, owner, due_at, created_at, updated_at, completed_at,"
                    " verification_status, verification_capture_id, verification_method)"
                    " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        remediation_id,
                        case_id,
                        clean_target,
                        clean_target_id,
                        rule_id.strip() if rule_id else None,
                        clean_title,
                        clean_description,
                        clean_action,
                        recommended_action_source,
                        "OPEN",
                        clean_priority,
                        clean_owner,
                        clean_due,
                        now,
                        now,
                        None,
                        "NOT_VERIFIED",
                        None,
                        None,
                    ),
                )
                row = connection.execute(
                    "SELECT * FROM remediations WHERE remediation_id = ?", (remediation_id,)
                ).fetchone()
        except sqlite3.Error as error:
            raise CaptureStorageError(f"cannot create remediation: {error}") from error
        if row is None:  # pragma: no cover - insert-then-read invariant
            raise CaptureStorageError("remediation creation did not persist")
        return _remediation_from_row(row)

    def import_remediation(
        self,
        case_id: str,
        target_type: str,
        target_id: str,
        title: str,
        description: str,
        recommended_action: str,
        priority: str,
        status: str,
        owner: str,
        due_at: str | None,
        rule_id: str | None,
    ) -> RemediationRecord:
        """Insert an imported remediation with its workflow status intact.

        Verification state is always reset (NOT_VERIFIED): verification
        results reference captures that may differ locally and must be
        re-run. No timeline is replayed.
        """
        clean_target = validate_remediation_target(target_type)
        clean_target_id = validate_remediation_target_id(clean_target, target_id)
        clean_status = validate_remediation_status(status)
        remediation_id = f"rem_{secrets.token_hex(8)}"
        now = _now_iso()
        try:
            with self._session() as connection:
                connection.execute(
                    "INSERT INTO remediations (remediation_id, case_id, target_type, target_id,"
                    " rule_id, title, description, recommended_action, recommended_action_source,"
                    " status, priority, owner, due_at, created_at, updated_at, completed_at,"
                    " verification_status, verification_capture_id, verification_method)"
                    " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        remediation_id,
                        case_id,
                        clean_target,
                        clean_target_id,
                        rule_id,
                        validate_title(title),
                        validate_description(description),
                        validate_action(recommended_action),
                        "analyst",
                        clean_status,
                        validate_priority(priority),
                        validate_owner(owner),
                        validate_due_date(due_at),
                        now,
                        now,
                        None,
                        "NOT_VERIFIED",
                        None,
                        None,
                    ),
                )
                row = connection.execute(
                    "SELECT * FROM remediations WHERE remediation_id = ?", (remediation_id,)
                ).fetchone()
        except sqlite3.Error as error:
            raise CaptureStorageError(f"cannot import remediation: {error}") from error
        if row is None:  # pragma: no cover - insert-then-read invariant
            raise CaptureStorageError("remediation import did not persist")
        return _remediation_from_row(row)

    def get_remediation(self, case_id: str, remediation_id: str) -> RemediationRecord | None:
        """Fetch a remediation scoped to its case; cross-case access never resolves."""
        try:
            with self._session() as connection:
                row = connection.execute(
                    "SELECT * FROM remediations WHERE remediation_id = ? AND case_id = ?",
                    (remediation_id, case_id),
                ).fetchone()
        except sqlite3.Error as error:
            raise CaptureStorageError(f"cannot load remediation: {error}") from error
        return _remediation_from_row(row) if row is not None else None

    def list_remediations(self, case_id: str) -> list[RemediationRecord]:
        try:
            with self._session() as connection:
                rows = connection.execute(
                    "SELECT * FROM remediations WHERE case_id = ? ORDER BY rowid ASC",
                    (case_id,),
                ).fetchall()
        except sqlite3.Error as error:
            raise CaptureStorageError(f"cannot list remediations: {error}") from error
        return [_remediation_from_row(row) for row in rows]

    def list_for_finding(self, case_id: str, finding_id: str) -> list[RemediationRecord]:
        """Remediations targeting one finding within a case."""
        try:
            with self._session() as connection:
                rows = connection.execute(
                    "SELECT * FROM remediations WHERE case_id = ? AND target_type = 'finding'"
                    " AND target_id = ? ORDER BY rowid ASC",
                    (case_id, finding_id),
                ).fetchall()
        except sqlite3.Error as error:
            raise CaptureStorageError(f"cannot list remediations: {error}") from error
        return [_remediation_from_row(row) for row in rows]

    def update_remediation(
        self,
        case_id: str,
        remediation_id: str,
        *,
        title: str | None = None,
        description: str | None = None,
        recommended_action: str | None = None,
        priority: str | None = None,
        owner: str | None = None,
        due_at: str | None = None,
        status: str | None = None,
    ) -> RemediationRecord | None:
        """Update workflow metadata; status moves go through the state machine."""
        current = self.get_remediation(case_id, remediation_id)
        if current is None:
            return None
        clean_title = validate_title(title) if title is not None else current.title
        clean_description = (
            validate_description(description) if description is not None else current.description
        )
        clean_action = (
            validate_action(recommended_action)
            if recommended_action is not None
            else current.recommended_action
        )
        clean_priority = validate_priority(priority) if priority is not None else current.priority
        clean_owner = validate_owner(owner) if owner is not None else current.owner
        clean_due = validate_due_date(due_at) if due_at is not None else current.due_at
        clean_status = current.status
        if status is not None and status != current.status:
            clean_status = validate_transition(current.status, status)
        now = _now_iso()
        completed_at = current.completed_at.isoformat() if current.completed_at else None
        if clean_status == "COMPLETED" and current.status != "COMPLETED":
            completed_at = now
        try:
            with self._session() as connection:
                connection.execute(
                    "UPDATE remediations SET title = ?, description = ?, recommended_action = ?,"
                    " priority = ?, owner = ?, due_at = ?, status = ?, updated_at = ?,"
                    " completed_at = ? WHERE remediation_id = ? AND case_id = ?",
                    (
                        clean_title,
                        clean_description,
                        clean_action,
                        clean_priority,
                        clean_owner,
                        clean_due,
                        clean_status,
                        now,
                        completed_at,
                        remediation_id,
                        case_id,
                    ),
                )
                row = connection.execute(
                    "SELECT * FROM remediations WHERE remediation_id = ? AND case_id = ?",
                    (remediation_id, case_id),
                ).fetchone()
        except sqlite3.Error as error:
            raise CaptureStorageError(f"cannot update remediation: {error}") from error
        return _remediation_from_row(row) if row is not None else None

    def set_verification_state(
        self,
        case_id: str,
        remediation_id: str,
        verification_status: str,
        verification_capture_id: str | None,
        verification_method: str | None,
    ) -> RemediationRecord | None:
        """Record the latest verification outcome on the remediation."""
        validate_verification_status(verification_status)
        try:
            with self._session() as connection:
                cursor = connection.execute(
                    "UPDATE remediations SET verification_status = ?, verification_capture_id = ?,"
                    " verification_method = ?, updated_at = ?"
                    " WHERE remediation_id = ? AND case_id = ?",
                    (
                        verification_status,
                        verification_capture_id,
                        verification_method,
                        _now_iso(),
                        remediation_id,
                        case_id,
                    ),
                )
                if (cursor.rowcount or 0) == 0:
                    return None
                row = connection.execute(
                    "SELECT * FROM remediations WHERE remediation_id = ? AND case_id = ?",
                    (remediation_id, case_id),
                ).fetchone()
        except sqlite3.Error as error:
            raise CaptureStorageError(f"cannot update verification state: {error}") from error
        return _remediation_from_row(row) if row is not None else None

    def delete_remediation(self, case_id: str, remediation_id: str) -> bool:
        """Delete a remediation and its workflow history; evidence is untouched."""
        try:
            with self._session() as connection:
                cursor = connection.execute(
                    "DELETE FROM remediations WHERE remediation_id = ? AND case_id = ?",
                    (remediation_id, case_id),
                )
                deleted = (cursor.rowcount or 0) > 0
                if deleted:
                    connection.execute(
                        "DELETE FROM remediation_timeline WHERE remediation_id = ? AND case_id = ?",
                        (remediation_id, case_id),
                    )
                    connection.execute(
                        "DELETE FROM verifications WHERE remediation_id = ? AND case_id = ?",
                        (remediation_id, case_id),
                    )
        except sqlite3.Error as error:
            raise CaptureStorageError(f"cannot delete remediation: {error}") from error
        return deleted

    # -- remediation timeline ------------------------------------------------

    def append_timeline(
        self,
        case_id: str,
        remediation_id: str,
        event_type: str,
        detail: dict[str, str] | None = None,
    ) -> RemediationTimelineEntry:
        """Append a workflow event; insertion order is authoritative."""
        if event_type not in REMEDIATION_TIMELINE_EVENTS:
            raise ValueError(f"event_type must be one of {', '.join(REMEDIATION_TIMELINE_EVENTS)}")
        clean_detail = {str(k): str(v) for k, v in (detail or {}).items()}
        entry_id = f"remtime_{secrets.token_hex(8)}"
        now = _now_iso()
        try:
            with self._session() as connection:
                connection.execute(
                    "INSERT INTO remediation_timeline (entry_id, remediation_id, case_id,"
                    " event_type, detail, created_at) VALUES (?,?,?,?,?,?)",
                    (entry_id, remediation_id, case_id, event_type, json.dumps(clean_detail), now),
                )
                row = connection.execute(
                    "SELECT * FROM remediation_timeline WHERE entry_id = ?", (entry_id,)
                ).fetchone()
        except sqlite3.Error as error:
            raise CaptureStorageError(f"cannot append remediation timeline: {error}") from error
        if row is None:  # pragma: no cover - insert-then-read invariant
            raise CaptureStorageError("remediation timeline event did not persist")
        return _timeline_from_row(row)

    def list_timeline(self, case_id: str, remediation_id: str) -> list[RemediationTimelineEntry]:
        try:
            with self._session() as connection:
                rows = connection.execute(
                    "SELECT * FROM remediation_timeline WHERE remediation_id = ? AND case_id = ?"
                    " ORDER BY rowid ASC",
                    (remediation_id, case_id),
                ).fetchall()
        except sqlite3.Error as error:
            raise CaptureStorageError(f"cannot list remediation timeline: {error}") from error
        return [_timeline_from_row(row) for row in rows]

    # -- verifications ---------------------------------------------------------

    def create_verification(
        self,
        case_id: str,
        remediation_id: str,
        method: str,
        baseline_capture_id: str = "",
        baseline_session_id: str | None = None,
        rule_id: str = "",
        verification_capture_id: str | None = None,
        result: str = "PENDING",
        comparison: dict[str, object] | None = None,
        notes: str = "",
        completed: bool = False,
    ) -> VerificationRecord:
        """Record one verification attempt (history is append-only)."""
        if method not in ("evidence", "analyst_asserted"):
            raise ValueError("verification method must be evidence or analyst_asserted")
        validate_verification_status(result)
        clean_notes = validate_verification_notes(notes)
        verification_id = f"verif_{secrets.token_hex(8)}"
        now = _now_iso()
        try:
            with self._session() as connection:
                connection.execute(
                    "INSERT INTO verifications (verification_id, remediation_id, case_id, method,"
                    " baseline_capture_id, baseline_session_id, rule_id, verification_capture_id,"
                    " result, comparison, notes, created_at, completed_at)"
                    " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        verification_id,
                        remediation_id,
                        case_id,
                        method,
                        baseline_capture_id,
                        baseline_session_id,
                        rule_id,
                        verification_capture_id,
                        result,
                        json.dumps(comparison or {}),
                        clean_notes,
                        now,
                        now if completed else None,
                    ),
                )
                row = connection.execute(
                    "SELECT * FROM verifications WHERE verification_id = ?", (verification_id,)
                ).fetchone()
        except sqlite3.Error as error:
            raise CaptureStorageError(f"cannot create verification: {error}") from error
        if row is None:  # pragma: no cover - insert-then-read invariant
            raise CaptureStorageError("verification creation did not persist")
        return _verification_from_row(row)

    def get_verification(
        self, case_id: str, remediation_id: str, verification_id: str
    ) -> VerificationRecord | None:
        try:
            with self._session() as connection:
                row = connection.execute(
                    "SELECT * FROM verifications WHERE verification_id = ?"
                    " AND remediation_id = ? AND case_id = ?",
                    (verification_id, remediation_id, case_id),
                ).fetchone()
        except sqlite3.Error as error:
            raise CaptureStorageError(f"cannot load verification: {error}") from error
        return _verification_from_row(row) if row is not None else None

    def list_verifications(self, case_id: str, remediation_id: str) -> list[VerificationRecord]:
        try:
            with self._session() as connection:
                rows = connection.execute(
                    "SELECT * FROM verifications WHERE remediation_id = ? AND case_id = ?"
                    " ORDER BY rowid ASC",
                    (remediation_id, case_id),
                ).fetchall()
        except sqlite3.Error as error:
            raise CaptureStorageError(f"cannot list verifications: {error}") from error
        return [_verification_from_row(row) for row in rows]

    def complete_verification(
        self, case_id: str, remediation_id: str, verification_id: str, notes: str
    ) -> VerificationRecord | None:
        """Complete a pending manual verification with analyst notes."""
        clean_notes = validate_verification_notes(notes)
        if not clean_notes:
            raise ValueError("completing a manual verification requires notes")
        try:
            with self._session() as connection:
                cursor = connection.execute(
                    "UPDATE verifications SET result = 'VERIFIED', notes = ?, completed_at = ?"
                    " WHERE verification_id = ? AND remediation_id = ? AND case_id = ?"
                    " AND result = 'PENDING'",
                    (clean_notes, _now_iso(), verification_id, remediation_id, case_id),
                )
                if (cursor.rowcount or 0) == 0:
                    return None
                row = connection.execute(
                    "SELECT * FROM verifications WHERE verification_id = ?", (verification_id,)
                ).fetchone()
        except sqlite3.Error as error:
            raise CaptureStorageError(f"cannot complete verification: {error}") from error
        return _verification_from_row(row) if row is not None else None
