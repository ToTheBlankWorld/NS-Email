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
from typing import Any, Protocol

from engine.core.certificate import CertificateEvidence
from engine.core.events import EventDirection, EventType, SessionEvent
from engine.core.findings import (
    EvidenceRef,
    FindingCategory,
    FindingSeverity,
    Remediation,
    SecurityFinding,
    StandardReference,
)
from engine.core.session import (
    Confidence,
    EmailProtocol,
    Orientation,
    Session,
    StarttlsObservation,
)
from engine.core.tls import TLSHandshake
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
    warnings TEXT NOT NULL DEFAULT '[]',
    tls_handshake TEXT
);
CREATE TABLE IF NOT EXISTS session_certificates (
    id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    position_in_chain INTEGER,
    subject TEXT NOT NULL,
    issuer TEXT NOT NULL,
    serial_number TEXT NOT NULL,
    not_before TEXT,
    not_after TEXT,
    signature_algorithm TEXT NOT NULL,
    public_key_algorithm TEXT,
    public_key_size_bits INTEGER,
    subject_alternative_names TEXT NOT NULL DEFAULT '[]',
    fingerprint_sha256 TEXT NOT NULL,
    PRIMARY KEY (id, session_id)
);
CREATE INDEX IF NOT EXISTS idx_certificates_session ON session_certificates(session_id);
CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    capture_id TEXT NOT NULL,
    session_id TEXT,
    protocol TEXT,
    rule_id TEXT NOT NULL,
    severity TEXT NOT NULL,
    confidence TEXT NOT NULL,
    category TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    observed_value TEXT,
    expected_value TEXT,
    remediation TEXT,
    standard_reference TEXT,
    evidence_refs TEXT NOT NULL DEFAULT '[]',
    first_packet INTEGER,
    last_packet INTEGER,
    details TEXT NOT NULL DEFAULT '{}',
    detected_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_findings_capture ON findings(capture_id);
CREATE INDEX IF NOT EXISTS idx_findings_session ON findings(session_id);
CREATE TABLE IF NOT EXISTS anomaly_models (
    model_id TEXT PRIMARY KEY,
    capture_id TEXT NOT NULL,
    algorithm TEXT NOT NULL,
    feature_schema_version TEXT NOT NULL,
    model_version TEXT NOT NULL,
    training_session_count INTEGER NOT NULL,
    protocol TEXT,
    trained_at TEXT NOT NULL,
    parameters TEXT NOT NULL DEFAULT '{}',
    preprocessing TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS anomaly_results (
    anomaly_id TEXT PRIMARY KEY,
    capture_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    protocol TEXT,
    status TEXT NOT NULL,
    score INTEGER,
    band TEXT,
    model_id TEXT,
    model_version TEXT NOT NULL,
    feature_schema_version TEXT NOT NULL,
    top_deviations TEXT NOT NULL DEFAULT '[]',
    baseline_summary TEXT NOT NULL DEFAULT '{}',
    evidence_refs TEXT NOT NULL DEFAULT '[]',
    generated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_anomalies_capture ON anomaly_results(capture_id);
CREATE INDEX IF NOT EXISTS idx_anomalies_session ON anomaly_results(session_id);
CREATE TABLE IF NOT EXISTS graph_nodes (
    node_id TEXT NOT NULL,
    capture_id TEXT NOT NULL,
    node_type TEXT NOT NULL,
    label TEXT NOT NULL,
    source_id TEXT NOT NULL,
    metadata TEXT NOT NULL DEFAULT '{}',
    PRIMARY KEY (node_id, capture_id)
);
CREATE INDEX IF NOT EXISTS idx_graph_nodes_capture ON graph_nodes(capture_id);
CREATE TABLE IF NOT EXISTS graph_edges (
    source_node_id TEXT NOT NULL,
    target_node_id TEXT NOT NULL,
    edge_type TEXT NOT NULL,
    basis TEXT NOT NULL,
    capture_id TEXT NOT NULL,
    PRIMARY KEY (source_node_id, target_node_id, edge_type, capture_id)
);
CREATE INDEX IF NOT EXISTS idx_graph_edges_capture ON graph_edges(capture_id);
CREATE TABLE IF NOT EXISTS ai_history (
    response_id TEXT PRIMARY KEY,
    capture_id TEXT NOT NULL,
    session_id TEXT,
    query TEXT NOT NULL,
    answer TEXT NOT NULL,
    provider TEXT NOT NULL,
    model TEXT NOT NULL,
    prompt_version TEXT NOT NULL,
    context_version TEXT NOT NULL,
    validation_status TEXT NOT NULL,
    generated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ai_history_capture ON ai_history(capture_id);
CREATE TABLE IF NOT EXISTS posture_snapshots (
    capture_id TEXT PRIMARY KEY,
    generated_at TEXT NOT NULL,
    analysis_version TEXT NOT NULL,
    policy_id TEXT NOT NULL,
    policy_version TEXT NOT NULL,
    overall_score INTEGER,
    posture_state TEXT NOT NULL,
    confidence TEXT NOT NULL,
    payload TEXT NOT NULL
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

    def replace_findings_for_capture(
        self, capture_id: str, findings: list[SecurityFinding]
    ) -> None: ...

    def list_findings_for_capture(self, capture_id: str) -> list[SecurityFinding]: ...

    def list_findings_for_session(self, session_id: str) -> list[SecurityFinding]: ...

    def get_finding(self, finding_id: str) -> SecurityFinding | None: ...

    def replace_anomaly_results(self, capture_id: str, report: dict[str, Any]) -> None: ...

    def list_anomaly_results(self, capture_id: str) -> list[dict[str, Any]]: ...

    def get_anomaly_result(self, anomaly_id: str) -> dict[str, Any] | None: ...

    def get_anomaly_for_session(self, session_id: str) -> dict[str, Any] | None: ...

    def replace_graph(
        self, capture_id: str, nodes: list[dict[str, Any]], edges: list[dict[str, Any]]
    ) -> None: ...

    def get_graph(
        self, capture_id: str
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]] | None: ...

    def get_anomaly_summary(self, capture_id: str) -> dict[str, int] | None: ...

    def replace_posture_snapshot(self, snapshot: dict[str, Any]) -> None: ...

    def get_posture_snapshot(self, capture_id: str) -> dict[str, Any] | None: ...


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
        session.handshake.model_dump_json() if session.handshake else None,
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


def _session_from_row(
    row: sqlite3.Row,
    events: list[SessionEvent],
    certificates: list[CertificateEvidence] | None = None,
) -> Session:
    starttls = None
    if row["starttls_advertised"] or row["starttls_requested"] or row["starttls_response_seen"]:
        starttls = StarttlsObservation(
            advertised=bool(row["starttls_advertised"]),
            requested=bool(row["starttls_requested"]),
            response_seen=bool(row["starttls_response_seen"]),
            packet_number=row["starttls_packet_number"],
            timestamp=_from_iso(row["starttls_at"]),
        )
    handshake_json = row["tls_handshake"] if "tls_handshake" in row.keys() else None  # noqa: SIM118 - sqlite3.Row supports `in keys()`, not dict semantics
    handshake = TLSHandshake.model_validate_json(handshake_json) if handshake_json else None
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
        handshake=handshake,
        certificates=certificates or [],
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


def _certificate_to_row(certificate: CertificateEvidence) -> tuple[object, ...]:
    return (
        certificate.id,
        certificate.session_id,
        certificate.position_in_chain,
        certificate.subject,
        certificate.issuer,
        certificate.serial_number,
        _iso(certificate.not_before),
        _iso(certificate.not_after),
        certificate.signature_algorithm,
        certificate.public_key_algorithm,
        certificate.public_key_size_bits,
        json.dumps(certificate.subject_alternative_names),
        certificate.fingerprint_sha256,
    )


def _certificate_from_row(row: sqlite3.Row) -> CertificateEvidence:
    return CertificateEvidence(
        id=row["id"],
        session_id=row["session_id"],
        subject=row["subject"],
        issuer=row["issuer"],
        serial_number=row["serial_number"],
        not_before=_from_iso(row["not_before"]) or datetime.now(UTC),
        not_after=_from_iso(row["not_after"]) or datetime.now(UTC),
        signature_algorithm=row["signature_algorithm"],
        public_key_algorithm=row["public_key_algorithm"],
        public_key_size_bits=row["public_key_size_bits"],
        subject_alternative_names=json.loads(row["subject_alternative_names"]),
        fingerprint_sha256=row["fingerprint_sha256"],
        position_in_chain=row["position_in_chain"],
    )


def _finding_to_row(finding: SecurityFinding) -> tuple[object, ...]:
    return (
        finding.id,
        finding.capture_id,
        finding.session_id,
        finding.protocol,
        finding.rule_id,
        finding.severity.value,
        finding.confidence.value,
        finding.category.value,
        finding.title,
        finding.description,
        finding.observed_value,
        finding.expected_value,
        finding.remediation.model_dump_json() if finding.remediation else None,
        finding.standard_reference.model_dump_json() if finding.standard_reference else None,
        json.dumps([ref.model_dump() for ref in finding.evidence_refs]),
        finding.first_packet,
        finding.last_packet,
        json.dumps(finding.details),
        _iso(finding.detected_at),
    )


def _finding_from_row(row: sqlite3.Row) -> SecurityFinding:
    remediation = (
        Remediation.model_validate_json(row["remediation"]) if row["remediation"] else None
    )
    standard_reference = (
        StandardReference.model_validate_json(row["standard_reference"])
        if row["standard_reference"]
        else None
    )
    return SecurityFinding(
        id=row["id"],
        capture_id=row["capture_id"],
        session_id=row["session_id"],
        protocol=row["protocol"],
        title=row["title"],
        description=row["description"],
        severity=FindingSeverity(row["severity"]),
        confidence=Confidence(row["confidence"]),
        category=FindingCategory(row["category"]),
        rule_id=row["rule_id"],
        evidence_refs=[EvidenceRef.model_validate(ref) for ref in json.loads(row["evidence_refs"])],
        observed_value=row["observed_value"],
        expected_value=row["expected_value"],
        remediation=remediation,
        standard_reference=standard_reference,
        first_packet=row["first_packet"],
        last_packet=row["last_packet"],
        details=json.loads(row["details"]),
        detected_at=_from_iso(row["detected_at"]) or datetime.now(UTC),
    )


def _anomaly_from_row(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "anomaly_id": row["anomaly_id"],
        "capture_id": row["capture_id"],
        "session_id": row["session_id"],
        "protocol": row["protocol"],
        "status": row["status"],
        "score": row["score"],
        "band": row["band"],
        "model_id": row["model_id"],
        "model_version": row["model_version"],
        "feature_schema_version": row["feature_schema_version"],
        "top_deviations": json.loads(row["top_deviations"]),
        "baseline_summary": json.loads(row["baseline_summary"]),
        "evidence_refs": json.loads(row["evidence_refs"]),
        "generated_at": row["generated_at"],
    }


class SQLiteSessionStore:
    """Concrete store: sessions/events/analysis tables next to the registry."""

    def __init__(self, db_path: Path) -> None:
        self._db_path = db_path
        try:
            db_path.parent.mkdir(parents=True, exist_ok=True)
            with self._session() as connection:
                connection.executescript(_SCHEMA)
                self._migrate(connection)
        except sqlite3.Error as error:
            raise CaptureStorageError(f"cannot initialize session store: {error}") from error

    @staticmethod
    def _migrate(connection: sqlite3.Connection) -> None:
        """Best-effort upgrades for stores created by earlier stages."""
        existing = {row[1] for row in connection.execute("PRAGMA table_info(sessions)")}
        if "tls_handshake" not in existing:
            connection.execute("ALTER TABLE sessions ADD COLUMN tls_handshake TEXT")
        # Stage 12: certificate identity is per observation, not global.
        # The original PRIMARY KEY (id) collapsed identical certificates
        # observed in different sessions (e.g. across captures), silently
        # dropping all but the last observation. Rebuild with (id,
        # session_id) when the legacy single-column key is detected.
        cert_info = connection.execute("PRAGMA table_info(session_certificates)").fetchall()
        cert_pk = sorted(row[1] for row in cert_info if row[5] > 0)
        if cert_pk == ["id"]:
            connection.execute(
                """CREATE TABLE session_certificates_new (
                    id TEXT NOT NULL,
                    session_id TEXT NOT NULL,
                    position_in_chain INTEGER,
                    subject TEXT NOT NULL,
                    issuer TEXT NOT NULL,
                    serial_number TEXT NOT NULL,
                    not_before TEXT,
                    not_after TEXT,
                    signature_algorithm TEXT NOT NULL,
                    public_key_algorithm TEXT,
                    public_key_size_bits INTEGER,
                    subject_alternative_names TEXT NOT NULL DEFAULT '[]',
                    fingerprint_sha256 TEXT NOT NULL,
                    PRIMARY KEY (id, session_id)
                )"""
            )
            connection.execute(
                "INSERT OR IGNORE INTO session_certificates_new SELECT * FROM session_certificates"
            )
            connection.execute("DROP TABLE session_certificates")
            connection.execute(
                "ALTER TABLE session_certificates_new RENAME TO session_certificates"
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_certificates_session "
                "ON session_certificates(session_id)"
            )

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

    def ping(self) -> bool:
        """Cheap database probe for the readiness endpoint."""
        try:
            with self._session() as connection:
                connection.execute("SELECT 1").fetchone()
            return True
        except sqlite3.Error:
            return False

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
                    (session.handshake.model_dump_json() if session.handshake else None)
                    connection.execute(
                        """INSERT INTO sessions (
                            id, capture_id, protocol, confidence, orientation,
                            client_ip, client_port, server_ip, server_port, implicit_tls,
                            started_at, ended_at, duration_seconds, packet_count,
                            bytes_client_to_server, bytes_server_to_client, complete,
                            completeness_reason, retransmissions, gap_count, gap_bytes,
                            starttls_advertised, starttls_requested, starttls_response_seen,
                            starttls_packet_number, starttls_at, warnings, tls_handshake
                        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                        _session_to_row(session),
                    )
                    connection.execute(
                        "DELETE FROM session_certificates WHERE session_id = ?", (session.id,)
                    )
                    for certificate in session.certificates:
                        connection.execute(
                            "INSERT OR REPLACE INTO session_certificates "
                            "(id, session_id, position_in_chain, subject, issuer, "
                            "serial_number, not_before, not_after, signature_algorithm, "
                            "public_key_algorithm, public_key_size_bits, "
                            "subject_alternative_names, fingerprint_sha256) "
                            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                            _certificate_to_row(certificate),
                        )
                    for event in session.events:
                        connection.execute(
                            "INSERT INTO session_events "
                            "(session_id, seq, type, direction, timestamp, packet_numbers, detail) "
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
                certificates = connection.execute(
                    "SELECT * FROM session_certificates WHERE session_id IN "
                    "(SELECT id FROM sessions WHERE capture_id = ?) "
                    "ORDER BY session_id, position_in_chain",
                    (capture_id,),
                ).fetchall()
        except sqlite3.Error as error:
            raise CaptureStorageError(f"cannot list sessions: {error}") from error
        events_by_session: dict[str, list[SessionEvent]] = {}
        for row in events:
            events_by_session.setdefault(row["session_id"], []).append(_event_from_row(row))
        certs_by_session: dict[str, list[CertificateEvidence]] = {}
        for row in certificates:
            certs_by_session.setdefault(row["session_id"], []).append(_certificate_from_row(row))
        return [
            _session_from_row(
                row,
                events_by_session.get(row["id"], []),
                certs_by_session.get(row["id"], []),
            )
            for row in rows
        ]

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
                certificates = connection.execute(
                    "SELECT * FROM session_certificates WHERE session_id = ? "
                    "ORDER BY position_in_chain",
                    (session_id,),
                ).fetchall()
        except sqlite3.Error as error:
            raise CaptureStorageError(f"cannot load session: {error}") from error
        if row is None:
            return None
        return _session_from_row(
            row,
            [_event_from_row(event) for event in events],
            [_certificate_from_row(certificate) for certificate in certificates],
        )

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

    def replace_findings_for_capture(
        self, capture_id: str, findings: list[SecurityFinding]
    ) -> None:
        """Atomically replace all findings for one capture."""
        try:
            with self._session() as connection:
                connection.execute("DELETE FROM findings WHERE capture_id = ?", (capture_id,))
                for finding in findings:
                    connection.execute(
                        "INSERT INTO findings "
                        "(id, capture_id, session_id, protocol, rule_id, severity, "
                        "confidence, category, title, description, observed_value, "
                        "expected_value, remediation, standard_reference, evidence_refs, "
                        "first_packet, last_packet, details, detected_at) "
                        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                        _finding_to_row(finding),
                    )
        except sqlite3.Error as error:
            raise CaptureStorageError(f"cannot persist findings: {error}") from error

    def list_findings_for_capture(self, capture_id: str) -> list[SecurityFinding]:
        return self._findings_query(
            "SELECT * FROM findings WHERE capture_id = ? ORDER BY detected_at ASC, id ASC",
            (capture_id,),
        )

    def list_findings_for_session(self, session_id: str) -> list[SecurityFinding]:
        return self._findings_query(
            "SELECT * FROM findings WHERE session_id = ? ORDER BY detected_at ASC, id ASC",
            (session_id,),
        )

    def get_finding(self, finding_id: str) -> SecurityFinding | None:
        rows = self._findings_query("SELECT * FROM findings WHERE id = ?", (finding_id,))
        return rows[0] if rows else None

    def replace_anomaly_results(self, capture_id: str, report: dict[str, Any]) -> None:
        """Atomically replace anomaly results + model metadata for one capture."""
        try:
            with self._session() as connection:
                connection.execute(
                    "DELETE FROM anomaly_results WHERE capture_id = ?", (capture_id,)
                )
                connection.execute("DELETE FROM anomaly_models WHERE capture_id = ?", (capture_id,))
                if report.get("model_id") and report["status"] != "insufficient_baseline":
                    model_meta = {
                        "model_id": report["model_id"],
                        "capture_id": capture_id,
                        "algorithm": "IsolationForest",
                        "feature_schema_version": report["feature_schema_version"],
                        "model_version": report["model_version"],
                        "training_session_count": report["training_session_count"],
                        "protocol": None,
                        "trained_at": report["generated_at"],
                        "parameters": "{}",
                        "preprocessing": "{}",
                    }
                    columns = ",".join(model_meta)
                    placeholders = ",".join("?" for _ in model_meta)
                    sql = (
                        f"INSERT OR REPLACE INTO anomaly_models ({columns}) VALUES ({placeholders})"
                    )
                    connection.execute(sql, tuple(model_meta.values()))
                for anomaly in report["anomalies"]:
                    row = dict(anomaly)
                    row["capture_id"] = capture_id
                    row["top_deviations"] = json.dumps(anomaly["top_deviations"])
                    row["baseline_summary"] = json.dumps(anomaly["baseline_summary"])
                    row["evidence_refs"] = json.dumps(anomaly["evidence_refs"])
                    columns = ",".join(row)
                    placeholders = ",".join("?" for _ in row)
                    sql = (
                        f"INSERT OR REPLACE INTO anomaly_results ({columns}) "
                        f"VALUES ({placeholders})"
                    )
                    connection.execute(sql, tuple(row.values()))
                connection.execute(
                    "UPDATE anomaly_models SET preprocessing = ? WHERE capture_id = ?",
                    (json.dumps(report["summary"]), capture_id),
                )
        except (sqlite3.Error, KeyError) as error:
            raise CaptureStorageError(f"cannot persist anomaly results: {error}") from error

    def list_anomaly_results(self, capture_id: str) -> list[dict[str, Any]]:
        try:
            with self._session() as connection:
                rows = connection.execute(
                    "SELECT * FROM anomaly_results WHERE capture_id = ? ORDER BY session_id",
                    (capture_id,),
                ).fetchall()
        except sqlite3.Error as error:
            raise CaptureStorageError(f"cannot load anomaly results: {error}") from error
        return [_anomaly_from_row(row) for row in rows]

    def get_anomaly_result(self, anomaly_id: str) -> dict[str, Any] | None:
        try:
            with self._session() as connection:
                row = connection.execute(
                    "SELECT * FROM anomaly_results WHERE anomaly_id = ?", (anomaly_id,)
                ).fetchone()
        except sqlite3.Error as error:
            raise CaptureStorageError(f"cannot load anomaly result: {error}") from error
        return _anomaly_from_row(row) if row else None

    def get_anomaly_summary(self, capture_id: str) -> dict[str, int] | None:
        try:
            with self._session() as connection:
                row = connection.execute(
                    "SELECT preprocessing FROM anomaly_models WHERE capture_id = ?",
                    (capture_id,),
                ).fetchone()
        except sqlite3.Error as error:
            raise CaptureStorageError(f"cannot load anomaly summary: {error}") from error
        if row is None:
            return None
        result: dict[str, int] = json.loads(row["preprocessing"])
        return result

    def get_anomaly_for_session(self, session_id: str) -> dict[str, Any] | None:
        try:
            with self._session() as connection:
                row = connection.execute(
                    "SELECT * FROM anomaly_results WHERE session_id = ?",
                    (session_id,),
                ).fetchone()
        except sqlite3.Error as error:
            raise CaptureStorageError(f"cannot load anomaly result: {error}") from error
        return _anomaly_from_row(row) if row else None

    def replace_graph(
        self, capture_id: str, nodes: list[dict[str, Any]], edges: list[dict[str, Any]]
    ) -> None:
        try:
            with self._session() as connection:
                connection.execute("DELETE FROM graph_nodes WHERE capture_id = ?", (capture_id,))
                connection.execute("DELETE FROM graph_edges WHERE capture_id = ?", (capture_id,))
                for node in nodes:
                    connection.execute(
                        "INSERT INTO graph_nodes "
                        "(node_id, capture_id, node_type, label, source_id, metadata) "
                        "VALUES (?,?,?,?,?,?)",
                        (
                            node["node_id"],
                            capture_id,
                            node["node_type"],
                            node["label"],
                            node["source_id"],
                            node["metadata"],
                        ),
                    )
                for edge in edges:
                    connection.execute(
                        "INSERT INTO graph_edges "
                        "(source_node_id, target_node_id, edge_type, basis, capture_id) "
                        "VALUES (?,?,?,?,?)",
                        (
                            edge["source_node_id"],
                            edge["target_node_id"],
                            edge["edge_type"],
                            edge["basis"],
                            capture_id,
                        ),
                    )
        except sqlite3.Error as error:
            raise CaptureStorageError(f"cannot persist graph: {error}") from error

    def get_graph(
        self, capture_id: str
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]] | None:
        try:
            with self._session() as connection:
                nodes = connection.execute(
                    "SELECT * FROM graph_nodes WHERE capture_id = ? ORDER BY node_type, node_id",
                    (capture_id,),
                ).fetchall()
                edges = connection.execute(
                    "SELECT * FROM graph_edges WHERE capture_id = ? "
                    "ORDER BY source_node_id, target_node_id",
                    (capture_id,),
                ).fetchall()
        except sqlite3.Error as error:
            raise CaptureStorageError(f"cannot load graph: {error}") from error
        if not nodes and not edges:
            return None
        node_list = [
            {
                "node_id": r["node_id"],
                "capture_id": r["capture_id"],
                "node_type": r["node_type"],
                "label": r["label"],
                "source_id": r["source_id"],
                "metadata": json.loads(r["metadata"]),
            }
            for r in nodes
        ]
        edge_list = [
            {
                "source_node_id": r["source_node_id"],
                "target_node_id": r["target_node_id"],
                "edge_type": r["edge_type"],
                "basis": r["basis"],
            }
            for r in edges
        ]
        return node_list, edge_list

    def save_ai_response(self, capture_id: str, response: dict[str, Any]) -> None:
        generated_at = response["generated_at"]
        if isinstance(generated_at, datetime):
            generated_at = generated_at.isoformat()
        try:
            with self._session() as connection:
                connection.execute(
                    "INSERT OR REPLACE INTO ai_history "
                    "(response_id, capture_id, session_id, query, answer, "
                    "provider, model, prompt_version, context_version, "
                    "validation_status, generated_at) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        response["response_id"],
                        capture_id,
                        response.get("session_id"),
                        response["query"],
                        response["answer"],
                        response["provider"],
                        response["model"],
                        response["prompt_version"],
                        response["context_version"],
                        response["validation_status"],
                        str(generated_at),
                    ),
                )
        except sqlite3.Error as error:
            raise CaptureStorageError(f"cannot save AI response: {error}") from error

    def list_ai_history(self, capture_id: str) -> list[dict[str, Any]]:
        try:
            with self._session() as connection:
                rows = connection.execute(
                    "SELECT * FROM ai_history WHERE capture_id = ? ORDER BY generated_at DESC",
                    (capture_id,),
                ).fetchall()
        except sqlite3.Error as error:
            raise CaptureStorageError(f"cannot load AI history: {error}") from error
        return [dict(row) for row in rows]

    def _findings_query(self, query: str, params: tuple[object, ...]) -> list[SecurityFinding]:
        try:
            with self._session() as connection:
                rows = connection.execute(query, params).fetchall()
        except sqlite3.Error as error:
            raise CaptureStorageError(f"cannot query findings: {error}") from error
        return [_finding_from_row(row) for row in rows]

    def replace_posture_snapshot(self, snapshot: dict[str, Any]) -> None:
        """Atomically replace the posture snapshot for the capture."""
        try:
            with self._session() as connection:
                connection.execute(
                    "INSERT OR REPLACE INTO posture_snapshots "
                    "(capture_id, generated_at, analysis_version, policy_id, "
                    "policy_version, overall_score, posture_state, confidence, payload) "
                    "VALUES (?,?,?,?,?,?,?,?,?)",
                    (
                        snapshot["capture_id"],
                        snapshot["generated_at"],
                        snapshot["analysis_version"],
                        snapshot["policy_id"],
                        snapshot["policy_version"],
                        snapshot["overall_score"],
                        snapshot["posture_state"],
                        snapshot["confidence"],
                        json.dumps(snapshot),
                    ),
                )
        except (sqlite3.Error, KeyError) as error:
            raise CaptureStorageError(f"cannot persist posture snapshot: {error}") from error

    def get_posture_snapshot(self, capture_id: str) -> dict[str, Any] | None:
        try:
            with self._session() as connection:
                row = connection.execute(
                    "SELECT payload FROM posture_snapshots WHERE capture_id = ?",
                    (capture_id,),
                ).fetchone()
        except sqlite3.Error as error:
            raise CaptureStorageError(f"cannot load posture snapshot: {error}") from error
        return json.loads(row["payload"]) if row else None
