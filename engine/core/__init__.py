"""Typed evidence models shared across engine analysis stages.

Every model is JSON-serializable so forensic records can be persisted to
SQLite and exchanged canonically between engine, API, and reports.
"""

from engine.core.base import ForensicBase, new_evidence_id, utc_now
from engine.core.capture import MAX_CAPTURE_SIZE_BYTES, Capture, CaptureFormat, CaptureStatus
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
from engine.core.tls import KeyExchange, TlsExtension, TLSHandshake, TLSVersion

__all__ = [
    "MAX_CAPTURE_SIZE_BYTES",
    "Capture",
    "CaptureFormat",
    "CaptureStatus",
    "CertificateEvidence",
    "Confidence",
    "EmailProtocol",
    "EventDirection",
    "EventType",
    "EvidenceRef",
    "FindingCategory",
    "FindingSeverity",
    "ForensicBase",
    "KeyExchange",
    "Orientation",
    "Remediation",
    "SecurityFinding",
    "Session",
    "SessionEvent",
    "StandardReference",
    "StarttlsObservation",
    "TLSHandshake",
    "TLSVersion",
    "TlsExtension",
    "new_evidence_id",
    "utc_now",
]
