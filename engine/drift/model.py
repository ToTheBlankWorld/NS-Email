"""Longitudinal drift domain model (Stage 14).

A drift record captures that structured evidence differed between two
observations of a case — never a mutation of either observation.
Language is neutral throughout ("changed", "observed", "no longer
observed"); drift never asserts attribution, ownership, intent,
compromise, or causality.

Drift ids are deterministic: ``drift_<sha256(canonical)[:16]>`` over
case id + baseline capture + comparison capture + drift type +
evidence key, so repeated evaluation produces identical ids. No random
UUIDs anywhere.
"""

import hashlib
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Final

DRIFT_ID_PREFIX: Final[str] = "drift_"
OBSERVATION_ID_PREFIX: Final[str] = "obs_"

#: Occurrence references recorded per drift record (bounded output).
MAX_EVIDENCE_REFS_PER_DRIFT: Final[int] = 50

#: Total drift records returned for one case (bounded output).
MAX_DRIFT_PER_CASE: Final[int] = 1000


class DriftType(StrEnum):
    """Explicit, finite drift vocabulary."""

    POSTURE_CHANGE = "posture_change"
    FINDING_INTRODUCED = "finding_introduced"
    FINDING_RESOLVED = "finding_resolved"
    FINDING_RECURRED = "finding_recurred"
    TLS_CONFIGURATION_CHANGED = "tls_configuration_changed"
    CERTIFICATE_CHANGED = "certificate_changed"
    CERTIFICATE_VALIDITY_CHANGED = "certificate_validity_changed"
    PROTOCOL_BEHAVIOR_CHANGED = "protocol_behavior_changed"
    ANOMALY_STATE_CHANGED = "anomaly_state_changed"
    CORRELATION_PATTERN_CHANGED = "correlation_pattern_changed"


class FindingLifecycle(StrEnum):
    """Lifecycle of one rule across ordered observations."""

    NEW = "new"
    PERSISTENT = "persistent"
    RESOLVED = "resolved"
    RECURRED = "recurred"
    NOT_COMPARABLE = "not_comparable"


def drift_id(
    case_id: str,
    baseline_capture_id: str,
    comparison_capture_id: str,
    drift_type: str,
    evidence_key: str,
) -> str:
    """Deterministic drift id over canonical inputs."""
    canonical = "|".join(
        [case_id, baseline_capture_id, comparison_capture_id, drift_type, evidence_key]
    )
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]
    return f"{DRIFT_ID_PREFIX}{digest}"


def observation_id(case_id: str, capture_id: str, evidence_digest: str) -> str:
    """Deterministic observation id over case + capture + evidence digest."""
    canonical = "|".join([case_id, capture_id, evidence_digest])
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]
    return f"{OBSERVATION_ID_PREFIX}{digest}"


@dataclass(frozen=True, slots=True)
class RulePresence:
    """One rule's footprint inside a single observation."""

    rule_id: str
    severity: str | None = None
    title: str | None = None
    count: int = 0
    finding_ids: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class CertObservation:
    """One certificate's footprint inside a single observation."""

    fingerprint: str
    subject: str | None = None
    issuer: str | None = None
    valid: bool | None = None
    signature_algorithm: str | None = None


@dataclass(frozen=True, slots=True)
class TlsConfigObservation:
    """One negotiated TLS configuration inside a single observation."""

    fingerprint: str
    tls_version: str | None = None
    cipher_suite: str | None = None
    key_exchange: str | None = None


@dataclass(frozen=True, slots=True)
class ObservationView:
    """Deterministic snapshot of one capture's structured evidence.

    Derived on demand from immutable analysis output; never persisted
    as a separate truth. ``created_at`` mirrors the underlying analysis
    completion instant so no wall-clock time enters derived payloads.
    """

    observation_id: str
    case_id: str
    capture_id: str
    analyzed: bool = False
    analysis_status: str = "not_analyzed"
    analyzed_at: str | None = None
    created_at: str | None = None
    posture_score: int | None = None
    posture_state: str | None = None
    session_count: int = 0
    finding_rules: tuple[RulePresence, ...] = ()
    protocols: tuple[str, ...] = ()
    tls_versions: tuple[str, ...] = ()
    cipher_suites: tuple[str, ...] = ()
    key_exchanges: tuple[str, ...] = ()
    tls_config_fingerprints: tuple[TlsConfigObservation, ...] = ()
    certificates: tuple[CertObservation, ...] = ()
    anomaly_bands: tuple[tuple[str, int], ...] | None = None
    evidence_digest: str = ""
    # Navigation mappings (bounded, sorted): rule -> session ids,
    # session -> "protocol|ip|port" endpoint key, fingerprint -> sessions.
    rule_sessions: tuple[tuple[str, tuple[str, ...]], ...] = ()
    session_endpoints: tuple[tuple[str, str], ...] = ()
    tls_config_sessions: tuple[tuple[str, tuple[str, ...]], ...] = ()
    cert_sessions: tuple[tuple[str, tuple[str, ...]], ...] = ()


@dataclass(frozen=True, slots=True)
class LifecycleRow:
    """One rule's lifecycle state at a target observation."""

    rule_id: str
    title: str | None = None
    baseline_present: bool = False
    current_present: bool = False
    lifecycle: FindingLifecycle = FindingLifecycle.NOT_COMPARABLE
    severity: str | None = None
    baseline_finding_id: str | None = None
    latest_finding_id: str | None = None
    comparable: bool = False


@dataclass(frozen=True, slots=True)
class DriftRecord:
    """One deterministic difference between two observations."""

    drift_id: str
    case_id: str
    drift_type: DriftType
    evidence_key: str
    baseline_capture_id: str
    comparison_capture_id: str
    before: dict[str, Any] = field(default_factory=dict)
    after: dict[str, Any] = field(default_factory=dict)
    evidence_refs: tuple[dict[str, Any], ...] = ()
    related_finding_ids: tuple[str, ...] = ()
    related_remediation_ids: tuple[str, ...] = ()
    related_verification_ids: tuple[str, ...] = ()
    related_correlations: tuple[dict[str, Any], ...] = ()
    regression_after_verification: bool = False
    statement: str = ""

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe serialization with deterministic key order."""
        return {
            "drift_id": self.drift_id,
            "case_id": self.case_id,
            "drift_type": self.drift_type.value,
            "evidence_key": self.evidence_key,
            "baseline_capture_id": self.baseline_capture_id,
            "comparison_capture_id": self.comparison_capture_id,
            "before": dict(self.before),
            "after": dict(self.after),
            "evidence_refs": [dict(ref) for ref in self.evidence_refs],
            "related_finding_ids": list(self.related_finding_ids),
            "related_remediation_ids": list(self.related_remediation_ids),
            "related_verification_ids": list(self.related_verification_ids),
            "related_correlations": [dict(item) for item in self.related_correlations],
            "regression_after_verification": self.regression_after_verification,
            "statement": self.statement,
        }


@dataclass(frozen=True, slots=True)
class ComparisonResult:
    """Deterministic comparison of one observation pair."""

    baseline_capture_id: str
    comparison_capture_id: str
    previous_capture_id: str
    lifecycle_anchor_capture_id: str
    posture_before: dict[str, Any] = field(default_factory=dict)
    posture_after: dict[str, Any] = field(default_factory=dict)
    posture_delta_points: int | None = None
    posture_statement: str = ""
    finding_lifecycle: tuple[LifecycleRow, ...] = ()
    tls_before: dict[str, Any] = field(default_factory=dict)
    tls_after: dict[str, Any] = field(default_factory=dict)
    certificates_before: dict[str, Any] = field(default_factory=dict)
    certificates_after: dict[str, Any] = field(default_factory=dict)
    protocols_before: tuple[str, ...] = ()
    protocols_after: tuple[str, ...] = ()
    anomaly_bands_before: dict[str, int] | None = None
    anomaly_bands_after: dict[str, int] | None = None
    drift_ids: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe serialization with deterministic key order."""
        return {
            "baseline_capture_id": self.baseline_capture_id,
            "comparison_capture_id": self.comparison_capture_id,
            "previous_capture_id": self.previous_capture_id,
            "lifecycle_anchor_capture_id": self.lifecycle_anchor_capture_id,
            "posture_before": dict(self.posture_before),
            "posture_after": dict(self.posture_after),
            "posture_delta_points": self.posture_delta_points,
            "posture_statement": self.posture_statement,
            "finding_lifecycle": [
                {
                    "rule_id": row.rule_id,
                    "title": row.title,
                    "baseline_present": row.baseline_present,
                    "current_present": row.current_present,
                    "lifecycle": row.lifecycle.value,
                    "severity": row.severity,
                    "baseline_finding_id": row.baseline_finding_id,
                    "latest_finding_id": row.latest_finding_id,
                    "comparable": row.comparable,
                }
                for row in self.finding_lifecycle
            ],
            "tls_before": dict(self.tls_before),
            "tls_after": dict(self.tls_after),
            "certificates_before": dict(self.certificates_before),
            "certificates_after": dict(self.certificates_after),
            "protocols_before": list(self.protocols_before),
            "protocols_after": list(self.protocols_after),
            "anomaly_bands_before": (
                dict(self.anomaly_bands_before) if self.anomaly_bands_before is not None else None
            ),
            "anomaly_bands_after": (
                dict(self.anomaly_bands_after) if self.anomaly_bands_after is not None else None
            ),
            "drift_ids": list(self.drift_ids),
        }


__all__ = [
    "DRIFT_ID_PREFIX",
    "MAX_DRIFT_PER_CASE",
    "MAX_EVIDENCE_REFS_PER_DRIFT",
    "OBSERVATION_ID_PREFIX",
    "CertObservation",
    "ComparisonResult",
    "DriftRecord",
    "DriftType",
    "FindingLifecycle",
    "LifecycleRow",
    "ObservationView",
    "RulePresence",
    "TlsConfigObservation",
    "drift_id",
    "observation_id",
]
