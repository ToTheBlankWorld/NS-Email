"""Multi-capture correlation domain model (Stage 12).

A correlation records that the same normalized structured evidence was
observed across two or more captures of a case. Correlations are
derived intelligence only: they describe repeated observations in
neutral terms ("shared evidence", "repeated observation") and never
assert attribution, ownership, intent, or compromise.

Correlation ids are deterministic: ``corr_<sha256(canonical)[:16]>``
over case id + type + evidence key + sorted source ids, so repeated
evaluation produces identical ids. No random UUIDs anywhere.
"""

import hashlib
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Final

CORRELATION_ID_PREFIX: Final[str] = "corr_"

#: Occurrence references recorded per correlation (bounded output).
MAX_OCCURRENCES_PER_CORRELATION: Final[int] = 200

#: Total correlations returned for one case (bounded output).
MAX_CORRELATIONS_PER_CASE: Final[int] = 500


class CorrelationType(StrEnum):
    """Explicit, finite correlation vocabulary."""

    SHARED_ENDPOINT = "shared_endpoint"
    SHARED_HOST = "shared_host"
    SHARED_CERTIFICATE = "shared_certificate"
    SHARED_CERTIFICATE_SUBJECT = "shared_certificate_subject"
    SHARED_TLS_CONFIGURATION = "shared_tls_configuration"
    SHARED_PROTOCOL = "shared_protocol"
    SHARED_FINDING = "shared_finding"
    SHARED_ANOMALY_PATTERN = "shared_anomaly_pattern"
    REPEATED_SESSION_PATTERN = "repeated_session_pattern"
    SHARED_EVIDENCE = "shared_evidence"


class CorrelationStrength(StrEnum):
    """Categorical relationship strength — no probabilistic scores.

    DIRECT: identity-level match (endpoint, host, certificate
    fingerprint, TLS configuration fingerprint, finding rule).
    DERIVED: normalized descriptive match (subjects, hostnames,
    protocols, bands, session patterns).
    """

    DIRECT = "direct"
    DERIVED = "derived"


def correlation_id(
    case_id: str, correlation_type: str, evidence_key: str, source_ids: list[str]
) -> str:
    """Deterministic correlation id over canonical inputs."""
    canonical = "|".join([case_id, correlation_type, evidence_key, *sorted(source_ids)])
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]
    return f"{CORRELATION_ID_PREFIX}{digest}"


@dataclass(frozen=True, slots=True)
class Occurrence:
    """One observation of the shared evidence (a reference, not a copy)."""

    capture_id: str
    session_id: str
    finding_id: str | None = None
    anomaly_id: str | None = None
    observed_at: str | None = None


@dataclass(frozen=True, slots=True)
class Correlation:
    """One deterministic cross-capture relationship."""

    correlation_id: str
    case_id: str
    correlation_type: CorrelationType
    strength: CorrelationStrength
    evidence_key: str
    evidence: dict[str, Any] = field(default_factory=dict)
    occurrence_count: int = 0
    capture_count: int = 0
    session_count: int = 0
    source_capture_ids: tuple[str, ...] = ()
    source_session_ids: tuple[str, ...] = ()
    occurrences: tuple[Occurrence, ...] = ()
    first_observed_at: str | None = None
    last_observed_at: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe serialization with deterministic key order."""
        return {
            "correlation_id": self.correlation_id,
            "case_id": self.case_id,
            "correlation_type": self.correlation_type.value,
            "strength": self.strength.value,
            "evidence_key": self.evidence_key,
            "evidence": dict(self.evidence),
            "occurrence_count": self.occurrence_count,
            "capture_count": self.capture_count,
            "session_count": self.session_count,
            "source_capture_ids": list(self.source_capture_ids),
            "source_session_ids": list(self.source_session_ids),
            "occurrences": [
                {
                    "capture_id": o.capture_id,
                    "session_id": o.session_id,
                    "finding_id": o.finding_id,
                    "anomaly_id": o.anomaly_id,
                    "observed_at": o.observed_at,
                }
                for o in self.occurrences
            ],
            "first_observed_at": self.first_observed_at,
            "last_observed_at": self.last_observed_at,
        }


@dataclass(frozen=True, slots=True)
class CorrelationReport:
    """The complete correlation result for one case evaluation."""

    case_id: str
    capture_ids: tuple[str, ...]
    correlations: tuple[Correlation, ...]
    sessions_scanned: int
    index_keys: int

    def to_summary(self) -> dict[str, Any]:
        """Counts only — never a score."""
        by_type: dict[str, int] = {}
        for correlation in self.correlations:
            key = correlation.correlation_type.value
            by_type[key] = by_type.get(key, 0) + 1
        return {
            "case_id": self.case_id,
            "capture_count": len(self.capture_ids),
            "correlation_count": len(self.correlations),
            "sessions_scanned": self.sessions_scanned,
            "index_keys": self.index_keys,
            "by_type": dict(sorted(by_type.items())),
        }


__all__ = [
    "CORRELATION_ID_PREFIX",
    "MAX_CORRELATIONS_PER_CASE",
    "MAX_OCCURRENCES_PER_CORRELATION",
    "Correlation",
    "CorrelationReport",
    "CorrelationStrength",
    "CorrelationType",
    "Occurrence",
    "correlation_id",
]
