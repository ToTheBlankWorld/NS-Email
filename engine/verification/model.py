"""Evidence-based verification domain model (Stage 13).

A verification result describes what a LATER capture shows about an
earlier finding — never a mutation of the earlier finding itself.
Outcomes use precise, neutral wording:

- VERIFIED: the original rule was not observed in the verification capture.
- FAILED: the same rule still appears in the relevant evidence.
- INCONCLUSIVE: the relevant session or evidence is absent/incomplete.
- PENDING: a manual verification was requested but not yet completed.

"Rule absent" is never equated with "globally secure" anywhere in this
module; statements name the rule and the capture explicitly.
"""

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Final

VERIFICATION_ID_PREFIX: Final[str] = "verif_"


class VerificationOutcome(StrEnum):
    """Terminal or pending verification states."""

    PENDING = "pending"
    VERIFIED = "verified"
    FAILED = "failed"
    INCONCLUSIVE = "inconclusive"


class VerificationMethod(StrEnum):
    """How the verification result was established."""

    EVIDENCE = "evidence"
    ANALYST_ASSERTED = "analyst_asserted"


@dataclass(frozen=True, slots=True)
class SessionView:
    """Minimal session evidence the comparison reads (store-agnostic)."""

    session_id: str
    capture_id: str
    protocol: str | None = None
    server_ip: str | None = None
    server_port: int | None = None
    tls_version: str | None = None
    cipher_suite: str | None = None
    key_exchange: str | None = None
    handshake_complete: bool | None = None
    complete: bool = False
    certificate_fingerprint: str | None = None
    certificate_subject: str | None = None
    certificate_valid: bool | None = None
    signature_algorithm: str | None = None
    subject_alternative_names: tuple[str, ...] = ()
    started_at: str | None = None


@dataclass(frozen=True, slots=True)
class FindingView:
    """Minimal finding evidence the comparison reads."""

    finding_id: str
    capture_id: str
    session_id: str | None = None
    rule_id: str = ""
    severity: str | None = None
    confidence: str | None = None


@dataclass(frozen=True, slots=True)
class PostureView:
    """Minimal posture snapshot the comparison quotes."""

    capture_id: str
    posture_state: str | None = None
    overall_score: int | None = None


@dataclass(frozen=True, slots=True)
class VerificationComparison:
    """Deterministic before/after comparison for one rule."""

    outcome: VerificationOutcome
    method: VerificationMethod
    rule_id: str
    baseline_capture_id: str
    verification_capture_id: str
    baseline_session_id: str | None
    verification_session_id: str | None
    session_match: str  # matched | no_matching_session | not_session_scoped | incomplete_evidence
    rule_present_in_verification: bool | None
    baseline_evidence: dict[str, Any] = field(default_factory=dict)
    verification_evidence: dict[str, Any] = field(default_factory=dict)
    posture_before: dict[str, Any] = field(default_factory=dict)
    posture_after: dict[str, Any] = field(default_factory=dict)
    posture_delta_points: int | None = None
    statement: str = ""

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe serialization with deterministic key order."""
        return {
            "outcome": self.outcome.value,
            "method": self.method.value,
            "rule_id": self.rule_id,
            "baseline_capture_id": self.baseline_capture_id,
            "verification_capture_id": self.verification_capture_id,
            "baseline_session_id": self.baseline_session_id,
            "verification_session_id": self.verification_session_id,
            "session_match": self.session_match,
            "rule_present_in_verification": self.rule_present_in_verification,
            "baseline_evidence": dict(self.baseline_evidence),
            "verification_evidence": dict(self.verification_evidence),
            "posture_before": dict(self.posture_before),
            "posture_after": dict(self.posture_after),
            "posture_delta_points": self.posture_delta_points,
            "statement": self.statement,
        }


__all__ = [
    "VERIFICATION_ID_PREFIX",
    "FindingView",
    "PostureView",
    "SessionView",
    "VerificationComparison",
    "VerificationMethod",
    "VerificationOutcome",
]
