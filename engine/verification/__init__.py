"""Evidence-based verification for remediation follow-up (Stage 13)."""

from engine.verification.compare import compare_rule
from engine.verification.model import (
    VERIFICATION_ID_PREFIX,
    FindingView,
    PostureView,
    SessionView,
    VerificationComparison,
    VerificationMethod,
    VerificationOutcome,
)

__all__ = [
    "VERIFICATION_ID_PREFIX",
    "FindingView",
    "PostureView",
    "SessionView",
    "VerificationComparison",
    "VerificationMethod",
    "VerificationOutcome",
    "compare_rule",
]
