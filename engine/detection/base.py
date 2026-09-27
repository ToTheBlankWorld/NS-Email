"""Rule-engine foundation: context, rule contract, and finding factory.

A rule evaluates structured Stage 2/3 evidence for one session and returns
zero or more findings. Rules are pure functions of the evidence and the
loaded policy: deterministic, explainable, reproducible.
"""

import datetime
import hashlib
from dataclasses import dataclass
from typing import Final, Protocol

from engine.core.findings import (
    EvidenceRef,
    FindingCategory,
    FindingSeverity,
    Remediation,
    SecurityFinding,
    StandardReference,
)
from engine.core.session import Confidence, Session
from engine.detection.policy import Policy

_HEX_LENGTH: Final[int] = 12


@dataclass(frozen=True, slots=True)
class RuleContext:
    """Everything a rule may look at: one session's evidence + policy."""

    session: Session
    policy: Policy


class SecurityRule(Protocol):
    """Contract every deterministic security rule implements."""

    rule_id: str
    name: str
    description: str
    category: FindingCategory
    default_severity: FindingSeverity

    def evaluate(self, context: RuleContext) -> list[SecurityFinding]:
        """Return findings for policy violations observed in the session."""
        ...


def finding_id(rule_id: str, session_id: str, observed_value: str, extra: str = "") -> str:
    """Deterministic finding identity: same rule + evidence → same id."""
    digest = hashlib.sha256(f"{rule_id}|{session_id}|{observed_value}|{extra}".encode()).hexdigest()
    return f"finding_{digest[:_HEX_LENGTH]}"


def build_finding(
    *,
    rule_id: str,
    name: str,
    description: str,
    category: FindingCategory,
    severity: FindingSeverity,
    confidence: Confidence,
    session: Session,
    evidence_refs: list[EvidenceRef],
    observed_value: str,
    expected_value: str | None,
    remediation: dict[str, str] | None,
    standard_reference: StandardReference | None,
    protocol: str | None,
    extra_condition: str = "",
) -> SecurityFinding:
    """Assemble one finding with a deterministic id and packet evidence."""
    packet_numbers = sorted({number for ref in evidence_refs for number in ref.packet_numbers})
    return SecurityFinding(
        id=finding_id(rule_id, session.id, observed_value, extra_condition),
        capture_id=session.capture_id,
        session_id=session.id,
        protocol=protocol,
        title=name,
        description=description,
        severity=severity,
        confidence=confidence,
        category=category,
        rule_id=rule_id,
        evidence_refs=evidence_refs,
        observed_value=observed_value,
        expected_value=expected_value,
        remediation=Remediation(**remediation) if remediation else None,
        standard_reference=standard_reference,
        first_packet=packet_numbers[0] if packet_numbers else None,
        last_packet=packet_numbers[-1] if packet_numbers else None,
        details={},
        detected_at=session.ended_at or session.started_at or datetime.datetime.now(datetime.UTC),
    )
