"""Security findings produced by the deterministic policy engine.

Every finding is deterministic, explainable, and evidence-backed: it is
produced by a versioned rule evaluating structured Stage 2/3 evidence,
carries its own confidence (separate from severity), cites the packets it
was observed in, and includes structured remediation guidance. Raw
credentials and application payloads never appear in finding fields.
"""

from enum import StrEnum
from typing import Any

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field

from engine.core.base import ForensicBase, utc_now
from engine.core.session import Confidence


class FindingSeverity(StrEnum):
    """Finite severity taxonomy; assigned by deterministic policy logic."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingCategory(StrEnum):
    """Analysis domains a finding can belong to."""

    STARTTLS = "starttls"
    PROTOCOL_VERSION = "protocol_version"
    CIPHER_SUITE = "cipher_suite"
    KEY_EXCHANGE = "key_exchange"
    FORWARD_SECRECY = "forward_secrecy"
    CERTIFICATE = "certificate"
    AUTHENTICATION = "authentication"
    HANDSHAKE = "handshake"
    DOWNGRADE = "downgrade"
    ANOMALY = "anomaly"
    OTHER = "other"


class Remediation(BaseModel):
    """Structured remediation guidance attached to a finding.

    Kept factual and generic; vendor-specific commands are never
    fabricated because the actual server configuration is not known.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    action: str
    target: str | None = None
    rationale: str | None = None
    priority: str | None = None


class StandardReference(BaseModel):
    """A documented standard/policy reference.

    Only include identifiers that are known and documented; when no
    precise reference is established, use ``None`` instead of inventing
    one.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str
    url: str | None = None


class EvidenceRef(BaseModel):
    """A pointer from a finding back to the evidence it is based on."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    source: str
    packet_numbers: list[int] = Field(default_factory=list)
    detail: str | None = None


class SecurityFinding(ForensicBase):
    """One deterministic, rule-derived finding.

    The identifier is deterministic — ``finding_<hash of rule + session +
    observed condition>`` — so re-analysis of the same evidence produces
    the same ids and duplicate findings collapse naturally.
    """

    capture_id: str | None = None
    session_id: str | None = None
    protocol: str | None = None
    title: str = Field(min_length=1, max_length=200)
    description: str = Field(min_length=1)
    severity: FindingSeverity
    confidence: Confidence = Confidence.HIGH
    category: FindingCategory
    rule_id: str
    evidence_refs: list[EvidenceRef] = Field(default_factory=list)
    observed_value: str | None = None
    expected_value: str | None = None
    remediation: Remediation | None = None
    standard_reference: StandardReference | None = None
    first_packet: int | None = None
    last_packet: int | None = None
    details: dict[str, Any] = Field(default_factory=dict)
    detected_at: AwareDatetime = Field(default_factory=utc_now)
