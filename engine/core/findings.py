"""Security findings produced by rule-based and analytical stages."""

from enum import StrEnum
from typing import Any

from pydantic import AwareDatetime, Field

from engine.core.base import ForensicBase, utc_now


class FindingSeverity(StrEnum):
    """Prioritization tiers applied during risk ranking."""

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
    DOWNGRADE = "downgrade"
    ANOMALY = "anomaly"
    OTHER = "other"


class SecurityFinding(ForensicBase):
    """A single security-relevant observation about analyzed evidence.

    Findings are produced by deterministic rules or analytical stages and
    always reference the evidence they are derived from, either directly
    via ``session_id``/``capture_id`` or via ``evidence_refs``.
    """

    capture_id: str | None = None
    session_id: str | None = None
    title: str = Field(min_length=1, max_length=200)
    description: str = Field(min_length=1)
    severity: FindingSeverity
    category: FindingCategory
    rule_id: str | None = None
    evidence_refs: list[str] = Field(default_factory=list)
    details: dict[str, Any] = Field(default_factory=dict)
    detected_at: AwareDatetime = Field(default_factory=utc_now)
