"""TLS version policy rule.

Evaluates the ACTUAL negotiated version (ServerHello evidence) against the
baseline. Offered versions never produce a version finding: a client may
offer TLS 1.3 while a server downgrades to TLS 1.0 — the finding must
describe what was negotiated.
"""

from typing import Final

from engine.core.findings import (
    EvidenceRef,
    FindingCategory,
    FindingSeverity,
    SecurityFinding,
    StandardReference,
)
from engine.core.session import Confidence
from engine.core.tls import TLSVersion
from engine.detection.base import RuleContext, build_finding

_RULE_ID: Final[str] = "TLS-VERSION-001"

_VERSION_RANK: Final[dict[str, int]] = {
    "SSL 2.0": 0,
    "SSL 3.0": 1,
    "TLS 1.0": 2,
    "TLS 1.1": 3,
    "TLS 1.2": 4,
    "TLS 1.3": 5,
}

# Severity by negotiated version: SSL protocol versions are broken in
# practice (POODLE/DROWN) and rank CRITICAL; TLS 1.0/1.1 are formally
# deprecated by RFC 8996 and rank HIGH.
_CRITICAL_VERSIONS: Final[frozenset[str]] = frozenset({"SSL 2.0", "SSL 3.0"})

_STANDARD: Final[StandardReference] = StandardReference(
    name="RFC 8996 (Deprecating TLS 1.0 and TLS 1.1)",
    url="https://www.rfc-editor.org/rfc/rfc8996.html",
)


class TlsVersionRule:
    rule_id = _RULE_ID
    name = "Deprecated TLS version negotiated"
    description = (
        "The session negotiated a TLS protocol version below the configured "
        "minimum, or a version that is formally deprecated."
    )
    category = FindingCategory.PROTOCOL_VERSION
    default_severity = FindingSeverity.HIGH

    def evaluate(self, context: RuleContext) -> list[SecurityFinding]:
        session = context.session
        handshake = session.handshake
        if handshake is None or handshake.tls_version is TLSVersion.UNKNOWN:
            return []

        negotiated = handshake.tls_version.value
        minimum = context.policy.tls.minimum_version
        minimum_rank = _VERSION_RANK.get(minimum)
        negotiated_rank = _VERSION_RANK.get(negotiated)
        if negotiated_rank is None or minimum_rank is None:
            return []  # unknown version names are never judged

        confidence = Confidence.HIGH if handshake.handshake_complete else Confidence.MEDIUM
        evidence = EvidenceRef(
            source="ServerHello",
            packet_numbers=handshake.server_hello_packets,
            detail=f"negotiated {negotiated}",
        )

        if negotiated in context.policy.tls.deprecated_versions:
            severity = (
                FindingSeverity.CRITICAL
                if negotiated in _CRITICAL_VERSIONS
                else FindingSeverity.HIGH
            )
            return [
                build_finding(
                    rule_id=_RULE_ID,
                    name=self.name,
                    description=(
                        f"The session negotiated {negotiated}, which is formally "
                        "deprecated and must not be relied on for transport security."
                    ),
                    category=self.category,
                    severity=severity,
                    confidence=confidence,
                    session=session,
                    evidence_refs=[evidence],
                    observed_value=negotiated,
                    expected_value=f"{minimum} or later",
                    remediation={
                        "action": f"Disable {negotiated} and require {minimum} or later",
                        "target": "mail server TLS configuration",
                        "rationale": "Deprecated protocol versions have known practical attacks",
                        "priority": "high",
                    },
                    standard_reference=_STANDARD,
                    protocol=session.protocol.value if session.protocol else None,
                )
            ]

        if negotiated_rank < minimum_rank:
            return [
                build_finding(
                    rule_id=_RULE_ID,
                    name=self.name,
                    description=(
                        f"The session negotiated {negotiated}, which is below the "
                        f"configured baseline minimum of {minimum}."
                    ),
                    category=self.category,
                    severity=FindingSeverity.LOW,
                    confidence=confidence,
                    session=session,
                    evidence_refs=[evidence],
                    observed_value=negotiated,
                    expected_value=f"{minimum} or later",
                    remediation={
                        "action": f"Configure the service to prefer {minimum} or later",
                        "target": "mail server TLS configuration",
                        "rationale": "The configured baseline requires a higher minimum version",
                        "priority": "low",
                    },
                    standard_reference=None,
                    protocol=session.protocol.value if session.protocol else None,
                )
            ]
        return []
