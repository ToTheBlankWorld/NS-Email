"""Cipher suite policy rules: classification-driven, never string-matched.

The selected suite's code is classified through the Stage 3 registry
(modern AEAD / legacy / deprecated / prohibited / unknown). Unknown codes
produce an informational observation and are never called weak.
"""

from typing import Final

from engine.core.findings import (
    EvidenceRef,
    FindingCategory,
    FindingSeverity,
    SecurityFinding,
)
from engine.core.session import Confidence
from engine.crypto.cipher_suites import CipherClass, classify_cipher_suite
from engine.detection.base import RuleContext, build_finding

_SELECTED_RULE_ID: Final[str] = "CIPHER-SELECTED-001"
_UNKNOWN_RULE_ID: Final[str] = "CIPHER-UNKNOWN-001"

# Severity by unacceptable classification. Prohibited families (RC4,
# NULL, export, anonymous) are cryptographically broken or unauthenticated
# and rank CRITICAL; deprecated families (3DES/DES-CBC) carry practical
# limits (SWEET32) and rank MEDIUM.
_SEVERITY_BY_CLASS: Final[dict[CipherClass, FindingSeverity]] = {
    CipherClass.PROHIBITED: FindingSeverity.CRITICAL,
    CipherClass.DEPRECATED: FindingSeverity.MEDIUM,
    CipherClass.LEGACY: FindingSeverity.LOW,
}


class CipherSuiteRule:
    """Evaluate the selected cipher suite against the policy classes."""

    rule_id = _SELECTED_RULE_ID
    name = "Unacceptable cipher suite negotiated"
    description = (
        "The negotiated cipher suite falls into a classification the "
        "configured baseline does not accept."
    )
    category = FindingCategory.CIPHER_SUITE
    default_severity = FindingSeverity.MEDIUM

    def evaluate(self, context: RuleContext) -> list[SecurityFinding]:
        session = context.session
        handshake = session.handshake
        if handshake is None or handshake.cipher_suite_code is None:
            return []

        classification = classify_cipher_suite(handshake.cipher_suite_code)
        if classification not in context.policy.cipher_suites.finding_classes:
            return []
        severity = _SEVERITY_BY_CLASS.get(classification, FindingSeverity.MEDIUM)

        return [
            build_finding(
                rule_id=self.rule_id,
                name=self.name,
                description=(
                    f"The negotiated cipher suite {handshake.cipher_suite} is "
                    f"classified as {classification.value} in the suite registry."
                ),
                category=self.category,
                severity=severity,
                confidence=(Confidence.HIGH if handshake.handshake_complete else Confidence.MEDIUM),
                session=session,
                evidence_refs=[
                    EvidenceRef(
                        source="ServerHello",
                        packet_numbers=handshake.server_hello_packets,
                        detail=f"selected suite {handshake.cipher_suite}",
                    )
                ],
                observed_value=handshake.cipher_suite or "",
                expected_value="a cipher suite in an accepted classification",
                remediation={
                    "action": "Disable the affected cipher suite family",
                    "target": "mail server TLS configuration",
                    "rationale": (
                        "The suite classification "
                        f"({classification.value}) is not accepted by the baseline"
                    ),
                    "priority": "high" if severity is FindingSeverity.CRITICAL else "medium",
                },
                standard_reference=None,
                protocol=session.protocol.value if session.protocol else None,
            )
        ]


class UnknownCipherSuiteRule:
    """Record unknown suite codes as observations — never as weakness."""

    rule_id = _UNKNOWN_RULE_ID
    name = "Cipher suite not in the local registry"
    description = (
        "The negotiated cipher suite is not present in the local registry. "
        "It is NOT classified as weak; the observation is informational."
    )
    category = FindingCategory.CIPHER_SUITE
    default_severity = FindingSeverity.INFO

    def evaluate(self, context: RuleContext) -> list[SecurityFinding]:
        session = context.session
        handshake = session.handshake
        if handshake is None or handshake.cipher_suite_code is None:
            return []
        if classify_cipher_suite(handshake.cipher_suite_code) is not CipherClass.UNKNOWN:
            return []

        return [
            build_finding(
                rule_id=self.rule_id,
                name=self.name,
                description=(
                    f"The negotiated cipher suite {handshake.cipher_suite} is not "
                    "in the local registry. No security classification can be "
                    "made without registry coverage."
                ),
                category=self.category,
                severity=FindingSeverity.INFO,
                confidence=Confidence.MEDIUM,
                session=session,
                evidence_refs=[
                    EvidenceRef(
                        source="ServerHello",
                        packet_numbers=handshake.server_hello_packets,
                        detail=f"selected suite {handshake.cipher_suite}",
                    )
                ],
                observed_value=handshake.cipher_suite or "",
                expected_value=None,
                remediation=None,
                standard_reference=None,
                protocol=session.protocol.value if session.protocol else None,
            )
        ]
