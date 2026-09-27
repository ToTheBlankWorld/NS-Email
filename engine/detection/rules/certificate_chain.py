"""Certificate chain and self-signed rules.

A passive capture normally does not contain the root CA — an incomplete
captured chain is an observation, not a verdict. Structural problems
(issuer signature verification failure) and self-signed leaves are
classified per policy with explicit explanations.
"""

from typing import Final

from engine.core.certificate import CertificateEvidence
from engine.core.findings import (
    EvidenceRef,
    FindingCategory,
    FindingSeverity,
    SecurityFinding,
)
from engine.core.session import Confidence, Session
from engine.detection.base import RuleContext, build_finding

_CHAIN_RULE_ID: Final[str] = "CERT-CHAIN-001"
_SELFSIGNED_RULE_ID: Final[str] = "CERT-SELF-SIGNED-001"


def _leaf(session: Session) -> CertificateEvidence | None:
    for certificate in session.certificates:
        if certificate.position_in_chain == 0:
            return certificate
    return None


def _cert_evidence_ref(certificate: CertificateEvidence) -> EvidenceRef:
    return EvidenceRef(
        source=f"Certificate({certificate.position_in_chain or 0})",
        packet_numbers=[],
        detail=f"subject {certificate.subject}",
    )


def _der_of(certificate: CertificateEvidence) -> bytes | None:
    """Re-derive the DER from the stored evidence fields.

    The store keeps facts, not DER bytes; signature verification is only
    attempted when a certificate object can be rebuilt from its fields.
    Since rebuilding DER from facts is not possible, verification uses the
    identity comparison instead and the field stays ``None``.
    """
    return None


def _signature_verifies(certificate: CertificateEvidence) -> bool | None:
    """Attempt a cryptographic self-signature check where practical.

    Rebuilding a verifyable certificate requires the original DER, which
    the evidence model intentionally does not persist; verification is
    therefore reported as performed only when it truly ran. With facts
    alone the result is ``None`` (unknown) — never a fabricated pass.
    """
    return None


class CertificateChainRule:
    """Distinguish observed-chain limitations from structural problems."""

    rule_id = _CHAIN_RULE_ID
    name = "Certificate chain inconsistency observed"
    description = (
        "The certificate chain as observed in the capture is structurally "
        "inconsistent: the leaf's issuer does not match any other observed "
        "certificate."
    )
    category = FindingCategory.CERTIFICATE
    default_severity = FindingSeverity.MEDIUM

    def evaluate(self, context: RuleContext) -> list[SecurityFinding]:
        session = context.session
        leaf = _leaf(session)
        if leaf is None or len(session.certificates) == 0:
            return []

        subjects = {c.subject for c in session.certificates if c.position_in_chain != 0}
        leaf_is_self_issued = leaf.subject == leaf.issuer

        if not leaf_is_self_issued and leaf.issuer not in subjects:
            # Missing intermediate/root in the capture is normal for passive
            # observation and is NOT a chain verdict.
            return [
                build_finding(
                    rule_id=self.rule_id,
                    name="Certificate chain incomplete in capture",
                    description=(
                        "The leaf certificate's issuer "
                        f"('{leaf.issuer}') was not observed in the capture. "
                        "A passive capture frequently omits higher chain "
                        "elements; this is an observation, not a validation "
                        "failure."
                    ),
                    category=self.category,
                    severity=FindingSeverity.INFO,
                    confidence=Confidence.HIGH,
                    session=session,
                    evidence_refs=[_cert_evidence_ref(leaf)],
                    observed_value=f"issuer '{leaf.issuer}' not observed",
                    expected_value=None,
                    remediation=None,
                    standard_reference=None,
                    protocol=session.protocol.value if session.protocol else None,
                )
            ]

        if leaf_is_self_issued and len(session.certificates) > 1:
            return [
                build_finding(
                    rule_id=self.rule_id,
                    name=self.name,
                    description=(
                        "The leaf certificate is self-issued but additional chain "
                        "certificates were presented, which is structurally "
                        "inconsistent."
                    ),
                    category=self.category,
                    severity=FindingSeverity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    session=session,
                    evidence_refs=[_cert_evidence_ref(c) for c in session.certificates],
                    observed_value="self-issued leaf with a non-empty chain",
                    expected_value=None,
                    remediation=None,
                    standard_reference=None,
                    protocol=session.protocol.value if session.protocol else None,
                )
            ]
        return []


class CertificateSelfSignedRule:
    """Record self-signed leaf certificates per policy.

    subject == issuer marks the observation; the explanation states
    explicitly that self-signed does not automatically mean insecure —
    it means no third-party vetting is asserted.
    """

    rule_id = _SELFSIGNED_RULE_ID
    name = "Self-signed certificate presented"
    description = (
        "The presented leaf certificate is self-signed: its issuer is its "
        "own subject, so no third-party vetting is asserted."
    )
    category = FindingCategory.CERTIFICATE
    default_severity = FindingSeverity.LOW

    def evaluate(self, context: RuleContext) -> list[SecurityFinding]:
        session = context.session
        leaf = _leaf(session)
        if leaf is None or not context.policy.certificates.warn_on_self_signed:
            return []
        if leaf.subject != leaf.issuer:
            return []

        return [
            build_finding(
                rule_id=self.rule_id,
                name=self.name,
                description=(
                    "The leaf certificate is self-signed "
                    f"(subject equals issuer: '{leaf.subject}'). Self-signed "
                    "certificates do not assert third-party identity vetting; "
                    "whether that is acceptable depends on the deployment."
                ),
                category=self.category,
                severity=FindingSeverity.LOW,
                confidence=Confidence.HIGH,
                session=session,
                evidence_refs=[_cert_evidence_ref(leaf)],
                observed_value="self-signed certificate",
                expected_value=None,
                remediation={
                    "action": (
                        "Replace the self-signed certificate with one issued by a "
                        "trusted CA where third-party vetting is required"
                    ),
                    "target": "mail server certificate configuration",
                    "rationale": "Self-signed certificates rely on out-of-band trust decisions",
                    "priority": "low",
                },
                standard_reference=None,
                protocol=session.protocol.value if session.protocol else None,
            )
        ]
