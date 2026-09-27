"""Certificate rules: validity, key strength, signature algorithm, identity."""

from typing import Final

from engine.core.certificate import CertificateEvidence
from engine.core.findings import (
    EvidenceRef,
    FindingCategory,
    FindingSeverity,
    SecurityFinding,
    StandardReference,
)
from engine.core.session import Confidence, Session
from engine.detection.base import RuleContext, build_finding

_VALIDITY_RULE_ID: Final[str] = "CERT-VALIDITY-001"
_KEY_RULE_ID: Final[str] = "CERT-KEY-001"
_SIGNATURE_RULE_ID: Final[str] = "CERT-SIG-001"
_IDENTITY_RULE_ID: Final[str] = "CERT-IDENTITY-001"

_EXPIRED_STANDARD: Final[StandardReference] = StandardReference(
    name="RFC 5280 (Internet X.509 PKI Certificate and CRL Profile)",
    url="https://www.rfc-editor.org/rfc/rfc5280.html",
)
_WEAK_KEY_STANDARD: Final[StandardReference] = StandardReference(
    name=("NIST SP 800-57 Part 1 (Key Management: Recommendation for Key Sizes)"),
    url="https://csrc.nist.gov/publications/detail/sp/800-57/part-1/rev-5/final",
)
_SHA1_STANDARD: Final[StandardReference] = StandardReference(
    name=(
        "RFC 6151 (Updated Security Considerations for the MD5 Message-Digest"
        " and the HMAC-MD5 Algorithms)"
    ),
    url="https://www.rfc-editor.org/rfc/rfc6151.html",
)

_LEAF_RULE_REF: Final[str] = "Certificate(0)"


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


class CertificateValidityRule:
    """Evaluate certificate validity against the CAPTURE timestamp.

    The reference instant is the session's first observed packet time —
    never the analysis host's current date.
    """

    rule_id = _VALIDITY_RULE_ID
    name = "Certificate validity window does not cover the capture time"
    description = (
        "The certificate's validity window did not cover the moment the traffic was captured."
    )
    category = FindingCategory.CERTIFICATE
    default_severity = FindingSeverity.HIGH

    def evaluate(self, context: RuleContext) -> list[SecurityFinding]:
        session = context.session
        certificate = _leaf(session)
        if certificate is None or session.started_at is None:
            return []  # no capture-time evidence: nothing to claim

        capture_time = session.started_at
        if capture_time > certificate.not_after:
            finding_type = "expired_at_capture"
            observed = f"valid until {certificate.not_after.isoformat()}"
            severity = FindingSeverity.HIGH
        elif capture_time < certificate.not_before:
            finding_type = "not_yet_valid_at_capture"
            observed = f"valid from {certificate.not_before.isoformat()}"
            severity = FindingSeverity.MEDIUM
        else:
            return []

        return [
            build_finding(
                rule_id=self.rule_id,
                name=self.name,
                description=(
                    f"The certificate was {finding_type.replace('_', ' ')}: the "
                    f"capture time ({capture_time.isoformat()}) falls outside the "
                    f"certificate validity window ({observed})."
                ),
                category=self.category,
                severity=severity,
                confidence=Confidence.HIGH,
                session=session,
                evidence_refs=[_cert_evidence_ref(certificate)],
                observed_value=observed,
                expected_value="certificate valid at capture time",
                remediation={
                    "action": (
                        "Replace the certificate with one whose validity covers the capture period"
                    ),
                    "target": "mail server certificate configuration",
                    "rationale": "Clients reject certificates outside their validity window",
                    "priority": "high" if severity is FindingSeverity.HIGH else "medium",
                },
                standard_reference=_EXPIRED_STANDARD,
                protocol=session.protocol.value if session.protocol else None,
                extra_condition=finding_type,
            )
        ]


class CertificateKeyRule:
    """Evaluate the leaf certificate's public key against policy minimums.

    Unknown key algorithms are never judged — they produce an
    informational observation only.
    """

    rule_id = _KEY_RULE_ID
    name = "Weak certificate public key"
    description = (
        "The leaf certificate's public key is below the minimum size the "
        "baseline requires for its algorithm."
    )
    category = FindingCategory.CERTIFICATE
    default_severity = FindingSeverity.HIGH

    def evaluate(self, context: RuleContext) -> list[SecurityFinding]:
        session = context.session
        certificate = _leaf(session)
        policy = context.policy.certificates
        if certificate is None or certificate.public_key_algorithm is None:
            return []

        algorithm = certificate.public_key_algorithm
        key_size = certificate.public_key_size_bits
        minimums = {
            "RSA": policy.minimum_rsa_bits,
            "DSA": policy.minimum_dsa_bits,
            "EC": policy.minimum_ec_bits,
        }
        if algorithm not in minimums or key_size is None:
            return [
                build_finding(
                    rule_id=self.rule_id,
                    name="Certificate key algorithm not recognized by policy",
                    description=(
                        f"The certificate public key algorithm ({algorithm}) is not "
                        "covered by the policy minimums. No security classification "
                        "is made."
                    ),
                    category=self.category,
                    severity=FindingSeverity.INFO,
                    confidence=Confidence.HIGH,
                    session=session,
                    evidence_refs=[_cert_evidence_ref(certificate)],
                    observed_value=(
                        f"{algorithm} {key_size if key_size is not None else ''}".strip()
                    ),
                    expected_value=None,
                    remediation=None,
                    standard_reference=None,
                    protocol=session.protocol.value if session.protocol else None,
                )
            ]

        minimum = minimums[algorithm]
        if key_size >= minimum:
            return []
        return [
            build_finding(
                rule_id=self.rule_id,
                name=self.name,
                description=(
                    f"The certificate uses a {algorithm} key of {key_size} bits, "
                    f"below the baseline minimum of {minimum} bits."
                ),
                category=self.category,
                severity=FindingSeverity.HIGH,
                confidence=Confidence.HIGH,
                session=session,
                evidence_refs=[_cert_evidence_ref(certificate)],
                observed_value=f"{algorithm} {key_size} bits",
                expected_value=f"{algorithm} at least {minimum} bits",
                remediation={
                    "action": "Reissue the certificate with a stronger key",
                    "target": "mail server certificate configuration",
                    "rationale": (
                        "Keys below the policy minimum are within reach of practical attacks"
                    ),
                    "priority": "high",
                },
                standard_reference=_WEAK_KEY_STANDARD,
                protocol=session.protocol.value if session.protocol else None,
            )
        ]


class CertificateSignatureRule:
    """Evaluate the leaf certificate's signature algorithm class.

    MD5 and SHA-1 signatures are prohibited by the baseline; modern
    SHA-2 families pass; unknown algorithms are informational only.
    """

    rule_id = _SIGNATURE_RULE_ID
    name = "Weak certificate signature algorithm"
    description = (
        "The leaf certificate's signature algorithm is prohibited by the "
        "baseline (collision-prone digest)."
    )
    category = FindingCategory.CERTIFICATE
    default_severity = FindingSeverity.HIGH

    def evaluate(self, context: RuleContext) -> list[SecurityFinding]:
        session = context.session
        certificate = _leaf(session)
        if certificate is None:
            return []

        algorithm_lower = certificate.signature_algorithm.lower()
        for weak in context.policy.certificates.weak_signature_algorithms:
            if weak in algorithm_lower:
                known = weak == "md5"
                return [
                    build_finding(
                        rule_id=self.rule_id,
                        name=self.name,
                        description=(
                            f"The certificate signature uses {weak.upper()} "
                            f"({certificate.signature_algorithm}). The baseline "
                            "prohibits this digest"
                            + (
                                " because collision attacks make signature forgery practical."
                                if known
                                else "."
                            )
                        ),
                        category=self.category,
                        severity=FindingSeverity.CRITICAL if known else FindingSeverity.HIGH,
                        confidence=Confidence.HIGH,
                        session=session,
                        evidence_refs=[_cert_evidence_ref(certificate)],
                        observed_value=certificate.signature_algorithm,
                        expected_value="SHA-256/SHA-384/SHA-512 family signature",
                        remediation={
                            "action": "Reissue the certificate signed with a SHA-2 family digest",
                            "target": "issuing CA configuration",
                            "rationale": "Weak digest signatures allow certificate forgery",
                            "priority": "high",
                        },
                        standard_reference=_SHA1_STANDARD,
                        protocol=session.protocol.value if session.protocol else None,
                    )
                ]
        return []


class CertificateIdentityRule:
    """Compare the observed SNI against the leaf certificate's SANs.

    Findings require BOTH sides of the comparison: when SNI or SAN
    evidence is unavailable the identity check is recorded as unknown and
    no mismatch is claimed.
    """

    rule_id = _IDENTITY_RULE_ID
    name = "Certificate does not match the requested hostname"
    description = (
        "The certificate's subject alternative names do not cover the "
        "server name the client requested (SNI)."
    )
    category = FindingCategory.CERTIFICATE
    default_severity = FindingSeverity.HIGH

    @staticmethod
    def _matches(sni: str, san: str) -> bool:
        san = san.lower().lstrip("*")
        sni = sni.lower()
        if san.startswith("."):
            suffix = san  # wildcard: match any single left-most label chain
            return sni.endswith(suffix) and sni != suffix
        return sni == san

    def evaluate(self, context: RuleContext) -> list[SecurityFinding]:
        session = context.session
        certificate = _leaf(session)
        handshake = session.handshake
        if (
            certificate is None
            or handshake is None
            or not context.policy.certificates.require_san_match_when_evidence_allows
        ):
            return []
        sni = handshake.sni_server_name
        if not sni or not certificate.subject_alternative_names:
            return []  # insufficient identity evidence: record nothing

        matched = any(self._matches(sni, san) for san in certificate.subject_alternative_names)
        if matched:
            return []
        return [
            build_finding(
                rule_id=self.rule_id,
                name=self.name,
                description=(
                    f"The client requested '{sni}' via SNI, but the certificate's "
                    "subject alternative names ("
                    f"{', '.join(certificate.subject_alternative_names)}) "
                    "do not cover that hostname."
                ),
                category=self.category,
                severity=FindingSeverity.HIGH,
                confidence=Confidence.HIGH,
                session=session,
                evidence_refs=[
                    _cert_evidence_ref(certificate),
                    EvidenceRef(
                        source="ClientHello",
                        packet_numbers=handshake.client_hello_packets,
                        detail=f"SNI {sni}",
                    ),
                ],
                observed_value=(
                    f"SNI {sni} vs SANs {', '.join(certificate.subject_alternative_names)}"
                ),
                expected_value="a certificate covering the requested hostname",
                remediation={
                    "action": ("Issue a certificate covering the hostname the clients connect to"),
                    "target": "mail server certificate configuration",
                    "rationale": (
                        "Hostname verification fails when the certificate does not cover the SNI"
                    ),
                    "priority": "high",
                },
                standard_reference=_EXPIRED_STANDARD,
                protocol=session.protocol.value if session.protocol else None,
            )
        ]
