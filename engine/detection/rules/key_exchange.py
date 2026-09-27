"""Key-exchange and forward-secrecy rules.

The key-exchange rule flags mechanisms the policy prohibits (static RSA,
static DH/ECDH) — these lack forward secrecy. The forward-secrecy rule
additionally records an informational observation when the mechanism
could not be determined: unknown is never converted into a failure.
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
from engine.core.tls import KeyExchange
from engine.detection.base import RuleContext, build_finding

_KX_RULE_ID: Final[str] = "KEYEX-001"
_FS_RULE_ID: Final[str] = "FS-001"

_KX_NAMES: Final[dict[KeyExchange, str]] = {
    KeyExchange.RSA: "static RSA key exchange",
    KeyExchange.DH: "static DH key exchange",
    KeyExchange.ECDH: "static ECDH key exchange",
}

_STANDARD: Final[StandardReference] = StandardReference(
    name="RFC 7525 (BCP 195: Recommendations for Secure Use of TLS)",
    url="https://www.rfc-editor.org/rfc/rfc7525.html",
)


class KeyExchangeRule:
    rule_id = _KX_RULE_ID
    name = "Non-forward-secret key exchange negotiated"
    description = (
        "The negotiated key-exchange mechanism is prohibited by the "
        "baseline. Traffic protected this way lacks forward secrecy: an "
        "attacker that later obtains the server's long-term key can "
        "decrypt captured sessions."
    )
    category = FindingCategory.KEY_EXCHANGE
    default_severity = FindingSeverity.MEDIUM

    def evaluate(self, context: RuleContext) -> list[SecurityFinding]:
        session = context.session
        handshake = session.handshake
        if handshake is None or handshake.key_exchange is KeyExchange.UNKNOWN:
            return []
        if handshake.key_exchange not in context.policy.key_exchange.prohibited:
            return []
        mechanism = _KX_NAMES.get(handshake.key_exchange, handshake.key_exchange.value)

        return [
            build_finding(
                rule_id=self.rule_id,
                name=self.name,
                description=(
                    f"The session negotiated {mechanism}, which the baseline "
                    "prohibits because it does not provide forward secrecy."
                ),
                category=self.category,
                severity=FindingSeverity.MEDIUM,
                confidence=(Confidence.HIGH if handshake.handshake_complete else Confidence.MEDIUM),
                session=session,
                evidence_refs=[
                    EvidenceRef(
                        source="ServerHello",
                        packet_numbers=handshake.server_hello_packets,
                        detail=f"key exchange {handshake.key_exchange.value}",
                    )
                ],
                observed_value=handshake.key_exchange.value,
                expected_value="an ephemeral key-exchange mechanism",
                remediation={
                    "action": "Prefer suites with ephemeral (E)DHE key exchange or TLS 1.3",
                    "target": "mail server TLS configuration",
                    "rationale": "Forward secrecy protects past sessions from key compromise",
                    "priority": "medium",
                },
                standard_reference=_STANDARD,
                protocol=session.protocol.value if session.protocol else None,
            )
        ]


class ForwardSecrecyRule:
    """Record undeterminable forward secrecy as informational — never as failure."""

    rule_id = _FS_RULE_ID
    name = "Forward secrecy could not be determined"
    description = (
        "The handshake evidence does not identify the key-exchange "
        "mechanism, so forward secrecy cannot be assessed for this session."
    )
    category = FindingCategory.FORWARD_SECRECY
    default_severity = FindingSeverity.INFO

    def evaluate(self, context: RuleContext) -> list[SecurityFinding]:
        session = context.session
        handshake = session.handshake
        if handshake is None or handshake.key_exchange is not KeyExchange.UNKNOWN:
            return []

        return [
            build_finding(
                rule_id=self.rule_id,
                name=self.name,
                description=(
                    "The negotiated key-exchange mechanism could not be "
                    "determined from the observed handshake, so forward secrecy "
                    "cannot be assessed. No conclusion is drawn."
                ),
                category=self.category,
                severity=FindingSeverity.INFO,
                confidence=Confidence.LOW,
                session=session,
                evidence_refs=[
                    EvidenceRef(
                        source="ServerHello",
                        packet_numbers=handshake.server_hello_packets,
                        detail="key exchange undetermined",
                    )
                ],
                observed_value="unknown",
                expected_value=None,
                remediation=None,
                standard_reference=None,
                protocol=session.protocol.value if session.protocol else None,
            )
        ]
