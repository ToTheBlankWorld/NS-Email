"""Rule registry and deterministic evaluation entry points."""

from typing import Final

from engine.core.findings import SecurityFinding
from engine.core.session import Session
from engine.detection.base import RuleContext, SecurityRule
from engine.detection.policy import Policy
from engine.detection.rules.certificate_chain import CertificateChainRule, CertificateSelfSignedRule
from engine.detection.rules.certificate_rules import (
    CertificateIdentityRule,
    CertificateKeyRule,
    CertificateSignatureRule,
    CertificateValidityRule,
)
from engine.detection.rules.cipher_suite import CipherSuiteRule, UnknownCipherSuiteRule
from engine.detection.rules.key_exchange import ForwardSecrecyRule, KeyExchangeRule
from engine.detection.rules.starttls import (
    PlaintextAuthenticationRule,
    PlaintextSessionRule,
    StarttlsRule,
    TlsFailureRule,
)
from engine.detection.rules.tls_version import TlsVersionRule


class RuleRegistry:
    """Ordered registry of active security rules."""

    def __init__(self) -> None:
        self._rules: list[SecurityRule] = []

    def register(self, rule: SecurityRule) -> None:
        self._rules.append(rule)

    def rules(self) -> list[SecurityRule]:
        return list(self._rules)


def default_registry() -> RuleRegistry:
    """The registry used by analysis: every built-in rule, stable order."""
    registry = RuleRegistry()
    registry.register(TlsVersionRule())
    registry.register(CipherSuiteRule())
    registry.register(UnknownCipherSuiteRule())
    registry.register(KeyExchangeRule())
    registry.register(ForwardSecrecyRule())
    registry.register(CertificateValidityRule())
    registry.register(CertificateKeyRule())
    registry.register(CertificateSignatureRule())
    registry.register(CertificateIdentityRule())
    registry.register(CertificateChainRule())
    registry.register(CertificateSelfSignedRule())
    registry.register(StarttlsRule())
    registry.register(PlaintextAuthenticationRule())
    registry.register(TlsFailureRule())
    registry.register(PlaintextSessionRule())
    return registry


def evaluate_session(session: Session, policy: Policy) -> list[SecurityFinding]:
    """Run every registered rule against one session, deduplicating by id."""
    registry = default_registry()
    context = RuleContext(session=session, policy=policy)
    findings_by_id: dict[str, SecurityFinding] = {}
    for rule in registry.rules():
        for finding in rule.evaluate(context):
            findings_by_id.setdefault(finding.id, finding)
    return list(findings_by_id.values())


def evaluate_sessions(sessions: list[Session], policy: Policy) -> list[SecurityFinding]:
    """Run rules independently per session — findings never merge hosts."""
    findings: list[SecurityFinding] = []
    seen: Final[set[str]] = set()
    for session in sessions:
        for finding in evaluate_session(session, policy):
            if finding.id in seen:  # pragma: no cover - ids are session-scoped
                continue
            seen.add(finding.id)
            findings.append(finding)
    return findings
