"""STARTTLS, plaintext-authentication, TLS-failure, and plaintext rules.

These rules combine Stage 2 plaintext conversation evidence with Stage 3
TLS evidence. Implicit-TLS sessions never require STARTTLS, and evidence
wording stays observational: a failed handshake is never called an attack.
"""

from typing import Final

from engine.core.events import EventType
from engine.core.findings import (
    EvidenceRef,
    FindingCategory,
    FindingSeverity,
    SecurityFinding,
)
from engine.core.session import Confidence, Session
from engine.detection.base import RuleContext, build_finding

_STARTTLS_RULE_ID: Final[str] = "STARTTLS-001"
_AUTH_RULE_ID: Final[str] = "AUTH-PLAINTEXT-001"
_FAILURE_RULE_ID: Final[str] = "TLS-FAILURE-001"
_PLAINTEXT_RULE_ID: Final[str] = "PLAINTEXT-001"

_NO_TLS_STANDARD: Final[dict[str, str]] = {
    "action": "Configure mail clients and servers to use TLS wherever the peer supports it",
    "target": "mail transport configuration",
    "rationale": "Plaintext email transport exposes content and credentials on the wire",
    "priority": "high",
}


def _starttls_evidence(session: Session, detail: str) -> EvidenceRef:
    starttls = session.starttls
    return EvidenceRef(
        source="STARTTLS negotiation",
        packet_numbers=[starttls.packet_number] if starttls and starttls.packet_number else [],
        detail=detail,
    )


class StarttlsRule:
    """Evaluate the STARTTLS negotiation lifecycle for non-implicit TLS."""

    rule_id = _STARTTLS_RULE_ID
    name = "STARTTLS negotiation incomplete"
    description = (
        "The plaintext STARTTLS negotiation did not result in a completed "
        "TLS transition as observed in the capture."
    )
    category = FindingCategory.STARTTLS
    default_severity = FindingSeverity.MEDIUM

    def evaluate(self, context: RuleContext) -> list[SecurityFinding]:
        session = context.session
        starttls = session.starttls
        if session.implicit_tls or starttls is None:
            return []

        protocol = session.protocol.value if session.protocol else None

        if starttls.advertised and not starttls.requested:
            return [
                build_finding(
                    rule_id=self.rule_id,
                    name="STARTTLS advertised but never requested",
                    description=(
                        "The server advertised STARTTLS support, but the client "
                        "never requested it, so the session stayed in plaintext."
                    ),
                    category=self.category,
                    severity=FindingSeverity.MEDIUM,
                    confidence=Confidence.HIGH,
                    session=session,
                    evidence_refs=[_starttls_evidence(session, "advertised, not requested")],
                    observed_value="STARTTLS advertised; no request observed",
                    expected_value="client requests STARTTLS when advertised",
                    remediation=_NO_TLS_STANDARD,
                    standard_reference=None,
                    protocol=protocol,
                    extra_condition="advertised-not-requested",
                )
            ]

        if starttls.requested and not starttls.response_seen:
            return [
                build_finding(
                    rule_id=self.rule_id,
                    name="STARTTLS requested but not accepted",
                    description=(
                        "The client requested STARTTLS, but no acceptance "
                        "response was observed in the capture."
                    ),
                    category=self.category,
                    severity=FindingSeverity.MEDIUM,
                    confidence=Confidence.HIGH,
                    session=session,
                    evidence_refs=[
                        _starttls_evidence(session, "requested, no acceptance observed")
                    ],
                    observed_value="STARTTLS requested; no acceptance observed",
                    expected_value="server accepts STARTTLS and TLS follows",
                    remediation=_NO_TLS_STANDARD,
                    standard_reference=None,
                    protocol=protocol,
                    extra_condition="requested-not-accepted",
                )
            ]

        if starttls.response_seen and (
            session.handshake is None or not session.handshake.client_hello_packets
        ):
            return [
                build_finding(
                    rule_id=self.rule_id,
                    name="TLS handshake not observed after STARTTLS acceptance",
                    description=(
                        "The STARTTLS acceptance response was observed, but no TLS "
                        "handshake followed within the capture. This may reflect a "
                        "capture limitation; no conclusion beyond the observation "
                        "is drawn."
                    ),
                    category=self.category,
                    severity=FindingSeverity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    session=session,
                    evidence_refs=[_starttls_evidence(session, "accepted; no handshake observed")],
                    observed_value="no TLS handshake after acceptance",
                    expected_value="a TLS handshake following the accepted STARTTLS",
                    remediation=None,
                    standard_reference=None,
                    protocol=protocol,
                    extra_condition="accepted-no-handshake",
                )
            ]
        return []


class PlaintextAuthenticationRule:
    """Authentication commands observed outside TLS.

    The rule consumes Stage 2's redacted authentication events: command
    shapes only — actual credential values were never stored.
    """

    rule_id = _AUTH_RULE_ID
    name = "Authentication command observed in plaintext"
    description = (
        "An authentication command crossed the wire outside TLS, exposing "
        "credential material to passive observation. The credential values "
        "are redacted throughout NS-Email."
    )
    category = FindingCategory.AUTHENTICATION
    default_severity = FindingSeverity.HIGH

    def evaluate(self, context: RuleContext) -> list[SecurityFinding]:
        session = context.session
        auth_events = [event for event in session.events if event.type is EventType.AUTHENTICATION]
        if not auth_events:
            return []

        observed = ", ".join(
            event.detail.get("command") or event.detail.get("mechanism") or "AUTH"
            for event in auth_events
        )
        packet_numbers = sorted(
            {number for event in auth_events for number in event.packet_numbers}
        )
        return [
            build_finding(
                rule_id=self.rule_id,
                name=self.name,
                description=(
                    f"Plaintext authentication was observed ({observed}) before "
                    "TLS protection (or without TLS entirely). Credential values "
                    "are redacted; the observation records the command shape only."
                ),
                category=self.category,
                severity=FindingSeverity.HIGH,
                confidence=Confidence.HIGH,
                session=session,
                evidence_refs=[
                    EvidenceRef(
                        source="SessionEvents",
                        packet_numbers=packet_numbers,
                        detail=f"authentication commands: {observed}",
                    )
                ],
                observed_value=observed,
                expected_value="authentication inside TLS",
                remediation={
                    "action": "Require TLS before authentication (reject plaintext AUTH/LOGIN)",
                    "target": "mail server and client configuration",
                    "rationale": "Plaintext authentication exposes credentials to passive capture",
                    "priority": "high",
                },
                standard_reference=None,
                protocol=session.protocol.value if session.protocol else None,
            )
        ]


class TlsFailureRule:
    """TLS handshake terminated before completion — observation only.

    A failed handshake is never attributed to an attack; the wording
    describes exactly what the capture shows.
    """

    rule_id = _FAILURE_RULE_ID
    name = "TLS handshake terminated before completion"
    description = (
        "The observed TLS handshake did not progress to completion, so the "
        "session did not establish TLS protection within the capture."
    )
    category = FindingCategory.HANDSHAKE
    default_severity = FindingSeverity.INFO

    def evaluate(self, context: RuleContext) -> list[SecurityFinding]:
        session = context.session
        handshake = session.handshake
        if (
            handshake is None
            or handshake.handshake_complete
            or handshake.handshake_complete is None
        ):
            return []

        return [
            build_finding(
                rule_id=self.rule_id,
                name=self.name,
                description=(
                    "The TLS handshake ended before completion "
                    f"({handshake.completeness_reason or 'reason unknown'}). "
                    "An aborted handshake has many benign causes, including "
                    "policy rejection and capture truncation."
                ),
                category=self.category,
                severity=FindingSeverity.INFO,
                confidence=Confidence.MEDIUM,
                session=session,
                evidence_refs=[
                    EvidenceRef(
                        source="ClientHello",
                        packet_numbers=handshake.client_hello_packets,
                        detail="handshake began",
                    )
                ],
                observed_value="incomplete TLS handshake",
                expected_value=None,
                remediation=None,
                standard_reference=None,
                protocol=session.protocol.value if session.protocol else None,
            )
        ]


class PlaintextSessionRule:
    """An email session that never used TLS at all."""

    rule_id = _PLAINTEXT_RULE_ID
    name = "Email session remained in plaintext"
    description = (
        "An identified email session carried its entire conversation in "
        "plaintext — no STARTTLS negotiation and no TLS handshake occurred."
    )
    category = FindingCategory.STARTTLS
    default_severity = FindingSeverity.MEDIUM

    def evaluate(self, context: RuleContext) -> list[SecurityFinding]:
        session = context.session
        if session.protocol is None or session.implicit_tls or session.handshake is not None:
            return []
        if session.starttls is not None and session.starttls.response_seen:
            return []

        return [
            build_finding(
                rule_id=self.rule_id,
                name=self.name,
                description=(
                    "The session used no TLS at all: every observed byte was "
                    "plaintext email protocol traffic."
                ),
                category=self.category,
                severity=FindingSeverity.MEDIUM,
                confidence=Confidence.HIGH,
                session=session,
                evidence_refs=[
                    EvidenceRef(
                        source="SessionEvents",
                        packet_numbers=[],
                        detail="no TLS records or STARTTLS transition observed",
                    )
                ],
                observed_value="no TLS",
                expected_value="TLS-protected email transport",
                remediation=_NO_TLS_STANDARD,
                standard_reference=None,
                protocol=session.protocol.value if session.protocol else None,
            )
        ]
