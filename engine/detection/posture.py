"""Explainable cryptographic security posture (Stage 5).

Aggregates deterministic Stage 4 findings into a posture snapshot with a
transparent, documented scoring formula. The score is a SecureMailScope
Posture metric — an analytical construct defined in
``docs/decisions/005-security-posture-model.md`` — not an
industry-standard rating and not an AI/ML output.

Scoring formula (deterministic, bounded 0-100):

    finding deduction = severity_weight
                        x confidence_multiplier
                        x prevalence_multiplier
      severity weights:      critical 40, high 25, medium 12, low 5, info 0
      confidence multiplier: high 1.0, medium 0.75, low 0.5, unknown 0.25
      prevalence multiplier: 0.5 + 0.5 x (affected_sessions / total_sessions)

    factor deduction = highest finding deduction in the factor
                       + 0.25 x (sum of remaining deductions in the factor)

    overall score    = round(100 - sum of factor deductions), clamped to 0-100

Breadth inside a factor adds only 25% per additional condition, so the
same underlying misconfiguration observed ten times costs barely more
than once (no linear double-counting). Different factors represent
independent configuration problems and sum normally.
"""

import hashlib
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Final

from engine.core.findings import FindingSeverity, SecurityFinding
from engine.core.session import Confidence, Session
from engine.detection.policy import Policy

ANALYSIS_VERSION: Final[str] = "0.5.0"  # keep in sync with pyproject version

SEVERITY_WEIGHTS: Final[dict[FindingSeverity, float]] = {
    FindingSeverity.CRITICAL: 40.0,
    FindingSeverity.HIGH: 25.0,
    FindingSeverity.MEDIUM: 12.0,
    FindingSeverity.LOW: 5.0,
    FindingSeverity.INFO: 0.0,
}

CONFIDENCE_MULTIPLIERS: Final[dict[Confidence, float]] = {
    Confidence.HIGH: 1.0,
    Confidence.MEDIUM: 0.75,
    Confidence.LOW: 0.5,
}

PREVALENCE_BASE: Final[float] = 0.5
PREVALENCE_SPAN: Final[float] = 0.5
BREADTH_FACTOR: Final[float] = 0.25

HEALTHY_SCORE: Final[int] = 90
ACCEPTABLE_SCORE: Final[int] = 75
DEGRADED_SCORE: Final[int] = 60
HIGH_EXPOSURE_SCORE: Final[int] = 40

FACTOR_LABELS: Final[dict[str, str]] = {
    "tls_configuration": "TLS configuration",
    "certificates": "Certificates",
    "starttls": "STARTTLS usage",
    "authentication": "Authentication",
    "handshake": "Handshake reliability",
}

FACTOR_BY_RULE: Final[dict[str, str]] = {
    "TLS-VERSION-001": "tls_configuration",
    "CIPHER-SELECTED-001": "tls_configuration",
    "CIPHER-UNKNOWN-001": "tls_configuration",
    "KEYEX-001": "tls_configuration",
    "FS-001": "tls_configuration",
    "CERT-VALIDITY-001": "certificates",
    "CERT-KEY-001": "certificates",
    "CERT-SIG-001": "certificates",
    "CERT-IDENTITY-001": "certificates",
    "CERT-CHAIN-001": "certificates",
    "CERT-SELF-SIGNED-001": "certificates",
    "STARTTLS-001": "starttls",
    "PLAINTEXT-001": "starttls",
    "AUTH-PLAINTEXT-001": "authentication",
    "TLS-FAILURE-001": "handshake",
}


class PostureState(StrEnum):
    """Descriptive posture bands (SecureMailScope-defined, documented)."""

    HEALTHY = "healthy"
    ACCEPTABLE = "acceptable"
    DEGRADED = "degraded"
    HIGH_EXPOSURE = "high_exposure"
    CRITICAL_EXPOSURE = "critical_exposure"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"

    @classmethod
    def for_score(cls, score: int) -> "PostureState":
        if score >= HEALTHY_SCORE:
            return cls.HEALTHY
        if score >= ACCEPTABLE_SCORE:
            return cls.ACCEPTABLE
        if score >= DEGRADED_SCORE:
            return cls.DEGRADED
        if score >= HIGH_EXPOSURE_SCORE:
            return cls.HIGH_EXPOSURE
        return cls.CRITICAL_EXPOSURE


class FactorStatus(StrEnum):
    """Factor-level status derived from the worst contributing severity."""

    OK = "ok"
    INFORMATIONAL = "informational"
    ACCEPTABLE = "acceptable"
    DEGRADED = "degraded"
    HIGH_EXPOSURE = "high_exposure"
    CRITICAL_EXPOSURE = "critical_exposure"

    @classmethod
    def for_severities(cls, severities: list[FindingSeverity]) -> "FactorStatus":
        if not severities:
            return cls.OK
        worst = max(severities, key=lambda s: SEVERITY_WEIGHTS[s])
        if worst is FindingSeverity.INFO:
            return cls.INFORMATIONAL
        if worst is FindingSeverity.LOW:
            return cls.ACCEPTABLE
        if worst is FindingSeverity.MEDIUM:
            return cls.DEGRADED
        if worst is FindingSeverity.HIGH:
            return cls.HIGH_EXPOSURE
        return cls.CRITICAL_EXPOSURE


def host_id_for(ip: str) -> str:
    """Deterministic, filesystem-safe host identifier from an endpoint IP."""
    return f"host_{hashlib.sha256(ip.encode()).hexdigest()[:12]}"


@dataclass(frozen=True, slots=True)
class _FindingEvaluation:
    """A finding with its score contribution computed for one factor."""

    finding: SecurityFinding
    deduction: float
    affected_sessions: int


@dataclass(frozen=True, slots=True)
class PostureFactor:
    """One correlated posture domain (e.g. TLS configuration)."""

    factor: str
    label: str
    status: str  # FactorStatus value
    score_contribution: float  # points deducted from the base score
    affected_sessions: int
    affected_hosts: int
    contributing_finding_ids: list[str]
    explanation: str


@dataclass(frozen=True, slots=True)
class HostPosture:
    """Aggregated posture context for one observed server endpoint."""

    host_id: str
    ip: str
    sessions: int
    protocols: list[str]
    findings_count: int
    highest_severity: str | None  # None when the host has no findings
    affected: bool
    tls_versions: list[str]


@dataclass(frozen=True, slots=True)
class ProtocolPosture:
    """Aggregated posture for one email protocol."""

    protocol: str
    sessions: int
    findings: int
    affected_sessions: int
    status: str


@dataclass(frozen=True, slots=True)
class PriorityItem:
    """One prioritized finding group with a deterministic explanation."""

    priority_score: float
    rule_id: str
    title: str
    severity: str
    confidence: str
    affected_sessions: int
    total_sessions: int
    prevalence: float
    affected_hosts: int
    evidence_count: int
    finding_ids: list[str]
    explanation: str


@dataclass(frozen=True, slots=True)
class SecurityPosture:
    """The full explainable posture snapshot for one capture."""

    capture_id: str
    analysis_version: str
    policy_id: str
    policy_version: str
    posture_state: str  # PostureState value
    overall_score: int | None  # None when evidence is insufficient
    confidence: str  # Confidence value
    total_sessions: int
    affected_sessions: int
    affected_hosts: int
    total_hosts: int
    finding_counts_by_severity: dict[str, int]
    category_breakdown: dict[str, int]
    factors: list[PostureFactor]
    hosts: list[HostPosture]
    protocols: list[ProtocolPosture]
    priorities: list[PriorityItem]
    explanation: list[str]
    generated_at: datetime  # evidence-derived (max finding time), not wall clock


# ---------------------------------------------------------------------------
# Computation
# ---------------------------------------------------------------------------


def _factor_of(finding: SecurityFinding) -> str:
    return FACTOR_BY_RULE.get(finding.rule_id, "other")


def _confidence_multiplier(confidence: Confidence) -> float:
    return CONFIDENCE_MULTIPLIERS.get(confidence, 0.25)


def _prevalence_multiplier(affected_sessions: int, total_sessions: int) -> float:
    if total_sessions <= 0:  # pragma: no cover - callers guard this
        return PREVALENCE_BASE
    ratio = min(1.0, affected_sessions / total_sessions)
    return PREVALENCE_BASE + PREVALENCE_SPAN * ratio


def _server_sessions(sessions: list[Session]) -> dict[str, list[Session]]:
    """Group sessions by their server endpoint (infrastructure-side only)."""
    grouped: dict[str, list[Session]] = {}
    for session in sessions:
        grouped.setdefault(str(session.server_ip), []).append(session)
    return dict(sorted(grouped.items()))


def _sessions_with_condition(
    findings: list[SecurityFinding], target: SecurityFinding
) -> set[str | None]:
    """Sessions sharing the same observed condition (rule + observed value)."""
    return {
        finding.session_id
        for finding in findings
        if finding.rule_id == target.rule_id and finding.observed_value == target.observed_value
    }


def _evidence_time(findings: list[SecurityFinding], sessions: list[Session]) -> datetime:
    """Deterministic snapshot time: the latest evidence instant, not the wall clock."""
    times = [finding.detected_at for finding in findings]
    times += [session.ended_at for session in sessions if session.ended_at]
    return max(times) if times else datetime.now(UTC)


def _overall_confidence(evaluations: list[_FindingEvaluation]) -> Confidence:
    """Confidence of the posture: the weakest of the top-3 contributing findings."""
    contributing = [e for e in evaluations if e.deduction > 0]
    if not contributing:
        return Confidence.HIGH
    ordered = sorted(contributing, key=lambda e: e.deduction, reverse=True)
    rank = {Confidence.HIGH: 3, Confidence.MEDIUM: 2, Confidence.LOW: 1}
    return min((e.finding.confidence for e in ordered[:3]), key=lambda c: rank[c])


def _insufficient_evidence_posture(capture_id: str, policy: Policy) -> SecurityPosture:
    return SecurityPosture(
        capture_id=capture_id,
        analysis_version=ANALYSIS_VERSION,
        policy_id=policy.id,
        policy_version=policy.version,
        posture_state=PostureState.INSUFFICIENT_EVIDENCE.value,
        overall_score=None,
        confidence=Confidence.LOW.value,
        total_sessions=0,
        affected_sessions=0,
        affected_hosts=0,
        total_hosts=0,
        finding_counts_by_severity={},
        category_breakdown={},
        factors=[],
        hosts=[],
        protocols=[],
        priorities=[],
        explanation=["insufficient_evidence: no sessions were reconstructed from this capture."],
        generated_at=datetime.now(UTC),
    )


def _build_hosts(
    sessions: list[Session], findings_by_session: dict[str, list[SecurityFinding]]
) -> list[HostPosture]:
    hosts: list[HostPosture] = []
    for ip, ip_sessions in _server_sessions(sessions).items():
        session_ids = {session.id for session in ip_sessions}
        host_findings = [
            finding for sid in session_ids for finding in findings_by_session.get(sid, [])
        ]
        severities = [finding.severity for finding in host_findings]
        tls_versions = sorted(
            {
                session.handshake.tls_version.value
                for session in ip_sessions
                if session.handshake is not None
            }
        )
        hosts.append(
            HostPosture(
                host_id=host_id_for(ip),
                ip=ip,
                sessions=len(ip_sessions),
                protocols=sorted(
                    {
                        session.protocol.value
                        for session in ip_sessions
                        if session.protocol is not None
                    }
                ),
                findings_count=len(host_findings),
                highest_severity=(
                    max(severities, key=lambda s: SEVERITY_WEIGHTS[s]).value if severities else None
                ),
                affected=bool(host_findings),
                tls_versions=tls_versions,
            )
        )
    hosts.sort(key=lambda host: host.ip)
    return hosts


def _build_protocols(
    sessions: list[Session],
    findings: list[SecurityFinding],
    affected_session_ids: set[str],
) -> list[ProtocolPosture]:
    protocols: list[ProtocolPosture] = []
    protocol_values = sorted(
        {session.protocol for session in sessions if session.protocol is not None},
        key=lambda p: p.value,
    )
    for protocol in protocol_values:
        protocol_sessions = [session for session in sessions if session.protocol is protocol]
        session_ids = {session.id for session in protocol_sessions}
        protocol_findings = [f for f in findings if f.session_id in session_ids]
        protocols.append(
            ProtocolPosture(
                protocol=protocol.value,
                sessions=len(protocol_sessions),
                findings=len(protocol_findings),
                affected_sessions=len(session_ids & affected_session_ids),
                status=FactorStatus.for_severities(
                    [finding.severity for finding in protocol_findings]
                ).value,
            )
        )
    return protocols


def _build_priorities(
    evaluations: list[_FindingEvaluation],
    total_sessions: int,
    host_of_session: dict[str, str],
) -> list[PriorityItem]:
    """Deterministic priority ranking of finding groups (by rule)."""
    groups: dict[str, list[_FindingEvaluation]] = {}
    for evaluation in evaluations:
        groups.setdefault(evaluation.finding.rule_id, []).append(evaluation)

    items: list[PriorityItem] = []
    for rule_id, group in groups.items():
        ordered = sorted(group, key=lambda e: e.deduction, reverse=True)
        dominant = ordered[0]
        affected_sessions = len({e.finding.session_id for e in group if e.finding.session_id})
        affected_hosts = len(
            {
                host_of_session[e.finding.session_id]
                for e in group
                if e.finding.session_id in host_of_session
            }
        )
        prevalence = (
            round(min(1.0, affected_sessions / total_sessions), 4) if total_sessions else 0.0
        )
        priority_score = round(
            SEVERITY_WEIGHTS.get(dominant.finding.severity, 0.0)
            * _confidence_multiplier(dominant.finding.confidence)
            * (PREVALENCE_BASE + PREVALENCE_SPAN * prevalence),
            2,
        )
        items.append(
            PriorityItem(
                priority_score=priority_score,
                rule_id=rule_id,
                title=dominant.finding.title,
                severity=dominant.finding.severity.value,
                confidence=dominant.finding.confidence.value,
                affected_sessions=affected_sessions,
                total_sessions=total_sessions,
                prevalence=prevalence,
                affected_hosts=affected_hosts,
                evidence_count=sum(len(e.finding.evidence_refs) for e in group),
                finding_ids=[e.finding.id for e in ordered],
                explanation=(
                    f"{dominant.finding.severity.value} severity affecting "
                    f"{affected_sessions}/{total_sessions} session(s) "
                    f"({round(prevalence * 100)}% prevalence) across "
                    f"{affected_hosts} host(s) with "
                    f"{dominant.finding.confidence.value} evidence confidence"
                ),
            )
        )
    items.sort(key=lambda item: (-item.priority_score, item.rule_id))
    return items


def _build_explanation(
    factors: list[PostureFactor], priorities: list[PriorityItem], total_sessions: int
) -> list[str]:
    lines: list[str] = []
    contributing = sorted(factors, key=lambda f: f.score_contribution, reverse=True)
    for factor in contributing:
        if factor.score_contribution <= 0:
            continue
        lines.append(
            f"{factor.label}: {factor.status} — {factor.affected_sessions}/"
            f"{total_sessions} session(s) affected "
            f"(-{factor.score_contribution:g} points)"
        )
    for index, item in enumerate(priorities[:3], start=1):
        lines.append(f"Priority {index}: {item.title} ({item.explanation})")
    if not lines:
        lines.append("No policy violations observed in the analyzed sessions.")
    return lines


def build_posture(
    capture_id: str,
    sessions: list[Session],
    findings: list[SecurityFinding],
    policy: Policy,
) -> SecurityPosture:
    """Compute the explainable posture snapshot from persisted evidence."""
    total_sessions = len(sessions)
    if total_sessions == 0:
        return _insufficient_evidence_posture(capture_id, policy)

    host_of_session = {session.id: str(session.server_ip) for session in sessions}

    # --- per-finding deductions ------------------------------------------
    evaluations: list[_FindingEvaluation] = []
    for finding in findings:
        affected = _sessions_with_condition(findings, finding)
        deduction = (
            SEVERITY_WEIGHTS.get(finding.severity, 0.0)
            * _confidence_multiplier(finding.confidence)
            * _prevalence_multiplier(len(affected), total_sessions)
        )
        evaluations.append(
            _FindingEvaluation(
                finding=finding,
                deduction=round(deduction, 2),
                affected_sessions=len(affected),
            )
        )

    # --- factor deductions: worst condition + breadth --------------------
    factor_domains: dict[str, list[_FindingEvaluation]] = {}
    for evaluation in evaluations:
        factor_domains.setdefault(_factor_of(evaluation.finding), []).append(evaluation)

    factors: list[PostureFactor] = []
    for factor in sorted(FACTOR_LABELS):
        domain = factor_domains.get(factor, [])
        if not domain:
            factors.append(
                PostureFactor(
                    factor=factor,
                    label=FACTOR_LABELS[factor],
                    status=FactorStatus.OK.value,
                    score_contribution=0.0,
                    affected_sessions=0,
                    affected_hosts=0,
                    contributing_finding_ids=[],
                    explanation="No findings in this domain.",
                )
            )
            continue

        ordered = sorted(domain, key=lambda e: e.deduction, reverse=True)
        deduction = round(
            ordered[0].deduction + BREADTH_FACTOR * sum(e.deduction for e in ordered[1:]), 2
        )
        affected_sessions = len({e.finding.session_id for e in domain if e.finding.session_id})
        affected_hosts = len(
            {
                host_of_session[e.finding.session_id]
                for e in domain
                if e.finding.session_id in host_of_session
            }
        )
        factors.append(
            PostureFactor(
                factor=factor,
                label=FACTOR_LABELS[factor],
                status=FactorStatus.for_severities([e.finding.severity for e in domain]).value,
                score_contribution=deduction,
                affected_sessions=affected_sessions,
                affected_hosts=affected_hosts,
                contributing_finding_ids=[e.finding.id for e in ordered],
                explanation=(
                    f"Dominated by '{ordered[0].finding.title}' "
                    f"({len(ordered)} condition(s) correlated in this domain)."
                ),
            )
        )

    total_deduction = min(100.0, sum(f.score_contribution for f in factors))
    overall_score = round(max(0.0, 100.0 - total_deduction))

    # --- aggregates -------------------------------------------------------
    findings_by_session: dict[str, list[SecurityFinding]] = {}
    for finding in findings:
        if finding.session_id:
            findings_by_session.setdefault(finding.session_id, []).append(finding)
    affected_session_ids = set(findings_by_session)
    priorities = _build_priorities(evaluations, total_sessions, host_of_session)

    return SecurityPosture(
        capture_id=capture_id,
        analysis_version=ANALYSIS_VERSION,
        policy_id=policy.id,
        policy_version=policy.version,
        posture_state=PostureState.for_score(overall_score).value,
        overall_score=overall_score,
        confidence=_overall_confidence(evaluations).value,
        total_sessions=total_sessions,
        affected_sessions=len(affected_session_ids),
        affected_hosts=len(
            {host_of_session[sid] for sid in affected_session_ids if sid in host_of_session}
        ),
        total_hosts=len(_server_sessions(sessions)),
        finding_counts_by_severity=_count_by(findings, lambda f: f.severity.value),
        category_breakdown=_count_by(findings, lambda f: f.category.value),
        factors=factors,
        hosts=_build_hosts(sessions, findings_by_session),
        protocols=_build_protocols(sessions, findings, affected_session_ids),
        priorities=priorities,
        explanation=_build_explanation(factors, priorities, total_sessions),
        generated_at=_evidence_time(findings, sessions),
    )


def _count_by(
    findings: list[SecurityFinding],
    key: Callable[[SecurityFinding], str],
) -> dict[str, int]:
    counts: dict[str, int] = {}
    for finding in findings:
        name = key(finding)
        counts[name] = counts.get(name, 0) + 1
    return counts
