"""Deterministic evaluation: rule registry over persisted evidence."""

from collections.abc import Iterable

from engine.core.findings import SecurityFinding
from engine.core.session import Session
from engine.detection.base import RuleContext
from engine.detection.policy import Policy
from engine.detection.registry import default_registry


def evaluate_session(session: Session, policy: Policy) -> list[SecurityFinding]:
    """Run every registered rule against one session, deduplicating by id."""
    context = RuleContext(session=session, policy=policy)
    findings_by_id: dict[str, SecurityFinding] = {}
    for rule in default_registry().rules():
        for finding in rule.evaluate(context):
            findings_by_id.setdefault(finding.id, finding)
    return list(findings_by_id.values())


def evaluate_sessions(sessions: Iterable[Session], policy: Policy) -> list[SecurityFinding]:
    """Run rules independently per session — findings never merge hosts."""
    findings: list[SecurityFinding] = []
    seen: set[str] = set()
    for session in sessions:
        for finding in evaluate_session(session, policy):
            if finding.id in seen:  # ids are session-scoped; belt and braces
                continue
            seen.add(finding.id)
            findings.append(finding)
    return findings
