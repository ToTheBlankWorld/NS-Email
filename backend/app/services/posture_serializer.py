"""Posture persistence: one atomic snapshot per capture.

The snapshot stores the full posture document as JSON so hosts,
protocols, factors, and priorities can be served without recomputation.
Re-analysis replaces the snapshot atomically — stale posture records
never survive.
"""

from typing import Any

from engine.detection.posture import SecurityPosture


def posture_to_payload(posture: SecurityPosture) -> dict[str, Any]:
    """Serialize the posture dataclasses into a JSON-safe document."""
    return {
        "capture_id": posture.capture_id,
        "analysis_version": posture.analysis_version,
        "policy_id": posture.policy_id,
        "policy_version": posture.policy_version,
        "posture_state": posture.posture_state,
        "overall_score": posture.overall_score,
        "confidence": posture.confidence,
        "total_sessions": posture.total_sessions,
        "affected_sessions": posture.affected_sessions,
        "affected_hosts": posture.affected_hosts,
        "total_hosts": posture.total_hosts,
        "finding_counts_by_severity": posture.finding_counts_by_severity,
        "category_breakdown": posture.category_breakdown,
        "factors": [
            {
                "factor": f.factor,
                "label": f.label,
                "status": f.status,
                "score_contribution": f.score_contribution,
                "affected_sessions": f.affected_sessions,
                "affected_hosts": f.affected_hosts,
                "contributing_finding_ids": f.contributing_finding_ids,
                "explanation": f.explanation,
            }
            for f in posture.factors
        ],
        "hosts": [
            {
                "host_id": h.host_id,
                "ip": h.ip,
                "sessions": h.sessions,
                "protocols": h.protocols,
                "findings_count": h.findings_count,
                "highest_severity": h.highest_severity,
                "affected": h.affected,
                "tls_versions": h.tls_versions,
            }
            for h in posture.hosts
        ],
        "protocols": [
            {
                "protocol": p.protocol,
                "sessions": p.sessions,
                "findings": p.findings,
                "affected_sessions": p.affected_sessions,
                "status": p.status,
            }
            for p in posture.protocols
        ],
        "priorities": [
            {
                "priority_score": p.priority_score,
                "rule_id": p.rule_id,
                "title": p.title,
                "severity": p.severity,
                "confidence": p.confidence,
                "affected_sessions": p.affected_sessions,
                "total_sessions": p.total_sessions,
                "prevalence": p.prevalence,
                "affected_hosts": p.affected_hosts,
                "evidence_count": p.evidence_count,
                "finding_ids": p.finding_ids,
                "explanation": p.explanation,
            }
            for p in posture.priorities
        ],
        "explanation": posture.explanation,
        "generated_at": posture.generated_at.isoformat(),
    }
