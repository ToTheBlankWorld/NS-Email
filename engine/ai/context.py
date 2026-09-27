"""AI context builder: InvestigationContext → sanitized, bounded AIContext.

Data minimization is the core principle: only fields needed to answer the
analyst's question are included. Credentials, raw payloads, internal
filesystem paths, and secret material are stripped before any LLM call.
"""

import json
from dataclasses import dataclass
from typing import Any, Final

from engine.core.session import Session
from engine.graph.builder import InvestigationContext

AI_CONTEXT_VERSION: Final = "1.0"
MAX_RELATED_SESSIONS: Final[int] = 5
MAX_FINDINGS: Final[int] = 10
MAX_TIMELINE_EVENTS: Final[int] = 20
MAX_CONTEXT_JSON_CHARS: Final[int] = 12_000

_SENSITIVE_KEYS: Final[frozenset[str]] = frozenset(
    {"credential_data", "password", "secret", "private_key", "api_key"}
)


def _strip_sensitive(obj: Any) -> Any:
    """Recursively remove sensitive keys from dicts and lists."""
    if isinstance(obj, dict):
        return {k: _strip_sensitive(v) for k, v in obj.items() if k.lower() not in _SENSITIVE_KEYS}
    if isinstance(obj, list):
        return [_strip_sensitive(item) for item in obj]
    return obj


@dataclass(frozen=True, slots=True)
class AIContext:
    """Sanitized, bounded context for the LLM prompt."""

    capture_id: str
    session_id: str
    protocol: str | None
    context_json: str  # the serialized, minimized context
    related_session_count: int
    context_version: str = AI_CONTEXT_VERSION


def build_ai_context(
    session: Session,
    investigation: InvestigationContext,
    findings: list[Any],
    posture_summary: dict[str, Any] | None,
) -> AIContext:
    """Build a minimized AI context from structured investigation evidence."""
    session_brief = {
        "session_id": session.id,
        "protocol": session.protocol.value if session.protocol else None,
        "client_ip": str(session.client_ip),
        "client_port": session.client_port,
        "server_ip": str(session.server_ip),
        "server_port": session.server_port,
        "started_at": session.started_at.isoformat() if session.started_at else None,
        "ended_at": session.ended_at.isoformat() if session.ended_at else None,
        "duration_seconds": session.duration_seconds,
        "complete": session.complete,
        "packet_count": session.packet_count,
        "implicit_tls": session.implicit_tls,
    }

    tls_brief: dict[str, Any] = {}
    if session.handshake:
        hs = session.handshake
        tls_brief = {
            "tls_version": hs.tls_version.value,
            "cipher_suite": hs.cipher_suite,
            "key_exchange": hs.key_exchange.value,
            "sni_server_name": hs.sni_server_name,
            "handshake_complete": hs.handshake_complete,
            "cipher_suites_offered": hs.cipher_suites_offered[:5],
        }

    cert_briefs = [
        {
            "subject": cert.subject,
            "issuer": cert.issuer,
            "not_before": cert.not_before.isoformat(),
            "not_after": cert.not_after.isoformat(),
            "public_key_algorithm": cert.public_key_algorithm,
            "public_key_size_bits": cert.public_key_size_bits,
            "signature_algorithm": cert.signature_algorithm,
            "fingerprint_sha256": cert.fingerprint_sha256,
            "position_in_chain": cert.position_in_chain,
        }
        for cert in session.certificates
    ]

    finding_briefs = [
        {
            "rule_id": f.rule_id,
            "title": f.title,
            "severity": f.severity.value,
            "confidence": f.confidence.value,
            "category": f.category.value,
            "observed_value": f.observed_value,
            "description": f.description[:200],
        }
        for f in findings[:MAX_FINDINGS]
    ]

    anomaly_brief: dict[str, Any] | None = None
    if investigation.anomaly_id:
        anomaly_brief = {
            "anomaly_id": investigation.anomaly_id,
            "score": investigation.anomaly_score,
        }

    posture_brief = posture_summary or {}

    related = [
        {"session_id": sid} for sid in investigation.related_session_ids[:MAX_RELATED_SESSIONS]
    ]

    timeline = investigation.timeline_events[:MAX_TIMELINE_EVENTS]

    context = _strip_sensitive(
        {
            "session": session_brief,
            "tls": tls_brief,
            "certificates": cert_briefs,
            "findings": finding_briefs,
            "anomaly": anomaly_brief,
            "posture": posture_brief,
            "related_sessions": related,
            "timeline": timeline,
            "evidence_refs": investigation.evidence_refs[:20],
        }
    )

    context_json = json.dumps(context, indent=1, default=str)
    if len(context_json) > MAX_CONTEXT_JSON_CHARS:
        context_json = context_json[:MAX_CONTEXT_JSON_CHARS]

    return AIContext(
        capture_id=session.capture_id,
        session_id=session.id,
        protocol=session.protocol.value if session.protocol else None,
        context_json=context_json,
        related_session_count=len(investigation.related_session_ids),
    )
