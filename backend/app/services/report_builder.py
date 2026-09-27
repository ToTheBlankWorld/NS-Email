"""Deterministic forensic report model (Stage 9).

The report is assembled exclusively from already-persisted, structured
evidence: capture metadata, analysis status, sessions, findings, the
posture snapshot, anomaly results, the evidence graph, and validated AI
history. Nothing is invented, re-scored, or re-classified here — the
report is a faithful aggregation of Stages 1-8 output.

Determinism: identical evidence state produces byte-identical JSON. The
report id is derived from the capture id, and ``generated_at`` reflects
the underlying analysis completion time rather than wall-clock time.
"""

import hashlib
import json
from collections import Counter
from dataclasses import dataclass, field
from typing import Any

REPORT_SCHEMA_VERSION = "1.0"
REPORT_APPLICATION_NAME = "NS-Email SecureMailScope"

_MAX_REPORT_FINDINGS = 500
_MAX_REPORT_ANOMALIES = 500
_MAX_AI_ENTRIES = 50

_SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")
_BAND_ORDER = ("anomalous", "highly_anomalous", "unusual", "normal", "insufficient_evidence")


@dataclass(frozen=True, slots=True)
class ReportInputs:
    """Everything the report builder needs, pre-serialized and JSON-safe."""

    capture: dict[str, Any]
    analysis_status: str
    analyzed_at: str | None
    sessions: list[dict[str, Any]] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    posture: dict[str, Any] | None = None
    anomalies: dict[str, Any] | None = None
    graph_nodes: list[dict[str, Any]] = field(default_factory=list)
    graph_edges: list[dict[str, Any]] = field(default_factory=list)
    ai_history: list[dict[str, Any]] = field(default_factory=list)
    ai_configured: bool = False
    ai_provider: str = ""
    ai_model: str = ""
    application_version: str = ""


def build_report(inputs: ReportInputs) -> dict[str, Any]:
    """Build the deterministic report document from serialized evidence."""
    capture = inputs.capture
    report_id = (
        "report_" + hashlib.sha256(str(capture.get("id", "")).encode("utf-8")).hexdigest()[:12]
    )

    return {
        "report": {
            "schema_version": REPORT_SCHEMA_VERSION,
            "report_id": report_id,
            "application": {
                "name": REPORT_APPLICATION_NAME,
                "version": inputs.application_version,
            },
            "generated_at": _report_generated_at(inputs),
            "analysis_status": inputs.analysis_status,
        },
        "capture": _capture_section(capture),
        "executive_summary": _executive_summary(inputs),
        "posture": _posture_section(inputs.posture),
        "findings": _findings_section(inputs.findings),
        "anomalies": _anomalies_section(inputs.anomalies),
        "tls_summary": _tls_summary(inputs.sessions),
        "graph_summary": _graph_summary(inputs.graph_nodes, inputs.graph_edges),
        "ai_analyst": _ai_section(inputs),
        "limitations": _limitations(inputs),
        "methodology": _methodology(),
    }


def _report_generated_at(inputs: ReportInputs) -> str | None:
    """Deterministic report timestamp: the underlying analysis completion time."""
    candidates = [
        inputs.analyzed_at,
        str((inputs.posture or {}).get("generated_at", "")) or None,
        str((inputs.anomalies or {}).get("generated_at", "")) or None,
    ]
    present = [c for c in candidates if c]
    return max(present) if present else None


def _capture_section(capture: dict[str, Any]) -> dict[str, Any]:
    return {
        "capture_id": capture.get("id"),
        "filename": capture.get("filename"),
        "format": capture.get("format"),
        "size_bytes": capture.get("size_bytes"),
        "sha256": capture.get("sha256"),
        "status": capture.get("status"),
        "packet_count": capture.get("packet_count"),
        "link_type": capture.get("link_type"),
        "started_at": capture.get("started_at"),
        "ended_at": capture.get("ended_at"),
        "duration_seconds": capture.get("duration_seconds"),
        "ingested_at": capture.get("ingested_at"),
        "inspection": capture.get("inspection"),
    }


def _executive_summary(inputs: ReportInputs) -> dict[str, Any]:
    posture = inputs.posture or {}
    anomalies = inputs.anomalies or {}
    severity_counts = Counter(str(f.get("severity")) for f in inputs.findings)
    band_counts = Counter(
        str(a.get("band") or a.get("status"))
        for a in (anomalies.get("anomalies", []) if isinstance(anomalies, dict) else [])
    )
    protocol_counts = Counter(str(s.get("protocol") or "unknown") for s in inputs.sessions)
    return {
        "posture_state": posture.get("posture_state"),
        "posture_score": posture.get("overall_score"),
        "total_sessions": len(inputs.sessions),
        "affected_sessions": posture.get("affected_sessions"),
        "affected_hosts": posture.get("affected_hosts"),
        "total_hosts": posture.get("total_hosts"),
        "findings_total": len(inputs.findings),
        "findings_by_severity": {s: severity_counts.get(s, 0) for s in _SEVERITY_ORDER},
        "anomalies_total": len(anomalies.get("anomalies", []))
        if isinstance(anomalies, dict)
        else 0,
        "anomalies_by_band": {b: band_counts.get(b, 0) for b in _BAND_ORDER},
        "protocol_distribution": dict(sorted(protocol_counts.items())),
        "tls_coverage": _tls_coverage(inputs.sessions),
    }


def _tls_coverage(sessions: list[dict[str, Any]]) -> dict[str, Any]:
    """Deterministic TLS coverage derived from session evidence."""
    total = len(sessions)
    with_handshake = sum(1 for s in sessions if s.get("handshake"))
    with_starttls = sum(1 for s in sessions if s.get("starttls"))
    complete = sum(
        1 for s in sessions if s.get("handshake") and s["handshake"].get("handshake_complete")
    )
    return {
        "sessions_total": total,
        "sessions_with_tls_handshake": with_handshake,
        "sessions_with_starttls": with_starttls,
        "handshakes_complete": complete,
    }


def _posture_section(posture: dict[str, Any] | None) -> dict[str, Any]:
    if not posture:
        return {"available": False}
    return {
        "available": True,
        "posture_state": posture.get("posture_state"),
        "overall_score": posture.get("overall_score"),
        "confidence": posture.get("confidence"),
        "policy_id": posture.get("policy_id"),
        "policy_version": posture.get("policy_version"),
        "analysis_version": posture.get("analysis_version"),
        "total_sessions": posture.get("total_sessions"),
        "affected_sessions": posture.get("affected_sessions"),
        "affected_hosts": posture.get("affected_hosts"),
        "total_hosts": posture.get("total_hosts"),
        "finding_counts_by_severity": posture.get("finding_counts_by_severity"),
        "category_breakdown": posture.get("category_breakdown"),
        "factors": posture.get("factors", []),
        "hosts": posture.get("hosts", []),
        "protocols": posture.get("protocols", []),
        "priorities": posture.get("priorities", []),
        "explanation": posture.get("explanation"),
        "generated_at": posture.get("generated_at"),
    }


def _findings_section(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """All findings with full evidence, remediation, and references."""
    ordered = sorted(
        findings,
        key=lambda f: (
            _SEVERITY_ORDER.index(str(f.get("severity")))
            if f.get("severity") in _SEVERITY_ORDER
            else 99,
            str(f.get("session_id") or ""),
            str(f.get("rule_id") or ""),
        ),
    )
    return ordered[:_MAX_REPORT_FINDINGS]


def _anomalies_section(anomalies: dict[str, Any] | None) -> dict[str, Any]:
    if not anomalies:
        return {"available": False, "items": []}
    items = list(anomalies.get("anomalies", []))[:_MAX_REPORT_ANOMALIES]
    first = items[0] if items else {}
    return {
        "available": True,
        "status": anomalies.get("status") or first.get("status"),
        "model_id": anomalies.get("model_id") or first.get("model_id"),
        "model_version": anomalies.get("model_version") or first.get("model_version"),
        "feature_schema_version": (
            anomalies.get("feature_schema_version") or first.get("feature_schema_version")
        ),
        "training_session_count": (
            anomalies.get("training_session_count") or first.get("training_session_count")
        ),
        "summary": anomalies.get("summary"),
        "items": items,
    }


def _tls_summary(sessions: list[dict[str, Any]]) -> dict[str, Any]:
    versions: Counter[str] = Counter()
    cipher_families: Counter[str] = Counter()
    key_exchanges: Counter[str] = Counter()
    signature_algorithms: Counter[str] = Counter()
    public_key_algorithms: Counter[str] = Counter()
    certificates: list[dict[str, Any]] = []
    seen_certs: set[str] = set()
    handshake_complete = 0
    handshake_incomplete = 0
    incomplete_reasons: Counter[str] = Counter()

    for session in sessions:
        handshake = session.get("handshake")
        if not handshake:
            continue
        versions[str(handshake.get("tls_version"))] += 1
        if handshake.get("handshake_complete"):
            handshake_complete += 1
        else:
            handshake_incomplete += 1
            reason = handshake.get("completeness_reason") or "unspecified"
            incomplete_reasons[str(reason)] += 1
        cipher = handshake.get("cipher_suite")
        if cipher:
            cipher_families[str(cipher).split("_")[0]] += 1
        key_exchanges[str(handshake.get("key_exchange"))] += 1
        for cert in session.get("certificates", []) or []:
            fingerprint = str(cert.get("fingerprint_sha256") or cert.get("id") or "")
            if fingerprint in seen_certs:
                continue
            seen_certs.add(fingerprint)
            if cert.get("signature_algorithm"):
                signature_algorithms[str(cert["signature_algorithm"])] += 1
            if cert.get("public_key_algorithm"):
                public_key_algorithms[str(cert["public_key_algorithm"])] += 1
            certificates.append(
                {
                    "cert_id": cert.get("id"),
                    "subject": cert.get("subject"),
                    "issuer": cert.get("issuer"),
                    "not_before": cert.get("not_before"),
                    "not_after": cert.get("not_after"),
                    "signature_algorithm": cert.get("signature_algorithm"),
                    "public_key_algorithm": cert.get("public_key_algorithm"),
                    "public_key_size_bits": cert.get("public_key_size_bits"),
                    "fingerprint_sha256": cert.get("fingerprint_sha256"),
                    "position_in_chain": cert.get("position_in_chain"),
                }
            )

    return {
        "versions_observed": dict(sorted(versions.items())),
        "cipher_families": dict(sorted(cipher_families.items())),
        "key_exchanges": dict(sorted(key_exchanges.items())),
        "handshakes_complete": handshake_complete,
        "handshakes_incomplete": handshake_incomplete,
        "incompleteness_reasons": dict(sorted(incomplete_reasons.items())),
        "certificates_observed": len(certificates),
        "signature_algorithms": dict(sorted(signature_algorithms.items())),
        "public_key_algorithms": dict(sorted(public_key_algorithms.items())),
        "certificates": certificates,
    }


def _graph_summary(nodes: list[dict[str, Any]], edges: list[dict[str, Any]]) -> dict[str, Any]:
    node_types: Counter[str] = Counter(str(n.get("node_type")) for n in nodes)
    edge_types: Counter[str] = Counter(str(e.get("edge_type")) for e in edges)
    cert_sessions: Counter[str] = Counter()
    for edge in edges:
        if edge.get("edge_type") == "tls_contains_certificate":
            cert_sessions[str(edge.get("target_node_id"))] += 1
    correlated = sorted(nid for nid, count in cert_sessions.items() if count >= 2)
    return {
        "node_count": len(nodes),
        "edge_count": len(edges),
        "node_types": dict(sorted(node_types.items())),
        "edge_types": dict(sorted(edge_types.items())),
        "correlated_certificate_nodes": correlated,
        "correlated_certificate_count": len(correlated),
    }


def _ai_section(inputs: ReportInputs) -> dict[str, Any]:
    section: dict[str, Any] = {
        "configured": inputs.ai_configured,
        "provider": inputs.ai_provider if inputs.ai_configured else "",
        "model": inputs.ai_model if inputs.ai_configured else "",
    }
    if not inputs.ai_configured:
        section["note"] = "AI analyst not configured"
        section["observations"] = []
        return section
    if not inputs.ai_history:
        section["note"] = "No validated AI observations recorded for this capture"
        section["observations"] = []
        return section
    entries = []
    for item in inputs.ai_history[:_MAX_AI_ENTRIES]:
        entries.append(
            {
                "response_id": item.get("response_id"),
                "session_id": item.get("session_id"),
                "query": item.get("query"),
                "answer": item.get("answer"),
                "provider": item.get("provider"),
                "model": item.get("model"),
                "prompt_version": item.get("prompt_version"),
                "context_version": item.get("context_version"),
                "validation_status": item.get("validation_status"),
                "generated_at": item.get("generated_at"),
            }
        )
    section["note"] = (
        "Interpretive assistance generated from structured evidence; "
        "validated against citations and never a source of security truth."
    )
    section["observations"] = entries
    return section


def _limitations(inputs: ReportInputs) -> dict[str, Any]:
    incomplete_sessions = sum(1 for s in inputs.sessions if not s.get("complete"))
    anomalies = (inputs.anomalies or {}).get("anomalies", [])
    insufficient = sum(1 for a in anomalies if a.get("status") == "insufficient_evidence")
    limitations = [
        "TLS handshake reconstruction covers plaintext handshake phases only; "
        "encrypted payload content is never inspected.",
        "Findings reflect the configured policy baseline and the evidence "
        "present in this capture; absence of findings is not proof of security.",
        "Behavioral anomalies are statistical deviations from the capture-local "
        "baseline; they are not indicators of compromise or maliciousness.",
        "Email message bodies, credentials, and raw payloads are excluded from "
        "all analysis output and reports by design.",
    ]
    if incomplete_sessions:
        limitations.append(
            f"{incomplete_sessions} session(s) are incomplete (missing TCP "
            "segments); evidence derived from them may be partial."
        )
    if insufficient:
        limitations.append(
            f"{insufficient} session(s) had insufficient data for behavioral "
            "anomaly evaluation and were not scored."
        )
    if not inputs.ai_configured:
        limitations.append("AI analyst is not configured; no AI observations are included.")
    elif not inputs.ai_history:
        limitations.append("No validated AI observations were recorded for this capture.")
    return {"items": limitations}


def _methodology() -> list[str]:
    return [
        "Stage 1: PCAP/PCAPNG ingestion with magic-byte validation, SHA-256 "
        "hashing, and deterministic capture ids.",
        "Stage 2: TCP flow reconstruction, stream reassembly, and "
        "SMTP/IMAP/POP3 session forensics with credential redaction.",
        "Stage 3: TLS record and handshake parsing with X.509 chain extraction.",
        "Stage 4: deterministic policy engine producing evidence-backed security findings.",
        "Stage 5: transparent security posture scoring with explainable factors.",
        "Stage 6: capture-local behavioral anomaly detection over typed session features.",
        "Stage 7: forensic evidence graph with certificate and TLS configuration pivots.",
        "Stage 8: evidence-grounded AI analyst with validated citations; "
        "AI output is interpretive assistance, never a source of truth.",
        "Stage 9: deterministic report assembly from the persisted evidence of the stages above.",
    ]


def report_to_json(report: dict[str, Any]) -> str:
    """Serialize the report deterministically (stable key order)."""
    return json.dumps(report, indent=2, sort_keys=True, default=str)
