"""Deterministic case report model (Stage 11).

A case report aggregates already-persisted evidence for every capture
attached to a case (findings, posture snapshots, anomaly results) with
the analyst workflow metadata recorded around them (bookmarks, notes,
tags, investigation timeline, report history). Like capture reports,
nothing is re-scored or re-classified here: posture values are quoted
verbatim from the Stage 5 snapshots, and no case-level security score
is invented.

Three content classes are kept explicitly separate throughout:

- forensic evidence (deterministic Stages 1-7 output),
- analyst notes/tags/bookmarks (analyst-authored, never evidence),
- AI interpretation (validated Stage 8 observations only, assistive).

Determinism: identical evidence + metadata state produces
byte-identical JSON. ``generated_at`` is derived from the underlying
analysis/case timestamps rather than wall-clock time. Timeline entries
themselves carry wall-clock ``created_at`` values and are therefore
explicitly dynamic metadata.
"""

import hashlib
import json
from collections import Counter
from dataclasses import dataclass, field
from typing import Any

CASE_REPORT_SCHEMA_VERSION = "1.0"
CASE_REPORT_APPLICATION_NAME = "NS-Email SecureMailScope"

_MAX_CASE_FINDINGS = 2000
_MAX_CASE_ANOMALIES = 2000
_MAX_AI_ENTRIES = 50

_SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")


@dataclass(frozen=True, slots=True)
class CaseReportInputs:
    """Everything the case report builder needs, pre-serialized."""

    case: dict[str, Any]
    captures: list[dict[str, Any]] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    anomalies: list[dict[str, Any]] = field(default_factory=list)
    anomaly_summaries: list[dict[str, Any]] = field(default_factory=list)
    postures: list[dict[str, Any]] = field(default_factory=list)
    graph_counts: list[dict[str, Any]] = field(default_factory=list)
    correlations: list[dict[str, Any]] = field(default_factory=list)
    correlation_summary: dict[str, Any] = field(default_factory=dict)
    remediations: list[dict[str, Any]] = field(default_factory=list)
    remediation_timeline: list[dict[str, Any]] = field(default_factory=list)
    verification_results: list[dict[str, Any]] = field(default_factory=list)
    longitudinal: dict[str, Any] = field(default_factory=dict)
    bookmarks: list[dict[str, Any]] = field(default_factory=list)
    notes: list[dict[str, Any]] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    timeline: list[dict[str, Any]] = field(default_factory=list)
    reports: list[dict[str, Any]] = field(default_factory=list)
    ai_observations: list[dict[str, Any]] = field(default_factory=list)
    provenance: dict[str, Any] = field(default_factory=dict)
    ai_configured: bool = False
    ai_provider: str = ""
    ai_model: str = ""
    application_version: str = ""


def case_report_id(case_id: str) -> str:
    """Deterministic report id derived from the case id."""
    digest = hashlib.sha256(str(case_id).encode("utf-8")).hexdigest()[:12]
    return f"case_report_{digest}"


def evidence_digest(inputs: CaseReportInputs) -> str:
    """Fingerprint of the evidence state a report/export reflects."""
    canonical = json.dumps(
        {
            "captures": inputs.captures,
            "findings": inputs.findings,
            "anomalies": inputs.anomalies,
            "postures": inputs.postures,
            "correlations": inputs.correlations,
            "remediations": inputs.remediations,
            "verification_results": inputs.verification_results,
            "longitudinal": inputs.longitudinal,
        },
        sort_keys=True,
        default=str,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def build_case_report(inputs: CaseReportInputs) -> dict[str, Any]:
    """Build the deterministic case report document."""
    return {
        "report": {
            "schema_version": CASE_REPORT_SCHEMA_VERSION,
            "report_id": case_report_id(str(inputs.case.get("case_id", ""))),
            "kind": "forensic_case_report",
            "application": {
                "name": CASE_REPORT_APPLICATION_NAME,
                "version": inputs.application_version,
            },
            "generated_at": _report_generated_at(inputs),
            "evidence_digest": evidence_digest(inputs),
            "case_id": inputs.case.get("case_id"),
            "case_number": inputs.case.get("case_number"),
        },
        "case": _case_section(inputs.case),
        "evidence": {
            "captures": inputs.captures,
            "posture_summaries": _posture_summaries(inputs.postures),
            "findings": _findings_section(inputs.findings),
            "anomalies": _anomalies_section(inputs.anomalies, inputs.anomaly_summaries),
            "graph_counts": inputs.graph_counts,
        },
        "correlation": _correlation_section(inputs.correlations, inputs.correlation_summary),
        "remediation": _remediation_section(inputs.remediations),
        "verification": _verification_section(inputs.verification_results),
        "longitudinal": _longitudinal_section(inputs.longitudinal),
        "analyst_work": {
            "notice": (
                "Analyst-authored metadata. Notes, tags, and bookmarks record "
                "the investigation workflow; they are not forensic evidence and "
                "never alter findings, posture, anomaly scores, or the graph."
            ),
            "bookmarks": inputs.bookmarks,
            "notes": inputs.notes,
            "tags": list(inputs.tags),
            "timeline": inputs.timeline,
            "timeline_notice": (
                "Case timeline: events performed during the investigation. "
                "This is not the forensic timeline reconstructed from packets."
            ),
        },
        "ai_interpretation": _ai_section(inputs),
        "provenance": inputs.provenance,
        "limitations": _limitations(inputs),
        "methodology": _methodology(),
    }


def _report_generated_at(inputs: CaseReportInputs) -> str | None:
    """Deterministic report timestamp from underlying state, not wall-clock."""
    candidates = [str(c.get("analyzed_at") or "") for c in inputs.captures if c.get("analyzed_at")]
    updated = str(inputs.case.get("updated_at") or "")
    if updated:
        candidates.append(updated)
    present = [c for c in candidates if c]
    return max(present) if present else None


def _case_section(case: dict[str, Any]) -> dict[str, Any]:
    return {
        "case_id": case.get("case_id"),
        "case_number": case.get("case_number"),
        "title": case.get("title"),
        "description": case.get("description"),
        "status": case.get("status"),
        "priority": case.get("priority"),
        "created_at": case.get("created_at"),
        "updated_at": case.get("updated_at"),
        "closed_at": case.get("closed_at"),
        "schema_version": case.get("schema_version"),
    }


def _posture_summaries(postures: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Quote the authoritative per-capture posture snapshots verbatim.

    No aggregation is performed: there is deliberately no case-level
    score. Each entry carries the capture's own state and score.
    """
    summaries = []
    for posture in postures:
        summaries.append(
            {
                "capture_id": posture.get("capture_id"),
                "posture_state": posture.get("posture_state"),
                "overall_score": posture.get("overall_score"),
                "confidence": posture.get("confidence"),
                "policy_id": posture.get("policy_id"),
                "policy_version": posture.get("policy_version"),
                "total_sessions": posture.get("total_sessions"),
                "affected_sessions": posture.get("affected_sessions"),
                "finding_counts_by_severity": posture.get("finding_counts_by_severity"),
                "generated_at": posture.get("generated_at"),
            }
        )
    return sorted(summaries, key=lambda s: str(s.get("capture_id") or ""))


def _findings_section(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    ordered = sorted(
        findings,
        key=lambda f: (
            _SEVERITY_ORDER.index(str(f.get("severity")))
            if f.get("severity") in _SEVERITY_ORDER
            else 99,
            str(f.get("capture_id") or ""),
            str(f.get("rule_id") or ""),
        ),
    )
    return ordered[:_MAX_CASE_FINDINGS]


def _anomalies_section(
    anomalies: list[dict[str, Any]], summaries: list[dict[str, Any]]
) -> dict[str, Any]:
    items = list(anomalies)[:_MAX_CASE_ANOMALIES]
    band_counts: Counter[str] = Counter(str(a.get("band") or a.get("status")) for a in items)
    return {
        "items": items,
        "count": len(items),
        "bands": dict(sorted(band_counts.items())),
        "per_capture_summaries": sorted(summaries, key=lambda s: str(s.get("capture_id") or "")),
        "notice": (
            "Anomaly bands describe statistical deviation from each "
            "capture-local baseline. They are not indicators of compromise."
        ),
    }


def _correlation_section(
    correlations: list[dict[str, Any]], summary: dict[str, Any]
) -> dict[str, Any]:
    """Derived cross-capture relationships with explicit references."""
    return {
        "notice": (
            "Derived investigation intelligence: repeated structured "
            "observations across the case's captures. Correlations describe "
            "shared evidence; they are not attribution, not proof of common "
            "ownership, and not indicators of compromise or malicious intent."
        ),
        "summary": summary,
        "correlations": list(correlations),
    }


def _remediation_section(remediations: list[dict[str, Any]]) -> dict[str, Any]:
    """Analyst remediation workflow: plans and states, not evidence."""
    by_status: dict[str, int] = {}
    for record in remediations:
        status = str(record.get("status", "OPEN"))
        by_status[status] = by_status.get(status, 0) + 1
    return {
        "notice": (
            "Remediation workflow records what analysts planned and did "
            "about findings. A remediation never alters the historical "
            "finding it targets; findings remain exactly as observed."
        ),
        "count": len(remediations),
        "by_status": dict(sorted(by_status.items())),
        "remediations": list(remediations),
    }


def _verification_section(verifications: list[dict[str, Any]]) -> dict[str, Any]:
    """Evidence-based verification results quoting later captures."""
    by_result: dict[str, int] = {}
    for record in verifications:
        result = str(record.get("result", "PENDING"))
        by_result[result] = by_result.get(result, 0) + 1
    return {
        "notice": (
            "Verification evidence describes what a later capture showed "
            "about an earlier finding. Absence of a rule in one capture "
            "does not prove global security. Analyst-asserted results are "
            "labeled as such and are not evidence-based."
        ),
        "count": len(verifications),
        "by_result": dict(sorted(by_result.items())),
        "results": list(verifications),
    }


def _longitudinal_section(longitudinal: dict[str, Any]) -> dict[str, Any]:
    """Derived longitudinal analysis: observations, trend, lifecycle, drift."""
    summary = longitudinal.get("drift_summary", {}) if longitudinal else {}
    return {
        "notice": (
            "Longitudinal analysis is derived from observed captures: how "
            "posture, findings, and configurations changed across "
            "observations. Drift does not prove causality. Finding absence "
            "in one capture does not prove global remediation. Repeated "
            "findings do not prove malicious activity. Posture changes do "
            "not prove that a particular action caused the change."
        ),
        "baseline": longitudinal.get("baseline", {}) if longitudinal else {},
        "observations": list(longitudinal.get("observations", [])) if longitudinal else [],
        "posture_trend": list(longitudinal.get("posture_trend", [])) if longitudinal else [],
        "comparisons": list(longitudinal.get("comparisons", [])) if longitudinal else [],
        "drift": list(longitudinal.get("drift", [])) if longitudinal else [],
        "drift_summary": summary,
    }


def _ai_section(inputs: CaseReportInputs) -> dict[str, Any]:
    section: dict[str, Any] = {
        "notice": (
            "AI-generated interpretive assistance derived from structured "
            "evidence. Only validated observations are included. AI output "
            "is never forensic evidence and never overrides findings."
        ),
        "configured": inputs.ai_configured,
        "provider": inputs.ai_provider if inputs.ai_configured else "",
        "model": inputs.ai_model if inputs.ai_configured else "",
    }
    if not inputs.ai_configured:
        section["observations"] = []
        section["detail"] = "AI analyst not configured"
        return section
    entries = []
    for item in inputs.ai_observations[:_MAX_AI_ENTRIES]:
        entries.append(
            {
                "response_id": item.get("response_id"),
                "capture_id": item.get("capture_id"),
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
    section["observations"] = entries
    if not entries:
        section["detail"] = "No validated AI observations recorded for this case"
    return section


def _limitations(inputs: CaseReportInputs) -> dict[str, Any]:
    items = [
        "Case metadata (notes, tags, bookmarks, priority, status) is analyst "
        "workflow context. It does not alter forensic evidence, severity, "
        "posture, anomaly scores, or graph relationships.",
        "Posture values quoted here are the per-capture Stage 5 snapshots; "
        "no case-level score is computed or implied.",
        "Behavioral anomalies are statistical deviations from capture-local "
        "baselines; they are not indicators of compromise or maliciousness.",
        "Email message bodies, credentials, and raw packet payloads are "
        "excluded from all case output by design.",
        "Technical provenance metadata below records what was processed, "
        "when, and by which application version. It is not a legal "
        "chain-of-custody certification.",
    ]
    if not inputs.ai_configured:
        items.append("AI analyst is not configured; no AI observations are included.")
    elif not inputs.ai_observations:
        items.append("No validated AI observations were recorded for this case.")
    return {"items": items}


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
        "Stage 9: deterministic report assembly from persisted evidence.",
        "Stage 11: case workspace — capture references, analyst notes, tags, "
        "bookmarks, investigation timeline, and reproducible export. Case "
        "metadata never mutates forensic truth.",
        "Stage 12: multi-capture correlation — deterministic shared-evidence "
        "relationships derived from structured observations. Correlation is "
        "not attribution and never alters forensic conclusions.",
        "Stage 13: remediation workflow — analyst plans over immutable "
        "findings with evidence-based verification against later captures. "
        "Absence of a rule in one capture does not prove global security.",
    ]


def case_report_to_json(report: dict[str, Any]) -> str:
    """Serialize the case report deterministically (stable key order)."""
    return json.dumps(report, indent=2, sort_keys=True, default=str)
