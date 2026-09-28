"""Longitudinal drift orchestration (Stage 14).

``DriftService`` derives observation snapshots, pairwise comparisons,
and drift records from immutable analysis output. The data flow is
strictly one-way and read-only: sessions, findings, posture snapshots,
anomaly summaries, correlations, and remediation records are read;
only the analyst-selected baseline is written (workflow metadata).

Nothing derived is persisted — observations, comparisons, and drift
records are pure functions of case attachments plus evidence state,
so they can never go stale and can never mutate forensic truth.
Neutral language only: change, observed, no longer observed. No
attribution, no intent, no compromise claims, no scores, no causality.
"""

import re
from dataclasses import replace
from itertools import pairwise
from typing import Any

from engine.drift import (
    DriftRecord,
    DriftType,
    ObservationView,
    build_observation,
    compare_pair,
    lifecycle_at,
    posture_trend,
    summarize_drift,
)
from engine.drift.model import MAX_DRIFT_PER_CASE

from app.case_store import CASE_ID_PATTERN, CaseStore
from app.drift_store import DriftStore
from app.registry import CaptureRegistry
from app.services.analysis import CaptureAnalysisService
from app.services.cases import CaseNotFoundError, CaseValidationError
from app.services.remediation_errors import RemediationNotFoundError

DRIFT_ID_PATTERN = re.compile(r"^drift_[0-9a-f]{16}$")

#: Bounded API output (mirrors the remediation listing bounds).
DEFAULT_LIST_LIMIT = 100
MAX_LIST_LIMIT = 500


def _require_case_id(case_id: str) -> str:
    cleaned = case_id.strip()
    if not CASE_ID_PATTERN.fullmatch(cleaned):
        raise CaseNotFoundError(case_id)
    return cleaned


def _observation_to_dict(observation: ObservationView) -> dict[str, Any]:
    return {
        "observation_id": observation.observation_id,
        "case_id": observation.case_id,
        "capture_id": observation.capture_id,
        "analyzed": observation.analyzed,
        "analysis_status": observation.analysis_status,
        "analyzed_at": observation.analyzed_at,
        "created_at": observation.created_at,
        "posture_score": observation.posture_score,
        "posture_state": observation.posture_state,
        "session_count": observation.session_count,
        "finding_rules": [
            {
                "rule_id": rule.rule_id,
                "severity": rule.severity,
                "title": rule.title,
                "count": rule.count,
                "finding_ids": list(rule.finding_ids),
            }
            for rule in observation.finding_rules
        ],
        "protocols": list(observation.protocols),
        "tls_versions": list(observation.tls_versions),
        "cipher_suites": list(observation.cipher_suites),
        "key_exchanges": list(observation.key_exchanges),
        "tls_config_fingerprints": [
            {
                "fingerprint": config.fingerprint,
                "tls_version": config.tls_version,
                "cipher_suite": config.cipher_suite,
                "key_exchange": config.key_exchange,
            }
            for config in observation.tls_config_fingerprints
        ],
        "certificates": [
            {
                "fingerprint": cert.fingerprint,
                "subject": cert.subject,
                "issuer": cert.issuer,
                "valid": cert.valid,
                "signature_algorithm": cert.signature_algorithm,
            }
            for cert in observation.certificates
        ],
        "anomaly_bands": (
            dict(observation.anomaly_bands) if observation.anomaly_bands is not None else None
        ),
        "evidence_digest": observation.evidence_digest,
    }


class DriftNotFoundError(Exception):
    """The requested drift id is unknown (covers malformed ids)."""

    def __init__(self, drift_id: str) -> None:
        super().__init__("no drift record exists with this id")
        self.drift_id = drift_id


class BaselineNotFoundError(Exception):
    """No baseline has been selected for the case."""

    def __init__(self, case_id: str) -> None:
        super().__init__("no baseline observation has been selected for this case")
        self.case_id = case_id


class DriftService:
    """Derive and serve longitudinal drift (read-only evidence)."""

    def __init__(
        self,
        drift_store: DriftStore,
        case_store: CaseStore,
        registry: CaptureRegistry,
        analysis: CaptureAnalysisService,
        remediation_store: Any,
    ) -> None:
        self._drift = drift_store
        self._cases = case_store
        self._registry = registry
        self._analysis = analysis
        self._remediations = remediation_store
        self._correlations: Any = None

    def attach_correlation_service(self, correlation_service: Any) -> None:
        """Provide correlations for pattern-change detection (same pattern)."""
        self._correlations = correlation_service

    # -- observations ----------------------------------------------------------

    def _require_case(self, case_id: str) -> str:
        cleaned = _require_case_id(case_id)
        if self._cases.get_case(cleaned) is None:
            raise CaseNotFoundError(case_id)
        return cleaned

    def _require_baseline_id(self, case_id: str) -> str:
        record = self._drift.get_baseline(case_id)
        if record is None:
            raise BaselineNotFoundError(case_id)
        return record.baseline_capture_id

    def _build_observation(self, case_id: str, capture_id: str) -> ObservationView | None:
        """Assemble one observation; None when the capture is unregistered."""
        if self._registry.get(capture_id) is None:
            return None
        status = self._analysis.analysis_status(capture_id)
        analyzed = status.status == "completed"
        analyzed_at = status.analyzed_at.isoformat() if status.analyzed_at else None
        sessions = self._analysis.sessions_for(capture_id) if analyzed else []
        findings = self._analysis.findings_for_capture(capture_id) if analyzed else []
        posture = self._analysis.posture_snapshot(capture_id) if analyzed else None
        anomaly_summary = self._analysis.anomaly_summary(capture_id) if analyzed else None
        return build_observation(
            case_id=case_id,
            capture_id=capture_id,
            analyzed=analyzed,
            analysis_status=status.status,
            analyzed_at=analyzed_at,
            sessions=sessions,
            findings=findings,
            posture=posture,
            anomaly_summary=anomaly_summary,
        )

    def _ordered_observations(self, case_id: str) -> list[ObservationView]:
        """All observations in canonical attachment order (deterministic)."""
        cleaned = self._require_case(case_id)
        observations: list[ObservationView] = []
        for attachment in self._cases.list_attachments(cleaned):
            observation = self._build_observation(cleaned, attachment.capture_id)
            if observation is not None:
                observations.append(observation)
        return observations

    def list_observations(self, case_id: str) -> list[dict[str, Any]]:
        """Observation snapshots in canonical attachment order."""
        return [_observation_to_dict(obs) for obs in self._ordered_observations(case_id)]

    # -- baseline -----------------------------------------------------------------

    def set_baseline(self, case_id: str, capture_id: str) -> dict[str, Any]:
        """Record the analyst-selected baseline capture for a case."""
        from app.services.cases import CaptureNotFoundError

        cleaned = self._require_case(case_id)
        cleaned_capture = capture_id.strip()
        if self._registry.get(cleaned_capture) is None:
            raise CaptureNotFoundError(cleaned_capture)
        if not self._cases.is_attached(cleaned, cleaned_capture):
            raise CaseValidationError("baseline capture does not belong to this case")
        record = self._drift.set_baseline(cleaned, cleaned_capture)
        self._cases.append_timeline(
            cleaned, "baseline_selected", {"capture_id": record.baseline_capture_id}
        )
        return {"case_id": cleaned, "baseline_capture_id": record.baseline_capture_id}

    def get_baseline(self, case_id: str) -> dict[str, Any]:
        """Current baseline selection; null when none has been selected."""
        cleaned = self._require_case(case_id)
        record = self._drift.get_baseline(cleaned)
        return {
            "case_id": cleaned,
            "baseline_capture_id": record.baseline_capture_id if record else None,
        }

    def clear_baseline(self, case_id: str) -> bool:
        """Remove the baseline selection, audited on the case timeline."""
        cleaned = self._require_case(case_id)
        cleared = self._drift.clear_baseline(cleaned)
        if cleared:
            self._cases.append_timeline(cleaned, "baseline_cleared", {})
        return cleared

    def clear_baseline_if_match(self, case_id: str, capture_id: str) -> None:
        """Detach hook: drop a baseline that referenced a detached capture."""
        try:
            cleaned = _require_case_id(case_id)
        except CaseNotFoundError:
            return
        if self._drift.clear_baseline_if_match(cleaned, capture_id.strip()):
            self._cases.append_timeline(
                cleaned, "baseline_cleared", {"capture_id": capture_id.strip()}
            )

    # -- comparisons + drift ---------------------------------------------------------

    def _correlation_maps(
        self, case_id: str
    ) -> tuple[dict[tuple[str, str], set[str]], dict[tuple[str, str], str]]:
        """Indexed correlation presence for pattern-change detection."""
        service = self._correlations
        if service is None:
            return {}, {}
        presence: dict[tuple[str, str], set[str]] = {}
        ids: dict[tuple[str, str], str] = {}
        for correlation in service.compute(case_id).correlations:
            key = (correlation.correlation_type.value, correlation.evidence_key)
            presence.setdefault(key, set()).update(correlation.source_capture_ids)
            ids.setdefault(key, correlation.correlation_id)
        return presence, ids

    def _observation_index(self, case_id: str) -> dict[str, ObservationView]:
        return {obs.capture_id: obs for obs in self._ordered_observations(case_id)}

    def _analyzed_chain(self, case_id: str) -> list[ObservationView]:
        """Attachment-ordered observations with completed analysis."""
        return [obs for obs in self._ordered_observations(case_id) if obs.analyzed]

    def compare_pair(
        self,
        case_id: str,
        baseline_capture_id: str,
        comparison_capture_id: str,
        *,
        anchor_capture_id: str | None = None,
    ) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        """Compare an explicit capture pair with lifecycle context.

        An empty baseline capture id falls back to the case baseline
        selection (404 when none has been selected). An explicit anchor
        defaults the same way, so ad-hoc pairs share the case-wide
        lifecycle context used by the consecutive chain.
        """
        cleaned = self._require_case(case_id)
        base_id = baseline_capture_id.strip()
        if not base_id:
            base_id = self._require_baseline_id(cleaned)
        cmp_id = comparison_capture_id.strip()
        if base_id == cmp_id:
            raise CaseValidationError("baseline and comparison captures must differ")
        index = self._observation_index(cleaned)
        for candidate in (base_id, cmp_id):
            observation = index.get(candidate)
            if observation is None:
                raise CaseValidationError(f"capture {candidate} does not belong to this case")
            if not observation.analyzed:
                raise CaseValidationError(f"capture {candidate} has not been analyzed")
        requested_anchor = anchor_capture_id.strip() if anchor_capture_id else ""
        stored_baseline = self._drift.get_baseline(cleaned)
        order = [obs.capture_id for obs in self._ordered_observations(cleaned)]
        candidate_anchor = requested_anchor or (
            stored_baseline.baseline_capture_id if stored_baseline else base_id
        )
        if candidate_anchor not in order:
            raise CaseValidationError("lifecycle anchor is not an analyzed case capture")
        # A stored baseline positioned after the comparison cannot anchor
        # it; fall back to the pair itself rather than failing.
        if order.index(candidate_anchor) > order.index(cmp_id):
            candidate_anchor = base_id
        anchor_id = candidate_anchor
        anchor_obs = index.get(anchor_id)
        if anchor_obs is None or not anchor_obs.analyzed:
            raise CaseValidationError("lifecycle anchor is not an analyzed case capture")
        intermediates = [
            obs
            for obs in self._ordered_observations(cleaned)
            if obs.analyzed
            and order.index(anchor_id) < order.index(obs.capture_id) < order.index(cmp_id)
        ]
        presence, corr_ids = self._correlation_maps(cleaned)
        comparison, records = compare_pair(
            case_id=cleaned,
            anchor=anchor_obs,
            previous=index[base_id],
            later=index[cmp_id],
            intermediates=intermediates,
            correlation_presence=presence,
            correlation_ids=corr_ids,
        )
        enriched = self._link_regressions(cleaned, records)
        comparison_dict = comparison.to_dict()
        return comparison_dict, [record.to_dict() for record in enriched]

    def list_comparisons(self, case_id: str) -> list[dict[str, Any]]:
        """Consecutive-pair comparisons along the canonical observation order."""
        cleaned = self._require_case(case_id)
        chain = self._analyzed_chain(cleaned)
        baseline_record = self._drift.get_baseline(cleaned)
        anchor_id = baseline_record.baseline_capture_id if baseline_record else None
        order = [obs.capture_id for obs in self._ordered_observations(cleaned)]
        presence, corr_ids = self._correlation_maps(cleaned)
        comparisons: list[dict[str, Any]] = []
        for previous, later in pairwise(chain):
            anchor_id_resolved = anchor_id or previous.capture_id
            anchor_obs = next((obs for obs in chain if obs.capture_id == anchor_id_resolved), None)
            if anchor_obs is None:
                anchor_obs, anchor_id_resolved = previous, previous.capture_id
            intermediates = [
                obs
                for obs in chain
                if order.index(anchor_id_resolved)
                < order.index(obs.capture_id)
                < order.index(later.capture_id)
            ]
            comparison, records = compare_pair(
                case_id=cleaned,
                anchor=anchor_obs,
                previous=previous,
                later=later,
                intermediates=intermediates,
                correlation_presence=presence,
                correlation_ids=corr_ids,
            )
            enriched = self._link_regressions(cleaned, records)
            comparison_dict = comparison.to_dict()
            comparison_dict["drift"] = [record.to_dict() for record in enriched]
            comparisons.append(comparison_dict)
        return comparisons

    def list_drift(
        self,
        case_id: str,
        *,
        type_filter: str | None = None,
        comparison_capture_id: str | None = None,
        limit: int = DEFAULT_LIST_LIMIT,
        offset: int = 0,
    ) -> tuple[int, list[dict[str, Any]]]:
        """Filtered, paginated drift records across all case comparisons."""
        cleaned = self._require_case(case_id)
        wanted: DriftType | None = None
        if type_filter is not None:
            try:
                wanted = DriftType(type_filter.strip().lower())
            except ValueError as error:
                raise CaseValidationError(
                    "type must be one of " + ", ".join(sorted(t.value for t in DriftType))
                ) from error
        if limit < 1 or limit > MAX_LIST_LIMIT:
            raise CaseValidationError(f"limit must be between 1 and {MAX_LIST_LIMIT}")
        if offset < 0:
            raise CaseValidationError("offset must not be negative")
        items = self._all_drift(cleaned, wanted=wanted, comparison_capture_id=comparison_capture_id)
        total = len(items)
        return total, items[offset : offset + limit]

    def _all_drift(
        self,
        case_id: str,
        *,
        wanted: DriftType | None = None,
        comparison_capture_id: str | None = None,
    ) -> list[dict[str, Any]]:
        """All drift records, sorted and bounded (no pagination validation)."""
        items: list[dict[str, Any]] = []
        for comparison in self.list_comparisons(case_id):
            for record in comparison["drift"]:
                if wanted is not None and record["drift_type"] != wanted.value:
                    continue
                if (
                    comparison_capture_id is not None
                    and record["comparison_capture_id"] != comparison_capture_id.strip()
                ):
                    continue
                items.append(record)
        # Sort by content-stable keys first: drift ids embed the random
        # case id, so they serve only as a final uniqueness tiebreak.
        items.sort(
            key=lambda r: (
                r["drift_type"],
                r["evidence_key"],
                r["baseline_capture_id"],
                r["comparison_capture_id"],
                r["drift_id"],
            )
        )
        return items[:MAX_DRIFT_PER_CASE]

    def get_drift(self, case_id: str, drift_id: str) -> dict[str, Any]:
        """One drift record with linked remediation snapshots."""
        cleaned_id = drift_id.strip()
        if not DRIFT_ID_PATTERN.fullmatch(cleaned_id):
            raise DriftNotFoundError(drift_id)
        for item in self._all_drift(self._require_case(case_id)):
            if item["drift_id"] == cleaned_id:
                record = dict(item)
                record["linked_remediations"] = [
                    self._remediation_snapshot(case_id, remediation_id)
                    for remediation_id in item["related_remediation_ids"]
                ]
                return record
        raise DriftNotFoundError(drift_id)

    def _remediation_snapshot(self, case_id: str, remediation_id: str) -> dict[str, Any]:
        """Small read-only snapshot of a linked remediation."""
        record = self._remediations.get_remediation(case_id, remediation_id)
        if record is None:
            return {"remediation_id": remediation_id, "available": False}
        return {
            "remediation_id": record.remediation_id,
            "available": True,
            "title": record.title,
            "status": record.status,
            "rule_id": record.rule_id,
            "verification_status": record.verification_status,
        }

    def drift_summary(self, case_id: str) -> dict[str, Any]:
        """Counts only — never a score."""
        cleaned = self._require_case(case_id)
        baseline_record = self._drift.get_baseline(cleaned)
        observations = self._ordered_observations(cleaned)
        items = self._all_drift(cleaned)
        records = [
            DriftRecord(
                drift_id=item["drift_id"],
                case_id=item["case_id"],
                drift_type=DriftType(item["drift_type"]),
                evidence_key=item["evidence_key"],
                baseline_capture_id=item["baseline_capture_id"],
                comparison_capture_id=item["comparison_capture_id"],
            )
            for item in items
        ]
        return summarize_drift(
            cleaned,
            baseline_record.baseline_capture_id if baseline_record else None,
            len(observations),
            records,
        )

    def remediation_drift(self, case_id: str, remediation_id: str) -> dict[str, Any]:
        """Regression view for one remediation (read-only, no transitions)."""
        cleaned = self._require_case(case_id)
        record = self._remediations.get_remediation(cleaned, remediation_id.strip())
        if record is None:
            raise RemediationNotFoundError(remediation_id)
        rule_id = record.rule_id
        if not rule_id:
            raise CaseValidationError("remediation has no associated rule")
        baseline_capture_id: str | None = None
        if record.target_type == "finding":
            finding = self._analysis.finding(record.target_id)
            if finding is not None:
                baseline_capture_id = finding.capture_id
        if baseline_capture_id is None:
            raise CaseValidationError("remediation baseline capture cannot be resolved")
        ordered = self._ordered_observations(cleaned)
        order = [obs.capture_id for obs in ordered]
        if baseline_capture_id not in order:
            raise CaseValidationError("remediation baseline is not part of this case")
        analyzed = [obs for obs in ordered if obs.analyzed]
        anchor = next(obs for obs in analyzed if obs.capture_id == baseline_capture_id)
        later_captures = [
            obs.capture_id
            for obs in analyzed
            if order.index(obs.capture_id) > order.index(anchor.capture_id)
        ]
        latest_id = later_captures[-1] if later_captures else anchor.capture_id
        latest = next(obs for obs in analyzed if obs.capture_id == latest_id)
        intermediates = [
            obs
            for obs in analyzed
            if order.index(anchor.capture_id) < order.index(obs.capture_id) < order.index(latest_id)
        ]
        current = lifecycle_at(rule_id, anchor, intermediates, latest)
        verifications = [
            {
                "verification_id": item.verification_id,
                "verification_capture_id": item.verification_capture_id,
                "result": item.result,
                "method": item.method,
            }
            for item in self._remediations.list_verifications(cleaned, record.remediation_id)
        ]
        items = self._all_drift(cleaned)
        related = [
            item["drift_id"]
            for item in items
            if item["drift_type"] == DriftType.FINDING_RECURRED.value
            and item["evidence_key"] == f"finding-rule|{rule_id.lower()}"
            and record.remediation_id in item["related_remediation_ids"]
        ]
        return {
            "case_id": cleaned,
            "remediation_id": record.remediation_id,
            "rule_id": rule_id,
            "status": record.status,
            "verification_status": record.verification_status,
            "baseline_capture_id": baseline_capture_id,
            "verification_captures": sorted(
                {
                    item["verification_capture_id"]
                    for item in verifications
                    if item["verification_capture_id"]
                }
            ),
            "verifications": verifications,
            "later_observations": later_captures,
            "current_lifecycle": current["lifecycle"],
            "current_present": current["current_present"],
            "regression_detected": bool(related),
            "related_drift_ids": related,
        }

    def export_data(self, case_id: str) -> dict[str, Any]:
        """Observations, baseline, comparisons, drift, and summary for export."""
        cleaned = self._require_case(case_id)
        baseline_record = self._drift.get_baseline(cleaned)
        comparisons = self.list_comparisons(cleaned)
        items = self._all_drift(cleaned)
        observations = self._ordered_observations(cleaned)
        return {
            "observations": [_observation_to_dict(obs) for obs in observations],
            "baseline": {
                "case_id": cleaned,
                "baseline_capture_id": (
                    baseline_record.baseline_capture_id if baseline_record else None
                ),
            },
            "comparisons": comparisons,
            "drift": items,
            "drift_summary": self.drift_summary(cleaned),
            "posture_trend": posture_trend([obs for obs in observations if obs.analyzed]),
        }

    # -- regression linking ------------------------------------------------------------

    def _link_regressions(self, case_id: str, records: list[DriftRecord]) -> list[DriftRecord]:
        """Attach remediation links to recurred-finding drift records.

        A link is created when a remediation for the same rule has a
        VERIFIED verification record: the condition returned after a
        recorded success. The remediation itself is never modified —
        the analyst reviews it explicitly.
        """
        if not any(record.drift_type == DriftType.FINDING_RECURRED for record in records):
            return records
        linked: list[DriftRecord] = []
        for record in records:
            if record.drift_type != DriftType.FINDING_RECURRED:
                linked.append(record)
                continue
            rule_id = record.evidence_key.split("|", 1)[-1]
            remediation_ids: set[str] = set()
            verification_ids: set[str] = set()
            for remediation in self._remediations.list_remediations(case_id):
                if (remediation.rule_id or "").lower() != rule_id.lower():
                    continue
                verified = [
                    item
                    for item in self._remediations.list_verifications(
                        case_id, remediation.remediation_id
                    )
                    if item.result == "VERIFIED"
                ]
                if not verified:
                    continue
                remediation_ids.add(remediation.remediation_id)
                verification_ids.update(item.verification_id for item in verified)
            if not remediation_ids:
                linked.append(record)
                continue
            statement = (
                record.statement
                + " Existing remediation "
                + ", ".join(sorted(remediation_ids))
                + " may require review."
            )
            linked.append(
                replace(
                    record,
                    related_remediation_ids=tuple(sorted(remediation_ids)),
                    related_verification_ids=tuple(sorted(verification_ids)),
                    regression_after_verification=True,
                    statement=statement,
                )
            )
        return linked
