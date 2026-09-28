"""Remediation workflow orchestration (Stage 13).

``RemediationService`` coordinates remediation plans over immutable
forensic findings. The data flow is strictly one-way: the service READS
findings, sessions, posture snapshots, and anomaly records, and WRITES
only remediation workflow state (records, timeline events,
verification results). Findings are never mutated, never deleted, and
never hidden — verification quotes later evidence without touching
earlier results.
"""

from typing import Any

from engine.verification import (
    FindingView,
    PostureView,
    SessionView,
    VerificationComparison,
    VerificationMethod,
    VerificationOutcome,
    compare_rule,
)

from app.case_store import CASE_ID_PATTERN, CaseStore
from app.registry import CaptureRegistry
from app.remediation_store import (
    REMEDIATION_ID_PATTERN,
    VERIFICATION_ID_PATTERN,
    RemediationRecord,
    RemediationStore,
    RemediationTimelineEntry,
    VerificationRecord,
    validate_due_date,
    validate_owner,
)
from app.services.analysis import CaptureAnalysisService
from app.services.cases import CaseNotFoundError, CaseValidationError
from app.services.remediation_errors import RemediationNotFoundError, VerificationNotFoundError

MAX_LIST_LIMIT = 500
DEFAULT_LIST_LIMIT = 100


def _require_case_id(case_id: str) -> str:
    cleaned = case_id.strip()
    if not CASE_ID_PATTERN.fullmatch(cleaned):
        raise CaseNotFoundError(case_id)
    return cleaned


def _require_remediation_id(remediation_id: str) -> str:
    cleaned = remediation_id.strip()
    if not REMEDIATION_ID_PATTERN.fullmatch(cleaned):
        raise RemediationNotFoundError(remediation_id)
    return cleaned


def _require_verification_id(verification_id: str) -> str:
    cleaned = verification_id.strip()
    if not VERIFICATION_ID_PATTERN.fullmatch(cleaned):
        raise VerificationNotFoundError(verification_id)
    return cleaned


def _record_to_dict(record: RemediationRecord) -> dict[str, Any]:
    return {
        "remediation_id": record.remediation_id,
        "case_id": record.case_id,
        "target_type": record.target_type,
        "target_id": record.target_id,
        "rule_id": record.rule_id,
        "title": record.title,
        "description": record.description,
        "recommended_action": record.recommended_action,
        "recommended_action_source": record.recommended_action_source,
        "status": record.status,
        "priority": record.priority,
        "owner": record.owner,
        "due_at": record.due_at,
        "created_at": record.created_at.isoformat() if record.created_at else None,
        "updated_at": record.updated_at.isoformat() if record.updated_at else None,
        "completed_at": record.completed_at.isoformat() if record.completed_at else None,
        "verification_status": record.verification_status,
        "verification_capture_id": record.verification_capture_id,
        "verification_method": record.verification_method,
    }


def _timeline_to_dict(entry: RemediationTimelineEntry) -> dict[str, Any]:
    return {
        "entry_id": entry.entry_id,
        "remediation_id": entry.remediation_id,
        "case_id": entry.case_id,
        "event_type": entry.event_type,
        "detail": dict(entry.detail),
        "created_at": entry.created_at.isoformat() if entry.created_at else None,
    }


def _verification_to_dict(record: VerificationRecord) -> dict[str, Any]:
    return {
        "verification_id": record.verification_id,
        "remediation_id": record.remediation_id,
        "case_id": record.case_id,
        "method": record.method,
        "baseline_capture_id": record.baseline_capture_id,
        "baseline_session_id": record.baseline_session_id,
        "rule_id": record.rule_id,
        "verification_capture_id": record.verification_capture_id,
        "result": record.result,
        "comparison": dict(record.comparison),
        "notes": record.notes,
        "created_at": record.created_at.isoformat() if record.created_at else None,
        "completed_at": record.completed_at.isoformat() if record.completed_at else None,
    }


def _session_view(session: Any) -> SessionView:
    """Project a session into the comparison view (read-only)."""
    handshake = session.handshake
    certificates = list(session.certificates or [])
    primary = certificates[0] if certificates else None
    started = session.started_at.isoformat() if session.started_at else None
    valid: bool | None = None
    if primary is not None and session.started_at is not None:
        valid = primary.not_before <= session.started_at <= primary.not_after
    return SessionView(
        session_id=session.id,
        capture_id=session.capture_id,
        protocol=session.protocol.value if session.protocol else None,
        server_ip=str(session.server_ip),
        server_port=session.server_port,
        tls_version=handshake.tls_version.value if handshake else None,
        cipher_suite=handshake.cipher_suite if handshake else None,
        key_exchange=handshake.key_exchange.value if handshake else None,
        handshake_complete=handshake.handshake_complete if handshake else None,
        complete=bool(session.complete),
        certificate_fingerprint=primary.fingerprint_sha256 if primary else None,
        certificate_subject=primary.subject if primary else None,
        certificate_valid=valid,
        signature_algorithm=primary.signature_algorithm if primary else None,
        subject_alternative_names=tuple(primary.subject_alternative_names) if primary else (),
        started_at=started,
    )


def _finding_view(finding: Any, capture_id: str) -> FindingView:
    return FindingView(
        finding_id=finding.id,
        capture_id=capture_id,
        session_id=finding.session_id,
        rule_id=finding.rule_id,
        severity=finding.severity.value if finding.severity else None,
        confidence=finding.confidence.value if finding.confidence else None,
    )


def _posture_view(capture_id: str, snapshot: dict[str, Any] | None) -> PostureView | None:
    if snapshot is None:
        return None
    return PostureView(
        capture_id=capture_id,
        posture_state=snapshot.get("posture_state"),
        overall_score=snapshot.get("overall_score"),
    )


class RemediationService:
    """Remediation plans and evidence-based verification (read-only evidence)."""

    def __init__(
        self,
        remediation_store: RemediationStore,
        case_store: CaseStore,
        registry: CaptureRegistry,
        analysis: CaptureAnalysisService,
    ) -> None:
        self._remediations = remediation_store
        self._cases = case_store
        self._registry = registry
        self._analysis = analysis

    # -- cases ---------------------------------------------------------------

    def _require_case(self, case_id: str) -> str:
        cleaned = _require_case_id(case_id)
        if self._cases.get_case(cleaned) is None:
            raise CaseNotFoundError(case_id)
        return cleaned

    def get_remediation(self, case_id: str, remediation_id: str) -> RemediationRecord:
        """Fetch a remediation scoped to its case."""
        record = self._remediations.get_remediation(
            self._require_case(case_id), _require_remediation_id(remediation_id)
        )
        if record is None:
            raise RemediationNotFoundError(remediation_id)
        return record

    def remediation_exists(self, case_id: str, remediation_id: str) -> bool:
        """Existence probe for note-target validation (no exceptions)."""
        try:
            cleaned_case = _require_case_id(case_id)
        except CaseNotFoundError:
            return False
        if not REMEDIATION_ID_PATTERN.fullmatch(remediation_id.strip()):
            return False
        return self._remediations.get_remediation(cleaned_case, remediation_id.strip()) is not None

    # -- targets ---------------------------------------------------------------

    def _check_target(self, case_id: str, target_type: str, target_id: str) -> None:
        """Reference check: finding/session must exist; case must match."""
        if target_type == "finding":
            if self._analysis.finding(target_id) is None:
                raise CaseValidationError("referenced finding does not exist")
            return
        if target_type == "session":
            if self._analysis.session(target_id) is None:
                raise CaseValidationError("referenced session does not exist")
            return
        if target_type == "case":
            if target_id != case_id:
                raise CaseValidationError("case remediations must target their own case")
            return
        # host / certificate / tls_configuration: shape-validated by the
        # store; resolved at navigation time (Stage 12 precedent).

    # -- CRUD --------------------------------------------------------------------

    def create_remediation(
        self,
        case_id: str,
        target_type: str,
        target_id: str,
        title: str,
        description: str = "",
        recommended_action: str = "",
        priority: str = "MEDIUM",
        owner: str = "",
        due_at: str | None = None,
        rule_id: str | None = None,
    ) -> RemediationRecord:
        cleaned_case = self._require_case(case_id)
        self._check_target(cleaned_case, target_type.strip(), target_id.strip())
        try:
            record = self._remediations.create_remediation(
                cleaned_case,
                target_type.strip(),
                target_id.strip(),
                title,
                description,
                recommended_action,
                "analyst",
                rule_id.strip() if rule_id and rule_id.strip() else None,
                priority.strip() if priority else "MEDIUM",
                owner,
                due_at,
            )
        except ValueError as error:
            raise CaseValidationError(str(error)) from error
        self._remediations.append_timeline(
            cleaned_case, record.remediation_id, "remediation_created", {"title": record.title}
        )
        return record

    def create_from_finding(
        self,
        case_id: str,
        finding_id: str,
        title: str | None = None,
        description: str = "",
        priority: str | None = None,
        owner: str = "",
        due_at: str | None = None,
    ) -> RemediationRecord:
        """Build a remediation from existing policy guidance (no LLM).

        The record preserves the Stage 4 recommendation verbatim, labeled
        with its policy-baseline source; the analyst may add notes.
        """
        cleaned_case = self._require_case(case_id)
        finding = self._analysis.finding(finding_id.strip())
        if finding is None:
            raise CaseValidationError("referenced finding does not exist")
        guidance = finding.remediation
        if guidance is not None and guidance.action.strip():
            parts = [f"Recommended action from SecureMailScope policy baseline: {guidance.action}"]
            if guidance.target:
                parts.append(f"Target: {guidance.target}")
            if guidance.rationale:
                parts.append(f"Rationale: {guidance.rationale}")
            recommended = "\n".join(parts)
            source = "policy"
        else:
            recommended = ""
            source = "analyst"
        try:
            record = self._remediations.create_remediation(
                cleaned_case,
                "finding",
                finding.id,
                title.strip() if title and title.strip() else finding.title,
                description,
                recommended,
                source,
                finding.rule_id,
                priority.strip() if priority else "MEDIUM",
                owner,
                due_at,
            )
        except ValueError as error:
            raise CaseValidationError(str(error)) from error
        self._remediations.append_timeline(
            cleaned_case,
            record.remediation_id,
            "remediation_created",
            {"title": record.title, "rule_id": finding.rule_id, "from": "finding"},
        )
        return record

    def list_remediations(
        self,
        case_id: str,
        *,
        status: str | None = None,
        priority: str | None = None,
        owner: str | None = None,
        verification_status: str | None = None,
        rule: str | None = None,
        target: str | None = None,
        search: str | None = None,
        sort: str = "updated",
        limit: int = DEFAULT_LIST_LIMIT,
        offset: int = 0,
    ) -> tuple[int, list[dict[str, Any]]]:
        """Filtered, sorted, paginated remediation records (bounded output)."""
        cleaned_case = self._require_case(case_id)
        if status is not None:
            from app.remediation_store import validate_remediation_status

            try:
                validate_remediation_status(status.strip().upper())
            except ValueError as error:
                raise CaseValidationError(str(error)) from error
            wanted_status = status.strip().upper()
        else:
            wanted_status = None
        if verification_status is not None:
            from app.remediation_store import validate_verification_status

            try:
                validate_verification_status(verification_status.strip().upper())
            except ValueError as error:
                raise CaseValidationError(str(error)) from error
            wanted_verification = verification_status.strip().upper()
        else:
            wanted_verification = None
        if sort not in ("priority", "due_date", "updated", "status"):
            raise CaseValidationError("sort must be one of priority, due_date, updated, status")
        if limit < 1 or limit > MAX_LIST_LIMIT:
            raise CaseValidationError(f"limit must be between 1 and {MAX_LIST_LIMIT}")
        if offset < 0:
            raise CaseValidationError("offset must not be negative")

        needle = search.strip().lower() if search and search.strip() else None
        items = []
        for record in self._remediations.list_remediations(cleaned_case):
            if wanted_status is not None and record.status != wanted_status:
                continue
            if priority is not None and record.priority != priority.strip().upper():
                continue
            if owner is not None and record.owner.lower() != owner.strip().lower():
                continue
            if wanted_verification is not None and (
                record.verification_status != wanted_verification
            ):
                continue
            if rule is not None and (record.rule_id or "").lower() != rule.strip().lower():
                continue
            if target is not None and record.target_id != target.strip():
                continue
            if needle is not None and needle not in (
                f"{record.title} {record.description} {record.owner} "
                f"{record.target_id} {record.rule_id or ''}".lower()
            ):
                continue
            items.append(_record_to_dict(record))

        rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        if sort == "priority":
            items.sort(key=lambda r: (rank.get(r["priority"], 4), r["remediation_id"]))
        elif sort == "due_date":
            items.sort(key=lambda r: (r["due_at"] is None, r["due_at"] or "", r["remediation_id"]))
        elif sort == "status":
            items.sort(key=lambda r: (r["status"], r["remediation_id"]))
        else:
            items.sort(key=lambda r: (r["updated_at"] or "", r["remediation_id"]), reverse=True)
        total = len(items)
        return total, items[offset : offset + limit]

    def list_for_finding(self, case_id: str, finding_id: str) -> list[dict[str, Any]]:
        """Remediations targeting one finding within a case."""
        cleaned_case = self._require_case(case_id)
        if self._analysis.finding(finding_id.strip()) is None:
            raise CaseValidationError("referenced finding does not exist")
        return [
            _record_to_dict(record)
            for record in self._remediations.list_for_finding(cleaned_case, finding_id.strip())
        ]

    def import_remediation(
        self,
        case_id: str,
        target_type: str,
        target_id: str,
        title: str,
        description: str,
        recommended_action: str,
        priority: str,
        status: str,
        owner: str,
        due_at: str | None,
        rule_id: str | None,
    ) -> RemediationRecord:
        """Import one remediation record with verification state reset."""
        cleaned_case = self._require_case(case_id)
        self._check_target(cleaned_case, target_type, target_id)
        if target_type == "case":
            target_id = cleaned_case
        try:
            return self._remediations.import_remediation(
                cleaned_case,
                target_type,
                target_id,
                title,
                description,
                recommended_action,
                priority,
                status,
                owner,
                due_at,
                rule_id,
            )
        except ValueError as error:
            raise CaseValidationError(str(error)) from error

    def update_remediation(
        self,
        case_id: str,
        remediation_id: str,
        *,
        title: str | None = None,
        description: str | None = None,
        recommended_action: str | None = None,
        priority: str | None = None,
        owner: str | None = None,
        due_at: str | None = None,
        status: str | None = None,
    ) -> RemediationRecord:
        cleaned_case = self._require_case(case_id)
        current = self._remediations.get_remediation(
            cleaned_case, _require_remediation_id(remediation_id)
        )
        if current is None:
            raise RemediationNotFoundError(remediation_id)
        try:
            if owner is not None:
                validate_owner(owner)
            if due_at is not None:
                validate_due_date(due_at)
            updated = self._remediations.update_remediation(
                cleaned_case,
                current.remediation_id,
                title=title,
                description=description,
                recommended_action=recommended_action,
                priority=priority.strip().upper() if priority else None,
                owner=owner,
                due_at=due_at,
                status=status.strip().upper() if status else None,
            )
        except ValueError as error:
            raise CaseValidationError(str(error)) from error
        if updated is None:  # pragma: no cover - existence checked above
            raise RemediationNotFoundError(remediation_id)
        if status is not None and status.strip().upper() != current.status:
            self._remediations.append_timeline(
                cleaned_case,
                updated.remediation_id,
                "status_changed",
                {"from": current.status, "to": updated.status},
            )
        if owner is not None and owner.strip() != current.owner:
            self._remediations.append_timeline(
                cleaned_case,
                updated.remediation_id,
                "owner_changed",
                {"from": current.owner, "to": updated.owner},
            )
        if priority is not None and priority.strip().upper() != current.priority:
            self._remediations.append_timeline(
                cleaned_case,
                updated.remediation_id,
                "priority_changed",
                {"from": current.priority, "to": updated.priority},
            )
        return updated

    def delete_remediation(self, case_id: str, remediation_id: str) -> None:
        cleaned_case = self._require_case(case_id)
        if not self._remediations.delete_remediation(
            cleaned_case, _require_remediation_id(remediation_id)
        ):
            raise RemediationNotFoundError(remediation_id)

    def remediation_timeline(self, case_id: str, remediation_id: str) -> list[dict[str, Any]]:
        record = self.get_remediation(case_id, remediation_id)
        return [
            _timeline_to_dict(entry)
            for entry in self._remediations.list_timeline(record.case_id, record.remediation_id)
        ]

    def record_note_added(self, case_id: str, remediation_id: str, note_id: str) -> None:
        """Timeline hook for case notes targeting a remediation."""
        self._remediations.append_timeline(
            case_id, remediation_id, "note_added", {"note_id": note_id}
        )

    # -- verification --------------------------------------------------------------

    def _require_verification_capture(self, case_id: str, verification_capture_id: str) -> str:
        """The analyst must explicitly select an attached, analyzed capture."""
        cleaned = verification_capture_id.strip()
        if not self._cases.is_attached(case_id, cleaned):
            raise CaseValidationError("verification capture does not belong to this case")
        if self._registry.get(cleaned) is None:
            raise CaseValidationError("verification capture is not registered")
        status = self._analysis.analysis_status(cleaned)
        if status.status != "completed":
            raise CaseValidationError("verification capture has not been analyzed")
        return cleaned

    def request_verification(
        self,
        case_id: str,
        remediation_id: str,
        mode: str,
        verification_capture_id: str | None = None,
        notes: str = "",
    ) -> VerificationRecord:
        """Run evidence comparison or record a manual verification request."""
        from app.remediation_store import validate_verification_notes

        record = self.get_remediation(case_id, remediation_id)
        cleaned_mode = mode.strip().lower()
        if cleaned_mode not in ("evidence", "manual"):
            raise CaseValidationError("verification mode must be evidence or manual")
        try:
            clean_notes = validate_verification_notes(notes or "")
        except ValueError as error:
            raise CaseValidationError(str(error)) from error

        if cleaned_mode == "manual":
            if clean_notes:
                verification = self._remediations.create_verification(
                    record.case_id,
                    record.remediation_id,
                    "analyst_asserted",
                    notes=clean_notes,
                    result="VERIFIED",
                    comparison={
                        "method": "analyst_asserted",
                        "notice": (
                            "Analyst-asserted verification: an analyst recorded "
                            "that the action was verified. Not evidence-based."
                        ),
                    },
                    completed=True,
                )
                self._remediations.set_verification_state(
                    record.case_id, record.remediation_id, "VERIFIED", None, "analyst_asserted"
                )
                self._remediations.append_timeline(
                    record.case_id,
                    record.remediation_id,
                    "verification_completed",
                    {
                        "verification_id": verification.verification_id,
                        "method": "analyst_asserted",
                    },
                )
                return verification
            verification = self._remediations.create_verification(
                record.case_id, record.remediation_id, "analyst_asserted", result="PENDING"
            )
            self._remediations.set_verification_state(
                record.case_id, record.remediation_id, "PENDING", None, "analyst_asserted"
            )
            self._remediations.append_timeline(
                record.case_id,
                record.remediation_id,
                "verification_requested",
                {"verification_id": verification.verification_id, "method": "analyst_asserted"},
            )
            return verification

        # Evidence-based verification: deterministic engine comparison.
        if record.target_type != "finding" or not record.rule_id:
            raise CaseValidationError(
                "evidence verification requires a finding-linked remediation with a rule"
            )
        if verification_capture_id is None or not verification_capture_id.strip():
            raise CaseValidationError("evidence verification requires a verification capture")
        verified_capture = self._require_verification_capture(
            record.case_id, verification_capture_id
        )
        finding = self._analysis.finding(record.target_id)
        if finding is None:  # pragma: no cover - targets validated at creation
            raise CaseValidationError("baseline finding is no longer available")
        comparison = self._compare(finding, finding.capture_id or "", verified_capture, clean_notes)
        # Engine outcomes are lowercase enum values; the workflow store
        # uses uppercase verification states. Map once at the boundary.
        result = str(comparison["outcome"]).upper()
        comparison = {**comparison, "outcome": result}
        verification = self._remediations.create_verification(
            record.case_id,
            record.remediation_id,
            "evidence",
            baseline_capture_id=finding.capture_id or "",
            baseline_session_id=finding.session_id,
            rule_id=finding.rule_id,
            verification_capture_id=verified_capture,
            result=result,
            comparison=comparison,
            notes=clean_notes,
            completed=True,
        )
        self._remediations.set_verification_state(
            record.case_id,
            record.remediation_id,
            result,
            verified_capture,
            "evidence",
        )
        self._remediations.append_timeline(
            record.case_id,
            record.remediation_id,
            "verification_completed" if result == "VERIFIED" else "verification_failed",
            {
                "verification_id": verification.verification_id,
                "result": result,
                "verification_capture_id": verified_capture,
            },
        )
        return verification

    def _compare(
        self, finding: Any, baseline_capture_id: str, verification_capture_id: str, notes: str
    ) -> dict[str, Any]:
        """Assemble engine views from stores and run the comparison."""
        baseline_session = None
        if finding.session_id:
            session = self._analysis.session(finding.session_id)
            if session is None:
                return _missing_baseline_session(finding, verification_capture_id)
            baseline_session = _session_view(session)
        verification_sessions = [
            _session_view(session)
            for session in self._analysis.sessions_for(verification_capture_id)
        ]
        verification_findings = [
            _finding_view(item, verification_capture_id)
            for item in self._analysis.findings_for_capture(verification_capture_id)
        ]
        comparison = compare_rule(
            baseline_finding=_finding_view(finding, baseline_capture_id),
            baseline_session=baseline_session,
            baseline_posture=_posture_view(
                baseline_capture_id, self._analysis.posture_snapshot(baseline_capture_id)
            ),
            verification_capture_id=verification_capture_id,
            verification_sessions=verification_sessions,
            verification_findings=verification_findings,
            verification_posture=_posture_view(
                verification_capture_id, self._analysis.posture_snapshot(verification_capture_id)
            ),
        )
        result = comparison.to_dict()
        if notes:
            result["analyst_notes"] = notes
        return result

    def complete_verification(
        self, case_id: str, remediation_id: str, verification_id: str, notes: str
    ) -> VerificationRecord:
        """Complete a pending manual verification with analyst notes."""
        record = self.get_remediation(case_id, remediation_id)
        try:
            completed = self._remediations.complete_verification(
                record.case_id,
                record.remediation_id,
                _require_verification_id(verification_id),
                notes,
            )
        except ValueError as error:
            raise CaseValidationError(str(error)) from error
        if completed is None:
            raise VerificationNotFoundError(verification_id)
        self._remediations.set_verification_state(
            record.case_id, record.remediation_id, "VERIFIED", None, "analyst_asserted"
        )
        self._remediations.append_timeline(
            record.case_id,
            record.remediation_id,
            "verification_completed",
            {"verification_id": completed.verification_id, "method": "analyst_asserted"},
        )
        return completed

    def list_verifications(self, case_id: str, remediation_id: str) -> list[dict[str, Any]]:
        record = self.get_remediation(case_id, remediation_id)
        return [
            _verification_to_dict(item)
            for item in self._remediations.list_verifications(record.case_id, record.remediation_id)
        ]

    def get_verification(
        self, case_id: str, remediation_id: str, verification_id: str
    ) -> dict[str, Any]:
        """Fetch one verification record scoped to its remediation and case."""
        record = self.get_remediation(case_id, remediation_id)
        stored = self._remediations.get_verification(
            record.case_id, record.remediation_id, _require_verification_id(verification_id)
        )
        if stored is None:
            raise VerificationNotFoundError(verification_id)
        return _verification_to_dict(stored)

    # -- case integration --------------------------------------------------------------

    def remediation_counts(self, case_id: str) -> dict[str, int]:
        """Workflow counts (and verification counts) — never scores."""
        cleaned = self._require_case(case_id)
        counts = {
            "open": 0,
            "in_progress": 0,
            "blocked": 0,
            "completed": 0,
            "verification_pending": 0,
            "verified": 0,
            "failed": 0,
            "inconclusive": 0,
        }
        status_map = {
            "OPEN": "open",
            "PLANNED": "open",
            "IN_PROGRESS": "in_progress",
            "BLOCKED": "blocked",
            "COMPLETED": "completed",
            "CANCELLED": None,
        }
        verification_map = {
            "PENDING": "verification_pending",
            "VERIFIED": "verified",
            "FAILED": "failed",
            "INCONCLUSIVE": "inconclusive",
            "NOT_VERIFIED": None,
        }
        for record in self._remediations.list_remediations(cleaned):
            bucket = status_map.get(record.status)
            if bucket is not None:
                counts[bucket] += 1
            verification_bucket = verification_map.get(record.verification_status)
            if verification_bucket is not None:
                counts[verification_bucket] += 1
        return counts

    def export_data(
        self, case_id: str
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
        """Remediation records, timelines, and verification results for export."""
        cleaned = self._require_case(case_id)
        records: list[dict[str, Any]] = []
        timelines: list[dict[str, Any]] = []
        verifications: list[dict[str, Any]] = []
        for record in self._remediations.list_remediations(cleaned):
            records.append(_record_to_dict(record))
            timelines.extend(
                _timeline_to_dict(entry)
                for entry in self._remediations.list_timeline(cleaned, record.remediation_id)
            )
            verifications.extend(
                _verification_to_dict(item)
                for item in self._remediations.list_verifications(cleaned, record.remediation_id)
            )
        return records, timelines, verifications


def _missing_baseline_session(finding: Any, verification_capture_id: str) -> dict[str, Any]:
    """Session-scoped finding whose baseline session record is unavailable."""
    comparison = VerificationComparison(
        outcome=VerificationOutcome.INCONCLUSIVE,
        method=VerificationMethod.EVIDENCE,
        rule_id=finding.rule_id,
        baseline_capture_id=finding.capture_id or "",
        verification_capture_id=verification_capture_id,
        baseline_session_id=finding.session_id,
        verification_session_id=None,
        session_match="incomplete_evidence",
        rule_present_in_verification=None,
        baseline_evidence={},
        verification_evidence={},
        posture_before={},
        posture_after={},
        posture_delta_points=None,
        statement=(
            f"Rule {finding.rule_id} could not be verified: the baseline "
            "session record is unavailable."
        ),
    )
    return comparison.to_dict()


__all__ = [
    "RemediationService",
    "_record_to_dict",
    "_timeline_to_dict",
    "_verification_to_dict",
]
