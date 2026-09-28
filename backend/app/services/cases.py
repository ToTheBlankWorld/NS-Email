"""Forensic case management orchestration (Stage 11).

``CaseService`` coordinates the case metadata store with read-only
access to the underlying forensic evidence (capture registry, analysis
results). The data flow is strictly one-way: the service READS
sessions, findings, posture snapshots, anomaly results, graph records,
and AI history, and WRITES only case metadata (references, notes, tags,
bookmarks, timeline events, report history).

It never mutates forensic truth: adding notes, tags, bookmarks,
changing priority, closing cases, or generating reports leaves every
analysis record byte-identical. Analyst notes are never forwarded to
the AI provider; only validated AI observations are quoted in reports
and exports.
"""

import hashlib
import io
import json
import zipfile
from typing import Any

from engine.ingestion.errors import CaptureStorageError

from app.api_models import AnalysisInfo, CaptureResponse, FindingResponse
from app.case_store import (
    BOOKMARK_ID_PATTERN,
    BOOKMARK_TARGET_TYPES,
    CASE_ID_PATTERN,
    NOTE_ID_PATTERN,
    NOTE_TARGET_TYPES,
    BookmarkRecord,
    CaptureAttachment,
    CaseRecord,
    CaseStore,
    NoteRecord,
    TimelineEntry,
    validate_bookmark_note,
    validate_bookmark_target,
    validate_description,
    validate_label,
    validate_note_content,
    validate_note_target,
    validate_priority,
    validate_status,
    validate_target_id,
    validate_title,
)
from app.registry import CaptureRegistry
from app.services.analysis import CaptureAnalysisService, CaptureNotFoundError
from app.services.case_report import (
    CASE_REPORT_APPLICATION_NAME,
    CaseReportInputs,
    build_case_report,
    case_report_to_json,
    evidence_digest,
)
from app.storage import CaptureStorage

CASE_EXPORT_SCHEMA_VERSION = "1.0"
CASE_BUNDLE_README_NAME = "README.txt"
CASE_BUNDLE_CASE_NAME = "case.json"
CASE_BUNDLE_MANIFEST_NAME = "evidence-manifest.json"
CASE_BUNDLE_REPORT_NAME = "reports/case-report.json"

# Import is a convenience, not a trust boundary: oversized bundles are
# rejected outright, and every imported value is re-validated.
MAX_IMPORT_NOTES = 500
MAX_IMPORT_BOOKMARKS = 500
MAX_IMPORT_CAPTURES = 100

# Reproducible bundles use a fixed archive timestamp so identical case
# state yields byte-identical zips.
_BUNDLE_ZIP_DATE = (2024, 1, 1, 0, 0, 0)


class CaseNotFoundError(Exception):
    """The requested case id is unknown (covers malformed ids too)."""

    def __init__(self, case_id: str) -> None:
        super().__init__("no case exists with this id")
        self.case_id = case_id


class CaseValidationError(ValueError):
    """Analyst-supplied case input failed validation (safe message)."""


def _require_case_id(case_id: str) -> str:
    cleaned = case_id.strip()
    if not CASE_ID_PATTERN.fullmatch(cleaned):
        raise CaseNotFoundError(case_id)
    return cleaned


def _record_to_dict(record: CaseRecord) -> dict[str, Any]:
    return {
        "case_id": record.case_id,
        "case_number": record.case_number,
        "title": record.title,
        "description": record.description,
        "status": record.status,
        "priority": record.priority,
        "created_at": record.created_at.isoformat() if record.created_at else None,
        "updated_at": record.updated_at.isoformat() if record.updated_at else None,
        "closed_at": record.closed_at.isoformat() if record.closed_at else None,
        "schema_version": record.schema_version,
    }


def _note_to_dict(note: NoteRecord) -> dict[str, Any]:
    return {
        "note_id": note.note_id,
        "case_id": note.case_id,
        "target_type": note.target_type,
        "target_id": note.target_id,
        "content": note.content,
        "created_at": note.created_at.isoformat() if note.created_at else None,
        "updated_at": note.updated_at.isoformat() if note.updated_at else None,
    }


def _bookmark_to_dict(bookmark: BookmarkRecord) -> dict[str, Any]:
    return {
        "bookmark_id": bookmark.bookmark_id,
        "case_id": bookmark.case_id,
        "target_type": bookmark.target_type,
        "target_id": bookmark.target_id,
        "label": bookmark.label,
        "note": bookmark.note,
        "created_at": bookmark.created_at.isoformat() if bookmark.created_at else None,
    }


def _timeline_to_dict(entry: TimelineEntry) -> dict[str, Any]:
    return {
        "entry_id": entry.entry_id,
        "case_id": entry.case_id,
        "event_type": entry.event_type,
        "detail": dict(entry.detail),
        "created_at": entry.created_at.isoformat() if entry.created_at else None,
    }


class CaseService:
    """Case workflow orchestration over read-only forensic evidence."""

    def __init__(
        self,
        case_store: CaseStore,
        registry: CaptureRegistry,
        analysis: CaptureAnalysisService,
        storage: CaptureStorage,
        app_version: str,
    ) -> None:
        self._cases = case_store
        self._registry = registry
        self._analysis = analysis
        self._storage = storage
        self._app_version = app_version
        self._ai_service: Any = None

    # -- cases -----------------------------------------------------------

    def create_case(self, title: str, description: str, priority: str) -> CaseRecord:
        try:
            record = self._cases.create_case(title, description or "", priority)
        except ValueError as error:
            raise CaseValidationError(str(error)) from error
        self._cases.append_timeline(record.case_id, "case_created", {"title": record.title})
        return record

    def list_cases(self, status: str | None = None) -> list[CaseRecord]:
        try:
            return self._cases.list_cases(status)
        except ValueError as error:
            raise CaseValidationError(str(error)) from error

    def get_case(self, case_id: str) -> CaseRecord:
        record = self._cases.get_case(_require_case_id(case_id))
        if record is None:
            raise CaseNotFoundError(case_id)
        return record

    def update_case(
        self,
        case_id: str,
        *,
        title: str | None = None,
        description: str | None = None,
        status: str | None = None,
        priority: str | None = None,
    ) -> CaseRecord:
        cleaned = _require_case_id(case_id)
        current = self._cases.get_case(cleaned)
        if current is None:
            raise CaseNotFoundError(case_id)
        try:
            updated = self._cases.update_case(
                cleaned, title=title, description=description, status=status, priority=priority
            )
        except ValueError as error:
            raise CaseValidationError(str(error)) from error
        if updated is None:  # pragma: no cover - existence checked above
            raise CaseNotFoundError(case_id)
        if status is not None and status != current.status:
            self._cases.append_timeline(
                cleaned,
                "status_changed",
                {"from": current.status, "to": updated.status},
            )
        return updated

    def delete_case(self, case_id: str) -> None:
        if not self._cases.delete_case(_require_case_id(case_id)):
            raise CaseNotFoundError(case_id)

    # -- capture references ----------------------------------------------

    def attach_capture(self, case_id: str, capture_id: str) -> CaptureAttachment:
        record = self.get_case(case_id)
        cleaned_capture = capture_id.strip()
        capture = self._registry.get(cleaned_capture)
        if capture is None:
            raise CaptureNotFoundError(cleaned_capture)
        already = self._cases.is_attached(record.case_id, capture.id)
        attachment = self._cases.attach_capture(record.case_id, capture.id)
        if not already:
            self._cases.append_timeline(
                record.case_id, "capture_attached", {"capture_id": capture.id}
            )
        return attachment

    def detach_capture(self, case_id: str, capture_id: str) -> None:
        record = self.get_case(case_id)
        if not self._cases.detach_capture(record.case_id, capture_id.strip()):
            raise CaseValidationError("capture is not attached to this case")

    def attached_capture_ids(self, case_id: str) -> list[CaptureAttachment]:
        record = self.get_case(case_id)
        return self._cases.list_attachments(record.case_id)

    # -- reference validation --------------------------------------------

    def _check_reference(self, case_id: str, target_type: str, target_id: str) -> None:
        """Reject references to nonexistent evidence for resolvable types.

        Finding, anomaly, session, capture, and case targets are verified
        against the stores. Certificate, TLS-handshake, graph-node, and
        timeline-event targets are lightweight references resolved at
        navigation time (documented in ADR-011).
        """
        if target_type == "case":
            if target_id != case_id:
                raise CaseValidationError("case notes must target their own case")
            return
        if target_type == "capture":
            if self._registry.get(target_id) is None:
                raise CaseValidationError("referenced capture does not exist")
            return
        if target_type == "session":
            if self._analysis.session(target_id) is None:
                raise CaseValidationError("referenced session does not exist")
            return
        if target_type == "finding":
            if self._analysis.finding(target_id) is None:
                raise CaseValidationError("referenced finding does not exist")
            return
        if target_type == "anomaly":
            if self._analysis.anomaly_result(target_id) is None:
                raise CaseValidationError("referenced anomaly does not exist")
            return

    # -- notes -----------------------------------------------------------

    def create_note(
        self, case_id: str, target_type: str, target_id: str, content: str
    ) -> NoteRecord:
        record = self.get_case(case_id)
        try:
            clean_type = validate_note_target(target_type)
            clean_target = validate_target_id(target_id)
        except ValueError as error:
            raise CaseValidationError(str(error)) from error
        self._check_reference(record.case_id, clean_type, clean_target)
        try:
            note = self._cases.add_note(record.case_id, clean_type, clean_target, content)
        except ValueError as error:
            raise CaseValidationError(str(error)) from error
        self._cases.append_timeline(
            record.case_id,
            "note_created",
            {"note_id": note.note_id, "target_type": clean_type, "target_id": clean_target},
        )
        return note

    def list_notes(self, case_id: str) -> list[NoteRecord]:
        return self._cases.list_notes(self.get_case(case_id).case_id)

    def update_note(self, case_id: str, note_id: str, content: str) -> NoteRecord:
        record = self.get_case(case_id)
        if not NOTE_ID_PATTERN.fullmatch(note_id.strip()):
            raise CaseValidationError("unknown note")
        try:
            updated = self._cases.update_note(record.case_id, note_id.strip(), content)
        except ValueError as error:
            raise CaseValidationError(str(error)) from error
        if updated is None:
            raise CaseValidationError("unknown note")
        self._cases.append_timeline(record.case_id, "note_updated", {"note_id": updated.note_id})
        return updated

    def delete_note(self, case_id: str, note_id: str) -> None:
        record = self.get_case(case_id)
        if not NOTE_ID_PATTERN.fullmatch(note_id.strip()):
            raise CaseValidationError("unknown note")
        if not self._cases.delete_note(record.case_id, note_id.strip()):
            raise CaseValidationError("unknown note")
        self._cases.append_timeline(record.case_id, "note_deleted", {"note_id": note_id.strip()})

    # -- tags ------------------------------------------------------------

    def add_tag(self, case_id: str, tag: str) -> str:
        record = self.get_case(case_id)
        try:
            normalized = self._cases.add_tag(record.case_id, tag)
        except ValueError as error:
            raise CaseValidationError(str(error)) from error
        self._cases.append_timeline(record.case_id, "tag_added", {"tag": normalized})
        return normalized

    def remove_tag(self, case_id: str, tag: str) -> None:
        record = self.get_case(case_id)
        try:
            removed = self._cases.remove_tag(record.case_id, tag)
        except ValueError as error:
            raise CaseValidationError(str(error)) from error
        if not removed:
            raise CaseValidationError("tag is not present on this case")
        self._cases.append_timeline(record.case_id, "tag_removed", {"tag": tag.strip().lower()})

    def list_tags(self, case_id: str) -> list[str]:
        return self._cases.list_tags(self.get_case(case_id).case_id)

    # -- bookmarks -------------------------------------------------------

    def create_bookmark(
        self,
        case_id: str,
        target_type: str,
        target_id: str,
        label: str = "",
        note: str = "",
    ) -> BookmarkRecord:
        record = self.get_case(case_id)
        try:
            clean_type = validate_bookmark_target(target_type)
            clean_target = validate_target_id(target_id)
        except ValueError as error:
            raise CaseValidationError(str(error)) from error
        self._check_reference(record.case_id, clean_type, clean_target)
        existing = [
            b
            for b in self._cases.list_bookmarks(record.case_id)
            if b.target_type == clean_type and b.target_id == clean_target
        ]
        try:
            bookmark = self._cases.add_bookmark(
                record.case_id, clean_type, clean_target, label or "", note or ""
            )
        except ValueError as error:
            raise CaseValidationError(str(error)) from error
        if not existing:
            event = {
                "finding": "finding_bookmarked",
                "anomaly": "anomaly_bookmarked",
            }.get(clean_type, "bookmark_added")
            self._cases.append_timeline(
                record.case_id,
                event,
                {
                    "bookmark_id": bookmark.bookmark_id,
                    "target_type": clean_type,
                    "target_id": clean_target,
                },
            )
        return bookmark

    def list_bookmarks(self, case_id: str) -> list[BookmarkRecord]:
        return self._cases.list_bookmarks(self.get_case(case_id).case_id)

    def delete_bookmark(self, case_id: str, bookmark_id: str) -> None:
        record = self.get_case(case_id)
        if not BOOKMARK_ID_PATTERN.fullmatch(bookmark_id.strip()):
            raise CaseValidationError("unknown bookmark")
        if not self._cases.delete_bookmark(record.case_id, bookmark_id.strip()):
            raise CaseValidationError("unknown bookmark")
        self._cases.append_timeline(
            record.case_id, "bookmark_removed", {"bookmark_id": bookmark_id.strip()}
        )

    # -- timeline ----------------------------------------------------------

    def list_timeline(self, case_id: str) -> list[TimelineEntry]:
        return self._cases.list_timeline(self.get_case(case_id).case_id)

    # -- evidence assembly (read-only) -------------------------------------

    def case_summary(self, case_id: str) -> dict[str, Any]:
        """Organizational summary: counts and quoted posture states.

        There is deliberately no case-level score: posture states and
        scores below are the authoritative per-capture Stage 5 values,
        quoted verbatim.
        """
        record = self.get_case(case_id)
        attachments = self._cases.list_attachments(record.case_id)
        session_total = 0
        finding_total = 0
        anomaly_total = 0
        capture_cards = []
        for attachment in attachments:
            capture = self._registry.get(attachment.capture_id)
            if capture is None:
                capture_cards.append({"capture_id": attachment.capture_id, "available": False})
                continue
            status = self._analysis.analysis_status(capture.id)
            findings = self._analysis.findings_for_capture(capture.id)
            anomalies = self._analysis.anomalies_for_capture(capture.id)
            posture = self._analysis.posture_snapshot(capture.id)
            session_total += status.session_count
            finding_total += len(findings)
            anomaly_total += len(anomalies)
            capture_cards.append(
                {
                    "capture_id": capture.id,
                    "available": True,
                    "filename": capture.filename,
                    "sha256": capture.sha256,
                    "analysis_status": status.status,
                    "session_count": status.session_count,
                    "findings_count": len(findings),
                    "anomalies_count": len(anomalies),
                    "posture_state": posture.get("posture_state") if posture else None,
                    "posture_score": posture.get("overall_score") if posture else None,
                }
            )
        notes = self._cases.list_notes(record.case_id)
        bookmarks = self._cases.list_bookmarks(record.case_id)
        tags = self._cases.list_tags(record.case_id)
        timeline = self._cases.list_timeline(record.case_id)
        reports = self._cases.list_reports(record.case_id)
        return {
            "case": _record_to_dict(record),
            "counts": {
                "captures": len(attachments),
                "sessions": session_total,
                "findings": finding_total,
                "anomalies": anomaly_total,
                "bookmarks": len(bookmarks),
                "notes": len(notes),
                "tags": len(tags),
                "timeline_events": len(timeline),
                "reports": len(reports),
            },
            "captures": sorted(capture_cards, key=lambda c: str(c["capture_id"])),
            "reports": reports,
        }

    def _report_inputs(self, case_id: str) -> CaseReportInputs:
        record = self.get_case(case_id)
        attachments = self._cases.list_attachments(record.case_id)
        captures: list[dict[str, Any]] = []
        findings: list[dict[str, Any]] = []
        anomalies: list[dict[str, Any]] = []
        anomaly_summaries: list[dict[str, Any]] = []
        postures: list[dict[str, Any]] = []
        graph_counts: list[dict[str, Any]] = []
        ai_observations: list[dict[str, Any]] = []
        provenance_captures: list[dict[str, Any]] = []
        for attachment in attachments:
            capture = self._registry.get(attachment.capture_id)
            if capture is None:
                continue
            status = self._analysis.analysis_status(capture.id)
            posture = self._analysis.posture_snapshot(capture.id)
            capture_findings = [
                FindingResponse.from_finding(f).model_dump(mode="json")
                for f in self._analysis.findings_for_capture(capture.id)
            ]
            capture_anomalies = self._analysis.anomalies_for_capture(capture.id)
            summary = self._analysis.anomaly_summary(capture.id)
            graph = self._analysis.graph(capture.id)
            nodes, edges = graph if graph else ([], [])
            node_types = sorted({str(n.get("node_type")) for n in nodes})
            edge_types = sorted({str(e.get("edge_type")) for e in edges})
            analyzed_at = status.analyzed_at.isoformat() if status.analyzed_at else None
            response = CaptureResponse.from_capture(
                capture, analysis=AnalysisInfo.from_record(status)
            ).model_dump(mode="json")
            captures.append(
                {
                    "capture_id": capture.id,
                    "filename": response["filename"],
                    "format": response["format"],
                    "size_bytes": response["size_bytes"],
                    "sha256": response["sha256"],
                    "status": response["status"],
                    "packet_count": response["packet_count"],
                    "ingested_at": response["ingested_at"],
                    "analysis_status": status.status,
                    "analyzed_at": analyzed_at,
                    "session_count": status.session_count,
                }
            )
            findings.extend(capture_findings)
            anomalies.extend(capture_anomalies)
            if summary is not None:
                anomaly_summaries.append({"capture_id": capture.id, "summary": summary})
            if posture is not None:
                postures.append(posture)
            graph_counts.append(
                {
                    "capture_id": capture.id,
                    "node_count": len(nodes),
                    "edge_count": len(edges),
                    "node_types": node_types,
                    "edge_types": edge_types,
                }
            )
            for entry in self._cases_store_ai_history(capture.id):
                ai_observations.append(entry)
            provenance_captures.append(
                {
                    "capture_id": capture.id,
                    "filename": capture.filename,
                    "sha256": capture.sha256,
                    "size_bytes": capture.size_bytes,
                    "ingested_at": capture.ingested_at.isoformat(),
                    "analyzed_at": analyzed_at,
                    "analysis_status": status.status,
                    "attached_at": attachment.attached_at.isoformat()
                    if attachment.attached_at
                    else None,
                }
            )
        ai_service = self._ai_service
        configured = bool(ai_service is not None and getattr(ai_service, "_provider", None))
        bookmarks = [_bookmark_to_dict(b) for b in self._cases.list_bookmarks(record.case_id)]
        notes = [_note_to_dict(n) for n in self._cases.list_notes(record.case_id)]
        tags = self._cases.list_tags(record.case_id)
        timeline = [_timeline_to_dict(e) for e in self._cases.list_timeline(record.case_id)]
        reports = self._cases.list_reports(record.case_id)
        provenance = {
            "label": (
                "Technical provenance metadata: what was processed, when, and by "
                "which application version. Not a legal chain-of-custody certification."
            ),
            "application_version": self._app_version,
            "captures": sorted(provenance_captures, key=lambda c: str(c["capture_id"])),
        }
        return CaseReportInputs(
            case=_record_to_dict(record),
            captures=sorted(captures, key=lambda c: str(c["capture_id"])),
            findings=findings,
            anomalies=anomalies,
            anomaly_summaries=anomaly_summaries,
            postures=postures,
            graph_counts=sorted(graph_counts, key=lambda c: str(c["capture_id"])),
            bookmarks=bookmarks,
            notes=notes,
            tags=tags,
            timeline=timeline,
            reports=reports,
            ai_observations=sorted(ai_observations, key=lambda o: str(o.get("generated_at") or "")),
            provenance=provenance,
            ai_configured=configured,
            ai_provider=str(getattr(getattr(ai_service, "_provider", None), "provider_name", "")),
            ai_model=str(getattr(getattr(ai_service, "_provider", None), "model_name", "")),
        )

    def _cases_store_ai_history(self, capture_id: str) -> list[dict[str, Any]]:
        """Validated AI observations only; analyst notes are never included."""
        store = getattr(self._analysis, "_store", None)
        if store is None or not hasattr(store, "list_ai_history"):
            return []
        history: list[dict[str, Any]] = store.list_ai_history(capture_id)
        return [dict(entry) for entry in history if entry.get("validation_status") == "validated"]

    def attach_ai_service(self, ai_service: Any) -> None:
        """Provide the AI service for configured-provider reporting only."""
        self._ai_service = ai_service

    # -- reports -----------------------------------------------------------

    def build_case_report(self, case_id: str) -> dict[str, Any]:
        """Build the deterministic case report document (no side effects)."""
        return build_case_report(self._report_inputs(self.get_case(case_id).case_id))

    def record_case_report(self, case_id: str, report_format: str) -> dict[str, str]:
        """Record report generation history; called AFTER building bytes."""
        record = self.get_case(case_id)
        digest = evidence_digest(self._report_inputs(record.case_id))
        meta = self._cases.record_report(record.case_id, report_format, digest)
        self._cases.append_timeline(
            record.case_id,
            "report_generated",
            {"report_id": meta["report_id"], "format": report_format},
        )
        return meta

    # -- export / bundle / import ------------------------------------------

    def build_export(self, case_id: str) -> dict[str, Any]:
        """Build the versioned case export document (no side effects)."""
        record = self.get_case(case_id)
        inputs = self._report_inputs(record.case_id)
        return {
            "schema_version": CASE_EXPORT_SCHEMA_VERSION,
            "application": {
                "name": CASE_REPORT_APPLICATION_NAME,
                "version": self._app_version,
            },
            "case": _record_to_dict(record),
            "captures": inputs.captures,
            "findings": sorted(
                inputs.findings,
                key=lambda f: (
                    str(f.get("capture_id") or ""),
                    str(f.get("rule_id") or ""),
                    str(f.get("id") or ""),
                ),
            ),
            "anomalies": sorted(
                inputs.anomalies,
                key=lambda a: (
                    str(a.get("capture_id") or ""),
                    str(a.get("session_id") or ""),
                ),
            ),
            "bookmarks": inputs.bookmarks,
            "notes": inputs.notes,
            "tags": list(inputs.tags),
            "timeline": inputs.timeline,
            "reports": inputs.reports,
            "provenance": inputs.provenance,
        }

    def record_export(self, case_id: str) -> None:
        """Record a case export event; called AFTER serializing bytes."""
        record = self.get_case(case_id)
        self._cases.append_timeline(record.case_id, "case_exported", {})

    def build_bundle(self, case_id: str, include_evidence: bool = False) -> bytes:
        """Build the reproducible case bundle (zip): case.json, README.txt,
        evidence-manifest.json, reports/case-report.json, and optionally
        the raw evidence bytes under evidence/ (explicit opt-in only)."""
        record = self.get_case(case_id)
        export = self.build_export(record.case_id)
        report = build_case_report(self._report_inputs(record.case_id))
        manifest_captures: list[dict[str, Any]] = [
            {
                "capture_id": c["capture_id"],
                "filename": c["filename"],
                "format": c.get("format"),
                "sha256": c["sha256"],
                "size_bytes": c["size_bytes"],
                "ingested_at": c.get("ingested_at"),
                "analyzed_at": c.get("analyzed_at"),
                "analysis_status": c.get("analysis_status"),
                "session_count": c.get("session_count"),
                "evidence_included": bool(include_evidence),
            }
            for c in export["captures"]
        ]
        manifest = {
            "schema_version": CASE_EXPORT_SCHEMA_VERSION,
            "case_id": record.case_id,
            "case_number": record.case_number,
            "captures": manifest_captures,
        }
        readme = _bundle_readme(record, export, include_evidence)
        buffer = io.BytesIO()

        def _write(path: str, data: bytes) -> None:
            info = zipfile.ZipInfo(path, date_time=_BUNDLE_ZIP_DATE)
            info.compress_type = zipfile.ZIP_DEFLATED
            buffer_zip.writestr(info, data)

        with zipfile.ZipFile(buffer, "w") as buffer_zip:
            _write(CASE_BUNDLE_CASE_NAME, case_report_to_json(export).encode("utf-8"))
            _write(CASE_BUNDLE_README_NAME, readme.encode("utf-8"))
            _write(
                CASE_BUNDLE_MANIFEST_NAME,
                json.dumps(manifest, indent=2, sort_keys=True).encode("utf-8"),
            )
            _write(CASE_BUNDLE_REPORT_NAME, case_report_to_json(report).encode("utf-8"))
            if include_evidence:
                for item in manifest_captures:
                    capture = self._registry.get(str(item["capture_id"]))
                    if capture is None:
                        continue
                    try:
                        evidence_path = self._storage.evidence_path(
                            capture.id, capture.format.value
                        )
                    except CaptureStorageError:
                        continue
                    if not evidence_path.is_file():
                        continue
                    info = zipfile.ZipInfo(
                        f"evidence/{capture.id}.{capture.format.value}",
                        date_time=_BUNDLE_ZIP_DATE,
                    )
                    info.compress_type = zipfile.ZIP_DEFLATED
                    buffer_zip.writestr(info, evidence_path.read_bytes())
        return buffer.getvalue()

    def import_case(self, document: Any) -> tuple[CaseRecord, dict[str, Any]]:
        """Import a previously exported case metadata bundle.

        Always creates a NEW case (nothing is overwritten). Captures are
        attached only when the same evidence is already registered locally
        with a matching SHA-256. Notes, tags, and bookmarks are
        re-validated; invalid entries are skipped with warnings. The
        imported timeline is not replayed — a single ``case_imported``
        event starts a fresh local trail. AI observations are never
        imported (interpretation is re-derived locally).
        """
        if not isinstance(document, dict):
            raise CaseValidationError("import document must be a JSON object")
        if document.get("schema_version") != CASE_EXPORT_SCHEMA_VERSION:
            raise CaseValidationError(
                f"unsupported import schema_version: {document.get('schema_version')!r}"
            )
        raw_case = document.get("case")
        if not isinstance(raw_case, dict):
            raise CaseValidationError("import document is missing its case section")
        try:
            title = validate_title(str(raw_case.get("title", "")))
            description = validate_description(str(raw_case.get("description", "")))
            priority = validate_priority(str(raw_case.get("priority", "MEDIUM")))
            status = str(raw_case.get("status", "OPEN"))
            validate_status(status)
        except ValueError as error:
            raise CaseValidationError(str(error)) from error

        raw_captures = document.get("captures", [])
        raw_notes = document.get("notes", [])
        raw_tags = document.get("tags", [])
        raw_bookmarks = document.get("bookmarks", [])
        if not isinstance(raw_captures, list) or len(raw_captures) > MAX_IMPORT_CAPTURES:
            raise CaseValidationError("import document has an invalid captures section")
        if not isinstance(raw_notes, list) or len(raw_notes) > MAX_IMPORT_NOTES:
            raise CaseValidationError("import document has an invalid notes section")
        if not isinstance(raw_tags, list):
            raise CaseValidationError("import document has an invalid tags section")
        if not isinstance(raw_bookmarks, list) or len(raw_bookmarks) > MAX_IMPORT_BOOKMARKS:
            raise CaseValidationError("import document has an invalid bookmarks section")

        record = self._cases.create_case(title, description, priority)
        if status != "OPEN":
            record = self._cases.update_case(record.case_id, status=status) or record
        warnings: list[str] = []
        attached = 0
        for entry in raw_captures:
            if not isinstance(entry, dict):
                warnings.append("skipped a malformed capture entry")
                continue
            capture_id = str(entry.get("capture_id", ""))
            expected_sha = str(entry.get("sha256", ""))
            capture = self._registry.get(capture_id)
            if capture is None or capture.sha256 != expected_sha:
                warnings.append(f"capture not available locally: {capture_id or '(missing id)'}")
                continue
            self._cases.attach_capture(record.case_id, capture.id)
            attached += 1
        imported_tags = 0
        for tag in raw_tags:
            if not isinstance(tag, str):
                warnings.append("skipped a malformed tag")
                continue
            try:
                self._cases.add_tag(record.case_id, tag)
                imported_tags += 1
            except (ValueError, CaptureStorageError) as error:
                warnings.append(f"skipped tag {tag!r}: {error}")
        imported_notes = 0
        for entry in raw_notes:
            if not isinstance(entry, dict):
                warnings.append("skipped a malformed note")
                continue
            try:
                target_type = validate_note_target(str(entry.get("target_type", "")))
                target_id = validate_target_id(str(entry.get("target_id", "")))
                content = validate_note_content(str(entry.get("content", "")))
            except ValueError as error:
                warnings.append(f"skipped note: {error}")
                continue
            if target_type == "case":
                target_id = record.case_id
            self._cases.add_note(record.case_id, target_type, target_id, content)
            imported_notes += 1
        imported_bookmarks = 0
        for entry in raw_bookmarks:
            if not isinstance(entry, dict):
                warnings.append("skipped a malformed bookmark")
                continue
            try:
                target_type = validate_bookmark_target(str(entry.get("target_type", "")))
                target_id = validate_target_id(str(entry.get("target_id", "")))
                label = validate_label(str(entry.get("label", "")))
                note = validate_bookmark_note(str(entry.get("note", "")))
            except ValueError as error:
                warnings.append(f"skipped bookmark: {error}")
                continue
            self._cases.add_bookmark(record.case_id, target_type, target_id, label, note)
            imported_bookmarks += 1
        self._cases.append_timeline(
            record.case_id,
            "case_imported",
            {
                "captures_attached": str(attached),
                "notes_imported": str(imported_notes),
                "tags_imported": str(imported_tags),
                "bookmarks_imported": str(imported_bookmarks),
            },
        )
        final = self._cases.get_case(record.case_id)
        if final is None:  # pragma: no cover - created above
            raise CaptureStorageError("imported case did not persist")
        summary = {
            "captures_attached": attached,
            "notes_imported": imported_notes,
            "tags_imported": imported_tags,
            "bookmarks_imported": imported_bookmarks,
            "warnings": warnings,
        }
        return final, summary


def _bundle_readme(record: CaseRecord, export: dict[str, Any], include_evidence: bool) -> str:
    captures = export.get("captures", [])
    lines = [
        "SecureMailScope forensic case bundle",
        "====================================",
        "",
        f"Case number : {record.case_number}",
        f"Title       : {record.title}",
        f"Status      : {record.status}",
        f"Priority    : {record.priority}",
        f"Captures    : {len(captures) if isinstance(captures, list) else 0}",
        "",
        "Contents",
        "--------",
        "case.json               Versioned case export (metadata, references, analyst",
        "                        work, provenance). No raw evidence payloads.",
        "evidence-manifest.json  Per-capture filename, SHA-256, size, and analysis",
        "                        metadata. Verify local evidence against these hashes.",
        "reports/case-report.json  Deterministic case report document.",
        "README.txt              This file.",
    ]
    if include_evidence:
        lines.append("evidence/               Raw capture bytes (explicitly requested export;")
        lines.append("                        handle as sensitive evidence; verify SHA-256 against")
        lines.append("                        the manifest before analysis).")
    else:
        lines.append("Raw capture bytes are NOT included. Re-attach the captures listed in")
        lines.append("evidence-manifest.json (matching SHA-256) to reproduce this case locally.")
    lines.extend(
        [
            "",
            "Analyst notes, tags, and bookmarks are investigation context, not",
            "forensic evidence. Technical provenance metadata is not a legal",
            "chain-of-custody certification.",
            "",
            "Verify: recompute SHA-256 over each local capture and compare with",
            "evidence-manifest.json before relying on this bundle.",
        ]
    )
    digest = hashlib.sha256(
        json.dumps(export, sort_keys=True, default=str).encode("utf-8")
    ).hexdigest()
    lines.extend(["", f"Export digest (sha256 of case.json): {digest}"])
    return "\n".join(lines) + "\n"


__all__ = [
    "BOOKMARK_TARGET_TYPES",
    "CASE_EXPORT_SCHEMA_VERSION",
    "CASE_ID_PATTERN",
    "NOTE_ID_PATTERN",
    "NOTE_TARGET_TYPES",
    "CaptureAttachment",
    "CaptureNotFoundError",
    "CaseNotFoundError",
    "CaseService",
    "CaseValidationError",
]
