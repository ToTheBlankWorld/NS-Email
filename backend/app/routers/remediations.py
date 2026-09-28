"""Remediation workflow endpoints (Stage 13).

Analyst-controlled remediation plans over immutable findings, plus
evidence-based verification against later captures. Every endpoint
reads evidence and writes only workflow state; findings, sessions,
posture, anomalies, and graphs are never mutated.

Error shape follows the repository convention:
``{"error": {"code", "message"}}`` with ``case_not_found`` (404),
``remediation_not_found`` (404, including malformed ids),
``verification_not_found`` (404), and ``invalid_request`` (422) for
rejected workflow input (bad transitions, unanalyzed verification
captures, cross-case references).
"""

import logging
import time
from collections.abc import Callable
from typing import Any

from fastapi import APIRouter, Query, Request, Response
from pydantic import BaseModel, Field

from app.case_store import CASE_ID_PATTERN
from app.errors import (
    ERROR_CASE_NOT_FOUND,
    ERROR_INVALID_REQUEST,
    ERROR_REMEDIATION_NOT_FOUND,
    ERROR_VERIFICATION_NOT_FOUND,
    ApiError,
)
from app.remediation_store import REMEDIATION_ID_PATTERN, VERIFICATION_ID_PATTERN
from app.services.cases import CaseNotFoundError, CaseValidationError
from app.services.remediation_errors import RemediationNotFoundError, VerificationNotFoundError
from app.services.remediations import (
    RemediationService,
    _record_to_dict,
    _verification_to_dict,
)

router = APIRouter(prefix="/api/cases", tags=["remediations"])

logger = logging.getLogger("ns_email.remediations")


def _remediations(request: Request) -> RemediationService:
    service: RemediationService | None = getattr(request.app.state, "remediation_service", None)
    if service is None:  # pragma: no cover - wiring invariant
        raise RuntimeError("remediation service is not configured")
    return service


def _handle_remediation_errors[T](action: str, func: Callable[[], T]) -> T:
    """Map remediation-domain errors onto the structured API error shape."""
    try:
        return func()
    except CaseNotFoundError as error:
        raise ApiError(ERROR_CASE_NOT_FOUND, "no case exists with this id", 404) from error
    except RemediationNotFoundError as error:
        raise ApiError(
            ERROR_REMEDIATION_NOT_FOUND, "no remediation exists with this id", 404
        ) from error
    except VerificationNotFoundError as error:
        raise ApiError(
            ERROR_VERIFICATION_NOT_FOUND, "no verification exists with this id", 404
        ) from error
    except CaseValidationError as error:
        raise ApiError(ERROR_INVALID_REQUEST, str(error), 422) from error


def _require_case_path(case_id: str) -> str:
    if not CASE_ID_PATTERN.fullmatch(case_id):
        raise ApiError(ERROR_CASE_NOT_FOUND, "no case exists with this id", 404)
    return case_id


def _require_remediation_path(remediation_id: str) -> str:
    if not REMEDIATION_ID_PATTERN.fullmatch(remediation_id):
        raise ApiError(ERROR_REMEDIATION_NOT_FOUND, "no remediation exists with this id", 404)
    return remediation_id


def _require_verification_path(verification_id: str) -> str:
    if not VERIFICATION_ID_PATTERN.fullmatch(verification_id):
        raise ApiError(ERROR_VERIFICATION_NOT_FOUND, "no verification exists with this id", 404)
    return verification_id


# -- request models ----------------------------------------------------------


class RemediationCreateBody(BaseModel):
    target_type: str = Field(min_length=1, max_length=32)
    target_id: str = Field(min_length=1, max_length=256)
    title: str = Field(min_length=1, max_length=200)
    description: str = Field(default="", max_length=5000)
    recommended_action: str = Field(default="", max_length=2000)
    priority: str = Field(default="MEDIUM", min_length=1, max_length=16)
    owner: str = Field(default="", max_length=128)
    due_at: str | None = Field(default=None, max_length=32)
    rule_id: str | None = Field(default=None, max_length=128)


class RemediationFromFindingBody(BaseModel):
    finding_id: str = Field(min_length=1, max_length=128)
    title: str | None = Field(default=None, max_length=200)
    description: str = Field(default="", max_length=5000)
    priority: str | None = Field(default=None, min_length=1, max_length=16)
    owner: str = Field(default="", max_length=128)
    due_at: str | None = Field(default=None, max_length=32)


class RemediationUpdateBody(BaseModel):
    title: str | None = Field(default=None, min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=5000)
    recommended_action: str | None = Field(default=None, max_length=2000)
    priority: str | None = Field(default=None, min_length=1, max_length=16)
    owner: str | None = Field(default=None, max_length=128)
    due_at: str | None = Field(default=None, max_length=32)
    status: str | None = Field(default=None, min_length=1, max_length=16)


class VerificationRequestBody(BaseModel):
    mode: str = Field(min_length=1, max_length=16)
    verification_capture_id: str | None = Field(default=None, max_length=64)
    notes: str = Field(default="", max_length=10000)


class VerificationCompleteBody(BaseModel):
    notes: str = Field(min_length=1, max_length=10000)


# -- remediations -------------------------------------------------------------------


@router.post("/{case_id}/remediations", summary="Create a remediation plan")
def create_remediation(
    case_id: str, request: Request, body: RemediationCreateBody
) -> dict[str, Any]:
    _require_case_path(case_id)
    service = _remediations(request)
    record = _handle_remediation_errors(
        "create_remediation",
        lambda: service.create_remediation(
            case_id,
            body.target_type,
            body.target_id,
            body.title,
            body.description,
            body.recommended_action,
            body.priority.upper() if body.priority else "MEDIUM",
            body.owner,
            body.due_at,
            body.rule_id,
        ),
    )
    logger.info("remediation created: case_id=%s target=%s", case_id, body.target_type)

    return _record_to_dict(record)


@router.post("/{case_id}/remediations/from-finding", summary="Create a remediation from a finding")
def create_remediation_from_finding(
    case_id: str, request: Request, body: RemediationFromFindingBody
) -> dict[str, Any]:
    """Prefill a remediation from existing policy guidance (no LLM)."""
    _require_case_path(case_id)
    service = _remediations(request)
    record = _handle_remediation_errors(
        "create_remediation_from_finding",
        lambda: service.create_from_finding(
            case_id,
            body.finding_id,
            body.title,
            body.description,
            body.priority.upper() if body.priority else None,
            body.owner,
            body.due_at,
        ),
    )
    logger.info("remediation created from finding: case_id=%s", case_id)

    return _record_to_dict(record)


@router.get("/{case_id}/remediations", summary="List remediations")
def list_remediations(
    case_id: str,
    request: Request,
    status: str | None = None,
    priority: str | None = None,
    owner: str | None = None,
    verification_status: str | None = Query(default=None, alias="verification"),
    rule: str | None = None,
    target: str | None = None,
    search: str | None = None,
    sort: str = "updated",
    limit: int = 100,
    offset: int = 0,
) -> dict[str, Any]:
    _require_case_path(case_id)
    service = _remediations(request)
    total, items = _handle_remediation_errors(
        "list_remediations",
        lambda: service.list_remediations(
            case_id,
            status=status.upper() if status else None,
            priority=priority.upper() if priority else None,
            owner=owner,
            verification_status=verification_status.upper() if verification_status else None,
            rule=rule,
            target=target,
            search=search,
            sort=sort,
            limit=limit,
            offset=offset,
        ),
    )
    return {
        "case_id": case_id,
        "total": total,
        "limit": limit,
        "offset": offset,
        "remediations": items,
    }


@router.get("/{case_id}/remediations/{remediation_id}", summary="Get one remediation")
def get_remediation(case_id: str, remediation_id: str, request: Request) -> dict[str, Any]:
    _require_case_path(case_id)
    _require_remediation_path(remediation_id)
    service = _remediations(request)

    return _record_to_dict(
        _handle_remediation_errors(
            "get_remediation", lambda: service.get_remediation(case_id, remediation_id)
        )
    )


@router.patch("/{case_id}/remediations/{remediation_id}", summary="Update a remediation")
def update_remediation(
    case_id: str, remediation_id: str, request: Request, body: RemediationUpdateBody
) -> dict[str, Any]:
    _require_case_path(case_id)
    _require_remediation_path(remediation_id)
    service = _remediations(request)

    return _record_to_dict(
        _handle_remediation_errors(
            "update_remediation",
            lambda: service.update_remediation(
                case_id,
                remediation_id,
                title=body.title,
                description=body.description,
                recommended_action=body.recommended_action,
                priority=body.priority.upper() if body.priority else None,
                owner=body.owner,
                due_at=body.due_at,
                status=body.status.upper() if body.status else None,
            ),
        )
    )


@router.delete("/{case_id}/remediations/{remediation_id}", summary="Delete a remediation")
def delete_remediation(case_id: str, remediation_id: str, request: Request) -> Response:
    _require_case_path(case_id)
    _require_remediation_path(remediation_id)
    service = _remediations(request)
    _handle_remediation_errors(
        "delete_remediation", lambda: service.delete_remediation(case_id, remediation_id)
    )
    logger.info("remediation deleted: case_id=%s", case_id)
    return Response(status_code=204)


@router.get(
    "/{case_id}/remediations/{remediation_id}/timeline",
    summary="Remediation workflow timeline",
)
def get_remediation_timeline(case_id: str, remediation_id: str, request: Request) -> dict[str, Any]:
    _require_case_path(case_id)
    _require_remediation_path(remediation_id)
    service = _remediations(request)
    entries = _handle_remediation_errors(
        "remediation_timeline", lambda: service.remediation_timeline(case_id, remediation_id)
    )
    return {"case_id": case_id, "remediation_id": remediation_id, "timeline": entries}


# -- verification ---------------------------------------------------------------------


@router.post(
    "/{case_id}/remediations/{remediation_id}/verify",
    summary="Request or run verification",
)
def request_verification(
    case_id: str, remediation_id: str, request: Request, body: VerificationRequestBody
) -> dict[str, Any]:
    """Evidence comparison (mode=evidence + capture) or manual request/note."""
    started = time.monotonic()
    _require_case_path(case_id)
    _require_remediation_path(remediation_id)
    service = _remediations(request)

    verification = _handle_remediation_errors(
        "request_verification",
        lambda: service.request_verification(
            case_id,
            remediation_id,
            body.mode,
            body.verification_capture_id,
            body.notes,
        ),
    )
    logger.info(
        "verification recorded: case_id=%s result=%s duration_ms=%d",
        case_id,
        verification.result,
        int((time.monotonic() - started) * 1000),
    )
    return _verification_to_dict(verification)


@router.get(
    "/{case_id}/remediations/{remediation_id}/verification",
    summary="List verification records",
)
def list_verifications(case_id: str, remediation_id: str, request: Request) -> dict[str, Any]:
    _require_case_path(case_id)
    _require_remediation_path(remediation_id)
    service = _remediations(request)
    records = _handle_remediation_errors(
        "list_verifications", lambda: service.list_verifications(case_id, remediation_id)
    )
    return {"case_id": case_id, "remediation_id": remediation_id, "verifications": records}


@router.get(
    "/{case_id}/remediations/{remediation_id}/verifications/{verification_id}",
    summary="Get one verification record",
)
def get_verification(
    case_id: str, remediation_id: str, verification_id: str, request: Request
) -> dict[str, Any]:
    _require_case_path(case_id)
    _require_remediation_path(remediation_id)
    _require_verification_path(verification_id)
    service = _remediations(request)
    return _handle_remediation_errors(
        "get_verification",
        lambda: service.get_verification(case_id, remediation_id, verification_id),
    )


@router.patch(
    "/{case_id}/remediations/{remediation_id}/verifications/{verification_id}",
    summary="Complete a pending manual verification",
)
def complete_verification(
    case_id: str,
    remediation_id: str,
    verification_id: str,
    request: Request,
    body: VerificationCompleteBody,
) -> dict[str, Any]:
    _require_case_path(case_id)
    _require_remediation_path(remediation_id)
    _require_verification_path(verification_id)
    service = _remediations(request)

    return _verification_to_dict(
        _handle_remediation_errors(
            "complete_verification",
            lambda: service.complete_verification(
                case_id, remediation_id, verification_id, body.notes
            ),
        )
    )


# -- finding integration ------------------------------------------------------------------


@router.get(
    "/{case_id}/findings/{finding_id}/remediations",
    summary="Remediations targeting one finding in this case",
)
def list_finding_remediations(case_id: str, finding_id: str, request: Request) -> dict[str, Any]:
    _require_case_path(case_id)
    service = _remediations(request)
    records = _handle_remediation_errors(
        "finding_remediations",
        lambda: service.list_for_finding(case_id, finding_id.strip()),
    )
    return {"case_id": case_id, "finding_id": finding_id.strip(), "remediations": records}
