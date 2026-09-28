"""Longitudinal drift endpoints (Stage 14).

Observation snapshots, explicit baselines, pairwise comparisons, and
deterministic drift records over a case's attached captures. All
computation is read-only and on-demand; drift is never persisted and
never mutates evidence.

Error shape follows the repository convention:
``{"error": {"code", "message"}}`` with ``case_not_found`` (404),
``drift_not_found`` (404, including malformed ids),
``baseline_not_found`` (404 when no baseline is selected), and
``invalid_request`` (422) for rejected input.
"""

import logging
import time
from collections.abc import Callable
from typing import Any

from fastapi import APIRouter, Query, Request, Response
from pydantic import BaseModel, Field

from app.case_store import CASE_ID_PATTERN
from app.errors import (
    ERROR_BASELINE_NOT_FOUND,
    ERROR_CAPTURE_NOT_FOUND,
    ERROR_CASE_NOT_FOUND,
    ERROR_DRIFT_NOT_FOUND,
    ERROR_INVALID_REQUEST,
    ERROR_REMEDIATION_NOT_FOUND,
    ApiError,
)
from app.remediation_store import REMEDIATION_ID_PATTERN
from app.services.analysis import CaptureNotFoundError
from app.services.cases import CaseNotFoundError, CaseValidationError
from app.services.drift import (
    DRIFT_ID_PATTERN,
    BaselineNotFoundError,
    DriftNotFoundError,
    DriftService,
)
from app.services.remediation_errors import RemediationNotFoundError

router = APIRouter(prefix="/api/cases", tags=["drift"])

logger = logging.getLogger("ns_email.drift")


def _drift(request: Request) -> DriftService:
    service: DriftService | None = getattr(request.app.state, "drift_service", None)
    if service is None:  # pragma: no cover - wiring invariant
        raise RuntimeError("drift service is not configured")
    return service


def _handle_drift_errors[T](action: str, func: Callable[[], T]) -> T:
    """Map drift-domain errors onto the structured API error shape."""
    try:
        return func()
    except CaseNotFoundError as error:
        raise ApiError(ERROR_CASE_NOT_FOUND, "no case exists with this id", 404) from error
    except CaptureNotFoundError as error:
        raise ApiError(ERROR_CAPTURE_NOT_FOUND, str(error), 404) from error
    except DriftNotFoundError as error:
        raise ApiError(ERROR_DRIFT_NOT_FOUND, "no drift record exists with this id", 404) from error
    except BaselineNotFoundError as error:
        raise ApiError(
            ERROR_BASELINE_NOT_FOUND, "no baseline observation has been selected", 404
        ) from error
    except RemediationNotFoundError as error:
        raise ApiError(
            ERROR_REMEDIATION_NOT_FOUND, "no remediation exists with this id", 404
        ) from error
    except CaseValidationError as error:
        raise ApiError(ERROR_INVALID_REQUEST, str(error), 422) from error


def _require_case_path(case_id: str) -> str:
    if not CASE_ID_PATTERN.fullmatch(case_id):
        raise ApiError(ERROR_CASE_NOT_FOUND, "no case exists with this id", 404)
    return case_id


def _require_drift_path(drift_id: str) -> str:
    if not DRIFT_ID_PATTERN.fullmatch(drift_id):
        raise ApiError(ERROR_DRIFT_NOT_FOUND, "no drift record exists with this id", 404)
    return drift_id


class BaselineBody(BaseModel):
    capture_id: str = Field(min_length=1, max_length=64)


class ComparisonBody(BaseModel):
    baseline_capture_id: str | None = Field(default=None, max_length=64)
    comparison_capture_id: str = Field(min_length=1, max_length=64)


@router.get("/{case_id}/observations", summary="List longitudinal observations")
def list_observations(case_id: str, request: Request) -> dict[str, Any]:
    """Observation snapshots in canonical attachment order."""
    _require_case_path(case_id)
    service = _drift(request)
    observations = _handle_drift_errors(
        "list_observations", lambda: service.list_observations(case_id)
    )
    return {"case_id": case_id, "observations": observations}


@router.post("/{case_id}/observations/baseline", summary="Select the baseline observation")
def set_baseline(case_id: str, request: Request, body: BaselineBody) -> dict[str, Any]:
    """Record the analyst-selected baseline capture (workflow metadata)."""
    _require_case_path(case_id)
    service = _drift(request)
    return _handle_drift_errors(
        "set_baseline", lambda: service.set_baseline(case_id, body.capture_id)
    )


@router.get("/{case_id}/observations/baseline", summary="Read the baseline selection")
def get_baseline(case_id: str, request: Request) -> dict[str, Any]:
    _require_case_path(case_id)
    service = _drift(request)
    return _handle_drift_errors("get_baseline", lambda: service.get_baseline(case_id))


@router.delete("/{case_id}/observations/baseline", summary="Clear the baseline selection")
def clear_baseline(case_id: str, request: Request) -> Response:
    _require_case_path(case_id)
    service = _drift(request)
    cleared = _handle_drift_errors("clear_baseline", lambda: service.clear_baseline(case_id))
    if not cleared:
        raise ApiError(ERROR_BASELINE_NOT_FOUND, "no baseline observation has been selected", 404)
    return Response(status_code=204)


@router.get("/{case_id}/drift", summary="List longitudinal drift records")
def list_drift(
    case_id: str,
    request: Request,
    type_filter: str | None = Query(default=None, alias="type"),
    comparison_capture_id: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> dict[str, Any]:
    """Filtered, paginated drift records across all case comparisons."""
    started = time.monotonic()
    _require_case_path(case_id)
    service = _drift(request)
    total, items = _handle_drift_errors(
        "list_drift",
        lambda: service.list_drift(
            case_id,
            type_filter=type_filter,
            comparison_capture_id=comparison_capture_id,
            limit=limit,
            offset=offset,
        ),
    )
    logger.info(
        "drift listed: case_id=%s total=%d duration_ms=%d",
        case_id,
        total,
        int((time.monotonic() - started) * 1000),
    )
    return {
        "case_id": case_id,
        "total": total,
        "limit": limit,
        "offset": offset,
        "drift": items,
    }


@router.get("/{case_id}/drift/summary", summary="Drift counts for one case")
def get_drift_summary(case_id: str, request: Request) -> dict[str, Any]:
    """Counts per drift dimension — never a score."""
    _require_case_path(case_id)
    service = _drift(request)
    return _handle_drift_errors("drift_summary", lambda: service.drift_summary(case_id))


@router.get("/{case_id}/drift/{drift_id}", summary="Get one drift record")
def get_drift(case_id: str, drift_id: str, request: Request) -> dict[str, Any]:
    _require_case_path(case_id)
    _require_drift_path(drift_id)
    service = _drift(request)
    return _handle_drift_errors("get_drift", lambda: service.get_drift(case_id, drift_id))


@router.get("/{case_id}/comparisons", summary="List pairwise observation comparisons")
def list_comparisons(case_id: str, request: Request) -> dict[str, Any]:
    """Consecutive-pair comparisons along the canonical observation order."""
    _require_case_path(case_id)
    service = _drift(request)
    comparisons = _handle_drift_errors(
        "list_comparisons", lambda: service.list_comparisons(case_id)
    )
    return {"case_id": case_id, "comparisons": comparisons}


@router.post("/{case_id}/comparisons", summary="Compare an explicit capture pair")
def compare_pair(case_id: str, request: Request, body: ComparisonBody) -> dict[str, Any]:
    """Compare two attached, analyzed captures with lifecycle context."""
    started = time.monotonic()
    _require_case_path(case_id)
    service = _drift(request)
    comparison, records = _handle_drift_errors(
        "compare_pair",
        lambda: service.compare_pair(
            case_id,
            body.baseline_capture_id or "",
            body.comparison_capture_id,
        ),
    )
    logger.info(
        "comparison computed: case_id=%s drift=%d duration_ms=%d",
        case_id,
        len(records),
        int((time.monotonic() - started) * 1000),
    )
    comparison["drift"] = records
    return comparison


@router.get(
    "/{case_id}/remediations/{remediation_id}/drift",
    summary="Regression view for one remediation",
)
def get_remediation_drift(case_id: str, remediation_id: str, request: Request) -> dict[str, Any]:
    """Baseline, verification captures, later observations, and regression status."""
    _require_case_path(case_id)
    if not REMEDIATION_ID_PATTERN.fullmatch(remediation_id):
        raise ApiError(ERROR_REMEDIATION_NOT_FOUND, "no remediation exists with this id", 404)
    service = _drift(request)
    return _handle_drift_errors(
        "remediation_drift", lambda: service.remediation_drift(case_id, remediation_id)
    )
