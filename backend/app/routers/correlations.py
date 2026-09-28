"""Case correlation endpoints (Stage 12).

Multi-capture investigation intelligence over the captures attached to
a case: deterministic shared-evidence relationships, a counts-only
summary, per-correlation context, session related-observations, and a
derived investigation graph. All computation is read-only and
on-demand; correlations are never persisted and never mutate evidence.

Error shape follows the repository convention:
``{"error": {"code", "message"}}`` with ``case_not_found`` (404),
``correlation_not_found`` (404, including malformed ids), and
``invalid_request`` (422) for rejected filters.
"""

import logging
import re
import time
from collections.abc import Callable
from typing import Any

from fastapi import APIRouter, Query, Request

from app.case_store import CASE_ID_PATTERN
from app.errors import (
    ERROR_CASE_NOT_FOUND,
    ERROR_CORRELATION_NOT_FOUND,
    ERROR_INVALID_REQUEST,
    ERROR_SESSION_NOT_FOUND,
    ApiError,
)
from app.services.analysis import CaptureNotFoundError
from app.services.cases import CaseNotFoundError, CaseValidationError
from app.services.correlations import (
    CORRELATION_ID_PATTERN,
    CorrelationNotFoundError,
    CorrelationService,
)

router = APIRouter(prefix="/api/cases", tags=["correlations"])

logger = logging.getLogger("ns_email.correlations")

_SESSION_ID_PATTERN = re.compile(r"^session_[0-9a-f]{16}$")


def _correlations(request: Request) -> CorrelationService:
    service: CorrelationService | None = getattr(request.app.state, "correlation_service", None)
    if service is None:  # pragma: no cover - wiring invariant
        raise RuntimeError("correlation service is not configured")
    return service


def _handle_correlation_errors[T](action: str, func: Callable[[], T]) -> T:
    """Map correlation-domain errors onto the structured API error shape."""
    try:
        return func()
    except CaseNotFoundError as error:
        raise ApiError(ERROR_CASE_NOT_FOUND, "no case exists with this id", 404) from error
    except CorrelationNotFoundError as error:
        raise ApiError(
            ERROR_CORRELATION_NOT_FOUND, "no correlation exists with this id", 404
        ) from error
    except CaseValidationError as error:
        raise ApiError(ERROR_INVALID_REQUEST, str(error), 422) from error
    except CaptureNotFoundError as error:
        raise ApiError(ERROR_CORRELATION_NOT_FOUND, str(error), 404) from error


def _require_case_path(case_id: str) -> str:
    if not CASE_ID_PATTERN.fullmatch(case_id):
        raise ApiError(ERROR_CASE_NOT_FOUND, "no case exists with this id", 404)
    return case_id


def _require_correlation_path(correlation_id: str) -> str:
    if not CORRELATION_ID_PATTERN.fullmatch(correlation_id):
        raise ApiError(ERROR_CORRELATION_NOT_FOUND, "no correlation exists with this id", 404)
    return correlation_id


def _require_session_path(session_id: str) -> str:
    if not _SESSION_ID_PATTERN.fullmatch(session_id):
        raise ApiError(ERROR_SESSION_NOT_FOUND, "no session exists with this id", 404)
    return session_id


@router.get("/{case_id}/correlations", summary="List case correlations")
def list_correlations(
    case_id: str,
    request: Request,
    type_filter: str | None = Query(default=None, alias="type"),
    capture_id: str | None = None,
    protocol: str | None = None,
    endpoint: str | None = None,
    certificate: str | None = None,
    finding: str | None = None,
    search: str | None = None,
    sort: str = "occurrences",
    limit: int = 100,
    offset: int = 0,
) -> dict[str, Any]:
    """Filtered, sorted, paginated correlations for one case."""
    started = time.monotonic()
    _require_case_path(case_id)
    service = _correlations(request)
    total, items = _handle_correlation_errors(
        "list_correlations",
        lambda: service.list_correlations(
            case_id,
            type_filter=type_filter,
            capture_id=capture_id,
            protocol=protocol,
            endpoint=endpoint,
            certificate=certificate,
            finding=finding,
            search=search,
            sort=sort,
            limit=limit,
            offset=offset,
        ),
    )
    logger.info(
        "correlations listed: case_id=%s total=%d duration_ms=%d",
        case_id,
        total,
        int((time.monotonic() - started) * 1000),
    )
    return {
        "case_id": case_id,
        "total": total,
        "limit": limit,
        "offset": offset,
        "correlations": items,
    }


@router.get("/{case_id}/correlations/summary", summary="Correlation counts for one case")
def get_correlation_summary(case_id: str, request: Request) -> dict[str, Any]:
    """Counts per correlation type — never a score."""
    _require_case_path(case_id)
    service = _correlations(request)
    return _handle_correlation_errors(
        "correlation_summary", lambda: service.correlation_summary(case_id)
    )


@router.get(
    "/{case_id}/correlations/{correlation_id}/context",
    summary="Investigation context for one correlation",
)
def get_correlation_context(case_id: str, correlation_id: str, request: Request) -> dict[str, Any]:
    _require_case_path(case_id)
    _require_correlation_path(correlation_id)
    service = _correlations(request)
    return _handle_correlation_errors(
        "correlation_context", lambda: service.correlation_context(case_id, correlation_id)
    )


@router.get("/{case_id}/correlations/{correlation_id}", summary="Get one correlation")
def get_correlation(case_id: str, correlation_id: str, request: Request) -> dict[str, Any]:
    _require_case_path(case_id)
    _require_correlation_path(correlation_id)
    service = _correlations(request)
    return _handle_correlation_errors(
        "get_correlation", lambda: service.get_correlation(case_id, correlation_id)
    )


@router.get(
    "/{case_id}/sessions/{session_id}/related",
    summary="Related observations for one session within the case",
)
def get_session_related(case_id: str, session_id: str, request: Request) -> dict[str, Any]:
    """Sessions sharing evidence with this session (additive; session intact)."""
    _require_case_path(case_id)
    _require_session_path(session_id)
    service = _correlations(request)
    related = _handle_correlation_errors(
        "session_related", lambda: service.related_for_session(case_id, session_id)
    )
    if related is None:
        raise ApiError(ERROR_SESSION_NOT_FOUND, "no session exists with this id", 404)
    return related


@router.get("/{case_id}/graph", summary="Derived case investigation graph")
def get_investigation_graph(case_id: str, request: Request) -> dict[str, Any]:
    """Correlation/investigation view: forensic vs correlation layers.

    Separate from the Stage 7 per-capture forensic graphs, which are
    unchanged. Forensic nodes carry ``layer: "forensic"``; correlation
    groupings carry ``layer: "correlation"``.
    """
    _require_case_path(case_id)
    service = _correlations(request)
    graph = _handle_correlation_errors(
        "investigation_graph", lambda: service.investigation_graph(case_id)
    )
    logger.info(
        "investigation graph built: case_id=%s nodes=%d edges=%d",
        case_id,
        graph["node_count"],
        graph["edge_count"],
    )
    return graph
