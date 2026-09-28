"""AI analyst endpoints (Stage 8, extended Stage 12)."""

from typing import Any

from fastapi import APIRouter, Request
from pydantic import BaseModel, Field

from app.case_store import CASE_ID_PATTERN
from app.errors import (
    ERROR_CASE_NOT_FOUND,
    ERROR_CORRELATION_NOT_FOUND,
    ERROR_POSTURE_NOT_AVAILABLE,
    ApiError,
)
from app.services.cases import CaseNotFoundError
from app.services.correlations import CORRELATION_ID_PATTERN, CorrelationNotFoundError

router = APIRouter(prefix="/api/ai", tags=["ai"])


def _ai_service(request: Request) -> Any:
    service = getattr(request.app.state, "ai_service", None)
    if service is None:
        raise ApiError(ERROR_POSTURE_NOT_AVAILABLE, "AI service is not configured", 503)
    return service


class AIQueryInput(BaseModel):
    question: str = Field(min_length=1, max_length=2000)
    session_id: str = Field(min_length=1)


class AICorrelationQueryInput(BaseModel):
    question: str = Field(min_length=1, max_length=2000)
    case_id: str = Field(min_length=1, max_length=64)
    correlation_id: str = Field(min_length=1, max_length=64)


class AIStatusResponse(BaseModel):
    configured: bool
    provider: str
    model: str
    local: bool


@router.get("/status", response_model=AIStatusResponse)
def get_ai_status(request: Request) -> AIStatusResponse:
    service = _ai_service(request)
    provider = service._provider
    if provider is None:
        return AIStatusResponse(configured=False, provider="", model="", local=True)
    return AIStatusResponse(
        configured=True,
        provider=provider.provider_name,
        model=provider.model_name,
        local=provider.is_local,
    )


@router.post("/query", summary="Ask the evidence-grounded AI analyst")
def query_ai(request: Request, body: AIQueryInput) -> dict[str, Any]:
    service = _ai_service(request)
    result: dict[str, Any] = service.query_session(body.session_id, body.question)
    if result.get("status") == "completed" and result.get("capture_id"):
        store = getattr(request.app.state, "session_store", None)
        if store is not None:
            store.save_ai_response(str(result.get("capture_id", "")), result)
    return result


@router.post("/query-correlation", summary="Ask about one case correlation")
def query_correlation(request: Request, body: AICorrelationQueryInput) -> dict[str, Any]:
    """Answer an explicit analyst question about one case correlation.

    The AI receives a minimized, bounded correlation context only — no
    secrets, no raw evidence, no analyst notes. Responses are ephemeral:
    never persisted, never quoted in reports. The AI cannot create
    correlations or change relationships.
    """
    if not CASE_ID_PATTERN.fullmatch(body.case_id.strip()):
        raise ApiError(ERROR_CASE_NOT_FOUND, "no case exists with this id", 404)
    if not CORRELATION_ID_PATTERN.fullmatch(body.correlation_id.strip()):
        raise ApiError(ERROR_CORRELATION_NOT_FOUND, "no correlation exists with this id", 404)
    correlation_service = getattr(request.app.state, "correlation_service", None)
    if correlation_service is None:  # pragma: no cover - wiring invariant
        raise ApiError(ERROR_POSTURE_NOT_AVAILABLE, "correlation service is not configured", 503)
    try:
        correlation = correlation_service.get_correlation(
            body.case_id.strip(), body.correlation_id.strip()
        )
    except CaseNotFoundError as error:
        raise ApiError(ERROR_CASE_NOT_FOUND, "no case exists with this id", 404) from error
    except CorrelationNotFoundError as error:
        raise ApiError(
            ERROR_CORRELATION_NOT_FOUND, "no correlation exists with this id", 404
        ) from error
    service = _ai_service(request)
    result: dict[str, Any] = service.query_correlation(correlation, body.question)
    # Ephemeral by design: correlation answers are never stored in
    # capture AI history and never surface in reports or exports.
    return result


@router.get("/history/{capture_id}", summary="AI query history for one capture")
def get_ai_history(capture_id: str, request: Request) -> list[dict[str, Any]]:
    store = getattr(request.app.state, "session_store", None)
    if store is None:
        raise ApiError(ERROR_POSTURE_NOT_AVAILABLE, "AI history is not available", 503)
    history: list[dict[str, Any]] = store.list_ai_history(capture_id)
    return history
