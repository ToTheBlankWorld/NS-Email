"""AI analyst endpoints (Stage 8)."""

from typing import Any

from fastapi import APIRouter, Request
from pydantic import BaseModel, Field

from app.errors import ERROR_POSTURE_NOT_AVAILABLE, ApiError

router = APIRouter(prefix="/api/ai", tags=["ai"])


def _ai_service(request: Request) -> Any:
    service = getattr(request.app.state, "ai_service", None)
    if service is None:
        raise ApiError(ERROR_POSTURE_NOT_AVAILABLE, "AI service is not configured", 503)
    return service


class AIQueryInput(BaseModel):
    question: str = Field(min_length=1, max_length=2000)
    session_id: str = Field(min_length=1)


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
    if result.get("status") == "completed":
        store = getattr(request.app.state, "session_store", None)
        if store is not None:
            store.save_ai_response(str(result.get("capture_id", "")), result)
    return result


@router.get("/history/{capture_id}", summary="AI query history for one capture")
def get_ai_history(capture_id: str, request: Request) -> list[dict[str, Any]]:
    store = getattr(request.app.state, "session_store", None)
    if store is None:
        raise ApiError(ERROR_POSTURE_NOT_AVAILABLE, "AI history is not available", 503)
    history: list[dict[str, Any]] = store.list_ai_history(capture_id)
    return history
