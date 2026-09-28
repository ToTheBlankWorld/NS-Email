"""System health and readiness endpoints."""

import time
from typing import Literal

from fastapi import APIRouter, Request
from pydantic import BaseModel

from app.config import load_settings

router = APIRouter(tags=["system"])


class HealthResponse(BaseModel):
    status: Literal["ok"]
    service: str


class ReadinessChecks(BaseModel):
    database: bool
    storage: bool


class ReadyResponse(BaseModel):
    ready: bool
    checks: ReadinessChecks
    duration_ms: int


@router.get("/health", response_model=HealthResponse)
def read_health() -> HealthResponse:
    settings = load_settings()
    return HealthResponse(status="ok", service=settings.service_name)


@router.get("/ready", response_model=ReadyResponse)
def read_ready(request: Request) -> ReadyResponse:
    """Readiness: verify the local dependencies the app requires.

    External AI availability is deliberately NOT a readiness requirement -
    SecureMailScope must remain usable without an external LLM.
    """
    started = time.monotonic()

    database_ok = False
    store = getattr(request.app.state, "session_store", None)
    if store is not None and hasattr(store, "ping"):
        database_ok = bool(store.ping())

    storage_ok = False
    storage = getattr(request.app.state, "capture_storage", None)
    if storage is not None:
        storage_ok = storage.root.is_dir()

    duration_ms = int((time.monotonic() - started) * 1000)
    ready = database_ok and storage_ok
    return ReadyResponse(
        ready=ready,
        checks=ReadinessChecks(database=database_ok, storage=storage_ok),
        duration_ms=duration_ms,
    )
