"""System health endpoints."""

from typing import Literal

from fastapi import APIRouter
from pydantic import BaseModel

from app.config import load_settings

router = APIRouter(tags=["system"])


class HealthResponse(BaseModel):
    status: Literal["ok"]
    service: str


@router.get("/health", response_model=HealthResponse)
def read_health() -> HealthResponse:
    settings = load_settings()
    return HealthResponse(status="ok", service=settings.service_name)
