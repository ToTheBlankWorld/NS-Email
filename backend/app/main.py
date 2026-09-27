"""FastAPI application factory for the NS-Email backend."""

import logging
import shutil
from pathlib import Path

from engine.ingestion.inspector import CaptureInspector, TsharkCaptureInspector
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import Settings, load_settings
from app.errors import install_error_handlers
from app.registry import SQLiteCaptureRegistry
from app.routers import captures, health
from app.services.ingestion import CaptureIngestionService
from app.storage import CaptureStorage

logger = logging.getLogger("ns_email.app")


def _resolve_inspector(settings: Settings) -> CaptureInspector | None:
    """Locate tshark; absence degrades to registered-without-metadata mode."""
    candidate = settings.tshark_path or shutil.which("tshark")
    if not candidate:
        logger.info("tshark not found; captures will register without packet metadata")
        return None
    if not Path(candidate).is_file():
        logger.warning(
            "configured tshark path does not exist (%s); packet inspection disabled",
            candidate,
        )
        return None
    return TsharkCaptureInspector(candidate, timeout_seconds=settings.inspector_timeout_seconds)


def _configure_services(app: FastAPI, settings: Settings) -> None:
    storage = CaptureStorage(settings.capture_storage_dir)
    registry = SQLiteCaptureRegistry(storage.registry_path())
    app.state.capture_storage = storage
    app.state.capture_registry = registry
    app.state.ingestion_service = CaptureIngestionService(
        storage=storage,
        registry=registry,
        inspector=_resolve_inspector(settings),
        max_capture_bytes=settings.max_capture_bytes,
    )


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or load_settings()
    logging.basicConfig(level=logging.INFO)
    app = FastAPI(
        title="NS-Email",
        description=(
            "AI-assisted cryptographic security posture assessment for secure email communications."
        ),
        version=settings.app_version,
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(settings.cors_origins),
        allow_methods=["GET", "POST"],
        allow_headers=["*"],
    )
    install_error_handlers(app)
    app.include_router(health.router)
    app.include_router(captures.router)
    _configure_services(app, settings)
    return app


app = create_app()
