"""FastAPI application factory for the NS-Email backend."""

import logging
import shutil
from pathlib import Path

from engine.ai.provider import LLMProvider, MockLLMProvider, OpenAICompatibleProvider
from engine.ai.service import AIAnalystService
from engine.detection import load_builtin_policy, load_policy_from_file
from engine.detection.policy import Policy
from engine.ingestion.inspector import CaptureInspector, TsharkCaptureInspector
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.case_store import CaseStore
from app.config import Settings, load_settings, validate_settings
from app.errors import install_error_handlers
from app.registry import SQLiteCaptureRegistry
from app.routers import (
    ai,
    anomalies,
    captures,
    cases,
    findings,
    graph,
    health,
    posture,
    reports,
    sessions,
)
from app.services.analysis import CaptureAnalysisService
from app.services.cases import CaseService
from app.services.ingestion import CaptureIngestionService
from app.storage import CaptureStorage
from app.store import SQLiteSessionStore

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


def _load_policy(settings: Settings) -> "Policy":
    if settings.policy_file:
        policy = load_policy_from_file(Path(settings.policy_file))
        logger.info("loaded custom policy %s v%s", policy.id, policy.version)
        return policy
    return load_builtin_policy()


def _resolve_ai_provider(settings: Settings) -> LLMProvider | None:
    if settings.ai_provider == "mock":
        return MockLLMProvider()
    if settings.ai_provider in ("openai", "ollama") and settings.ai_base_url:
        return OpenAICompatibleProvider(
            settings.ai_base_url, settings.ai_model, settings.ai_api_key
        )
    return None


def _make_ai_service(
    provider: LLMProvider | None, analysis_service: CaptureAnalysisService
) -> AIAnalystService:
    return AIAnalystService(provider=provider, analysis_service=analysis_service)


def _configure_services(app: FastAPI, settings: Settings) -> None:
    storage = CaptureStorage(settings.capture_storage_dir)
    registry = SQLiteCaptureRegistry(storage.registry_path())
    store = SQLiteSessionStore(storage.registry_path())
    case_store = CaseStore(storage.registry_path())
    policy = _load_policy(settings)
    app.state.capture_storage = storage
    app.state.capture_registry = registry
    app.state.session_store = store
    app.state.case_store = case_store
    app.state.policy = policy
    app.state.ingestion_service = CaptureIngestionService(
        storage=storage,
        registry=registry,
        inspector=_resolve_inspector(settings),
        max_capture_bytes=settings.max_capture_bytes,
    )
    analysis_service = CaptureAnalysisService(
        storage=storage,
        registry=registry,
        store=store,
        policy=policy,
        max_graph_nodes=settings.max_graph_nodes,
    )
    app.state.analysis_service = analysis_service
    ai_provider = _resolve_ai_provider(settings)
    app.state.ai_service = _make_ai_service(ai_provider, analysis_service)
    case_service = CaseService(
        case_store=case_store,
        registry=registry,
        analysis=analysis_service,
        storage=storage,
        app_version=settings.app_version,
    )
    case_service.attach_ai_service(app.state.ai_service)
    app.state.case_service = case_service
    app.state.settings = settings


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or load_settings()
    problems = validate_settings(settings)
    if problems:
        # Fail fast with actionable messages; secrets are never included.
        raise RuntimeError("invalid configuration:\n- " + "\n- ".join(problems))
    logging.basicConfig(level=logging.INFO)
    logger.info(
        "configuration validated: provider=%s max_capture_bytes=%d max_graph_nodes=%d",
        settings.ai_provider or "(ai disabled)",
        settings.max_capture_bytes,
        settings.max_graph_nodes,
    )
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
        allow_methods=["GET", "POST", "PATCH", "DELETE"],
        allow_headers=["*"],
    )
    install_error_handlers(app)
    app.include_router(health.router)
    app.include_router(captures.router)
    app.include_router(cases.router)
    app.include_router(sessions.router)
    app.include_router(findings.router)
    app.include_router(posture.router)
    app.include_router(anomalies.router)
    app.include_router(graph.router)
    app.include_router(ai.router)
    app.include_router(reports.router)
    _configure_services(app, settings)
    return app


app = create_app()
