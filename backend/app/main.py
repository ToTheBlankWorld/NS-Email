"""FastAPI application factory for the NS-Email backend."""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import load_settings
from app.routers import health


def create_app() -> FastAPI:
    settings = load_settings()
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
        allow_methods=["GET"],
        allow_headers=["*"],
    )
    app.include_router(health.router)
    return app


app = create_app()
