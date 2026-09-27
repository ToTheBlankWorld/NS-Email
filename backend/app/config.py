"""Application settings.

The foundation only needs non-sensitive settings. Values that could differ per
environment are read from environment variables; no secrets live in source.
"""

import os
from dataclasses import dataclass
from importlib.metadata import PackageNotFoundError, version

SERVICE_NAME = "ns-email"
CORS_ORIGINS_ENV_VAR = "NS_EMAIL_CORS_ORIGINS"
DEFAULT_CORS_ORIGINS: tuple[str, ...] = ("http://localhost:3000",)


@dataclass(frozen=True)
class Settings:
    service_name: str
    app_version: str
    cors_origins: tuple[str, ...]


def _app_version() -> str:
    try:
        return version("ns-email")
    except PackageNotFoundError:  # running from a source checkout without installation
        return "0.0.0"


def load_settings() -> Settings:
    """Build settings from defaults and the environment."""
    raw_origins = os.environ.get(CORS_ORIGINS_ENV_VAR, "")
    origins = tuple(o.strip() for o in raw_origins.split(",") if o.strip())
    return Settings(
        service_name=SERVICE_NAME,
        app_version=_app_version(),
        cors_origins=origins or DEFAULT_CORS_ORIGINS,
    )
