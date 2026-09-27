"""Application settings.

Settings that vary per environment are read from environment variables;
no secrets live in source. Invalid configuration fails fast at startup
with a clear message instead of misbehaving later.
"""

import os
from dataclasses import dataclass
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

from engine.core.capture import MAX_CAPTURE_SIZE_BYTES

SERVICE_NAME = "ns-email"
CORS_ORIGINS_ENV_VAR = "NS_EMAIL_CORS_ORIGINS"
CAPTURE_STORAGE_ENV_VAR = "NS_EMAIL_CAPTURE_STORAGE"
MAX_CAPTURE_BYTES_ENV_VAR = "NS_EMAIL_MAX_CAPTURE_BYTES"
TSHARK_PATH_ENV_VAR = "NS_EMAIL_TSHARK_PATH"
POLICY_FILE_ENV_VAR = "NS_EMAIL_POLICY_FILE"

DEFAULT_CORS_ORIGINS: tuple[str, ...] = ("http://localhost:3000",)
DEFAULT_CAPTURE_STORAGE_DIR = Path("data/captures")
DEFAULT_MAX_CAPTURE_BYTES = MAX_CAPTURE_SIZE_BYTES
DEFAULT_INSPECTOR_TIMEOUT_SECONDS = 120.0


@dataclass(frozen=True)
class Settings:
    service_name: str
    app_version: str
    cors_origins: tuple[str, ...]
    capture_storage_dir: Path = DEFAULT_CAPTURE_STORAGE_DIR
    max_capture_bytes: int = DEFAULT_MAX_CAPTURE_BYTES
    tshark_path: str | None = None
    inspector_timeout_seconds: float = DEFAULT_INSPECTOR_TIMEOUT_SECONDS
    policy_file: str | None = None


def _app_version() -> str:
    try:
        return version("ns-email")
    except PackageNotFoundError:  # running from a source checkout without installation
        return "0.0.0"


def _max_capture_bytes() -> int:
    raw = os.environ.get(MAX_CAPTURE_BYTES_ENV_VAR)
    if not raw:
        return DEFAULT_MAX_CAPTURE_BYTES
    try:
        value = int(raw)
    except ValueError as error:
        raise ValueError(
            f"{MAX_CAPTURE_BYTES_ENV_VAR} must be a positive integer, got {raw!r}"
        ) from error
    if value <= 0:
        raise ValueError(f"{MAX_CAPTURE_BYTES_ENV_VAR} must be a positive integer, got {raw!r}")
    # The engine enforces an absolute ceiling regardless of configuration.
    return min(value, MAX_CAPTURE_SIZE_BYTES)


def load_settings() -> Settings:
    """Build settings from defaults and the environment."""
    raw_origins = os.environ.get(CORS_ORIGINS_ENV_VAR, "")
    origins = tuple(o.strip() for o in raw_origins.split(",") if o.strip())
    storage_raw = os.environ.get(CAPTURE_STORAGE_ENV_VAR)
    tshark_raw = os.environ.get(TSHARK_PATH_ENV_VAR)
    return Settings(
        service_name=SERVICE_NAME,
        app_version=_app_version(),
        cors_origins=origins or DEFAULT_CORS_ORIGINS,
        capture_storage_dir=Path(storage_raw) if storage_raw else DEFAULT_CAPTURE_STORAGE_DIR,
        max_capture_bytes=_max_capture_bytes(),
        tshark_path=tshark_raw or None,
        policy_file=os.environ.get(POLICY_FILE_ENV_VAR) or None,
    )
