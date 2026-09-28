"""Structured API error model.

Clients always receive ``{"error": {"code": ..., "message": ...}}``.
Internal details, storage paths, and tracebacks never reach responses;
unexpected errors are logged server-side and reported generically.
"""

import logging

from engine.ingestion.errors import (
    CaptureStorageError,
    CaptureTooLargeError,
    InvalidCaptureError,
    UnsupportedCaptureTypeError,
)
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

logger = logging.getLogger("ns_email.api")

ERROR_INVALID_CAPTURE_TYPE = "invalid_capture_type"
ERROR_CAPTURE_TOO_LARGE = "capture_too_large"
ERROR_INVALID_CAPTURE = "invalid_capture"
ERROR_CAPTURE_NOT_FOUND = "capture_not_found"
ERROR_CAPTURE_STORAGE = "capture_storage_error"
ERROR_CAPTURE_PROCESSING = "capture_processing_error"
ERROR_SESSION_NOT_FOUND = "session_not_found"
ERROR_FINDING_NOT_FOUND = "finding_not_found"
ERROR_POSTURE_NOT_AVAILABLE = "posture_not_available"
ERROR_ANOMALY_NOT_AVAILABLE = "anomaly_not_available"
ERROR_INSPECTOR_UNAVAILABLE = "packet_inspector_unavailable"
ERROR_INVALID_REQUEST = "invalid_request"
ERROR_INTERNAL = "internal_error"


class ApiError(Exception):
    """An error with a stable machine-readable code for API clients."""

    def __init__(self, code: str, message: str, status_code: int) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code


def _payload(code: str, message: str) -> dict[str, dict[str, str]]:
    return {"error": {"code": code, "message": message}}


def _json(code: str, message: str, status_code: int) -> JSONResponse:
    return JSONResponse(status_code=status_code, content=_payload(code, message))


def install_error_handlers(app: FastAPI) -> None:
    """Register structured handlers for domain, validation, and unexpected errors."""

    @app.exception_handler(ApiError)
    async def handle_api_error(request: Request, error: ApiError) -> JSONResponse:
        return _json(error.code, error.message, error.status_code)

    @app.exception_handler(UnsupportedCaptureTypeError)
    async def handle_unsupported_type(request: Request, error: Exception) -> JSONResponse:
        return _json(ERROR_INVALID_CAPTURE_TYPE, str(error), 400)

    @app.exception_handler(CaptureTooLargeError)
    async def handle_too_large(request: Request, error: Exception) -> JSONResponse:
        return _json(ERROR_CAPTURE_TOO_LARGE, str(error), 413)

    @app.exception_handler(InvalidCaptureError)
    async def handle_invalid(request: Request, error: Exception) -> JSONResponse:
        return _json(ERROR_INVALID_CAPTURE, str(error), 422)

    @app.exception_handler(CaptureStorageError)
    async def handle_storage(request: Request, error: Exception) -> JSONResponse:
        logger.error("capture storage error: %s", error)
        return _json(ERROR_CAPTURE_STORAGE, "capture storage failed on the server", 500)

    @app.exception_handler(RequestValidationError)
    async def handle_validation_error(request: Request, error: Exception) -> JSONResponse:
        return _json(ERROR_INVALID_REQUEST, "request payload failed validation", 422)

    @app.exception_handler(StarletteHTTPException)
    async def handle_http_exception(
        request: Request, error: StarletteHTTPException
    ) -> JSONResponse:
        """Route unmatched requests through the structured error shape."""
        code = {
            404: "not_found",
            405: "method_not_allowed",
            413: "request_too_large",
        }.get(error.status_code, ERROR_INVALID_REQUEST)
        message = "resource not found" if error.status_code == 404 else "request rejected"
        return _json(code, message, error.status_code)

    @app.exception_handler(Exception)
    async def handle_unexpected(request: Request, error: Exception) -> JSONResponse:
        logger.exception("unhandled error")
        return _json(ERROR_INTERNAL, "internal server error", 500)
