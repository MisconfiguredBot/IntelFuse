"""Shared error types for provider and transport failures."""

from __future__ import annotations


class APIClientError(RuntimeError):
    """Structured API error that keeps provider failure details intact."""

    def __init__(
        self,
        provider: str,
        message: str,
        *,
        status_code: int | None = None,
        category: str = "http_error",
        retryable: bool = False,
        payload: dict | None = None,
    ) -> None:
        self.provider = provider
        self.status_code = status_code
        self.category = category
        self.retryable = retryable
        self.payload = payload or {}
        super().__init__(message)


class InputValidationError(ValueError):
    """Raised when user input fails validation."""
