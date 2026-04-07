"""Shared HTTP helpers with simple retry support."""

from __future__ import annotations

import json
import socket
import time
import urllib.error
import urllib.parse
import urllib.request

from .errors import APIClientError

TRANSIENT_STATUS_CODES = {408, 429, 500, 502, 503, 504}


class HTTPClient:
    """Minimal JSON HTTP client built on the Python standard library."""

    def __init__(self, provider: str, *, timeout: float = 15.0, user_agent: str = "intelfuse-cli") -> None:
        self.provider = provider
        self.timeout = timeout
        self.user_agent = user_agent

    def get_json(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        params: dict[str, str | int | bool | None] | None = None,
        retries: int = 2,
    ) -> dict:
        return self.request_json("GET", url, headers=headers, params=params, retries=retries)

    def request_json(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        params: dict[str, str | int | bool | None] | None = None,
        body: bytes | None = None,
        retries: int = 2,
    ) -> dict:
        request_headers = {"user-agent": self.user_agent, "accept": "application/json"}
        if headers:
            request_headers.update(headers)
        full_url = self._with_params(url, params)
        request = urllib.request.Request(full_url, headers=request_headers, method=method, data=body)

        attempt = 0
        while True:
            try:
                with urllib.request.urlopen(request, timeout=self.timeout) as response:
                    raw = response.read().decode("utf-8", errors="replace")
                    if not raw.strip():
                        return {}
                    try:
                        return json.loads(raw)
                    except json.JSONDecodeError as exc:
                        raise APIClientError(
                            self.provider,
                            f"{self.provider} returned invalid JSON.",
                            category="bad_response",
                        ) from exc
            except urllib.error.HTTPError as exc:
                payload = self._load_error_payload(exc)
                category = self._categorize_http_error(exc.code)
                retryable = exc.code in TRANSIENT_STATUS_CODES
                message = self._build_error_message(exc.code, payload)
                if retryable and attempt < retries:
                    self._sleep_before_retry(attempt)
                    attempt += 1
                    continue
                raise APIClientError(
                    self.provider,
                    message,
                    status_code=exc.code,
                    category=category,
                    retryable=retryable,
                    payload=payload,
                ) from exc
            except urllib.error.URLError as exc:
                reason = exc.reason
                if isinstance(reason, socket.timeout):
                    category = "timeout"
                    message = f"{self.provider} request timed out."
                else:
                    category = "network"
                    message = f"{self.provider} network failure: {reason}"
                retryable = True
                if attempt < retries:
                    self._sleep_before_retry(attempt)
                    attempt += 1
                    continue
                raise APIClientError(self.provider, message, category=category, retryable=retryable) from exc
            except TimeoutError as exc:
                if attempt < retries:
                    self._sleep_before_retry(attempt)
                    attempt += 1
                    continue
                raise APIClientError(
                    self.provider,
                    f"{self.provider} request timed out.",
                    category="timeout",
                    retryable=True,
                ) from exc

    @staticmethod
    def _with_params(url: str, params: dict[str, str | int | bool | None] | None) -> str:
        if not params:
            return url
        filtered = {key: value for key, value in params.items() if value is not None}
        if not filtered:
            return url
        return f"{url}?{urllib.parse.urlencode(filtered)}"

    @staticmethod
    def _sleep_before_retry(attempt: int) -> None:
        time.sleep(min(2 ** attempt, 4))

    def _load_error_payload(self, exc: urllib.error.HTTPError) -> dict:
        raw = exc.read().decode("utf-8", errors="replace")
        if not raw:
            return {}
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return {"message": raw}

    def _build_error_message(self, status_code: int, payload: dict) -> str:
        message = (
            payload.get("error", {}).get("message")
            or payload.get("errors", [{}])[0].get("detail")
            or payload.get("message")
            or "Unknown API error."
        )
        return f"{self.provider} error (HTTP {status_code}): {message}"

    @staticmethod
    def _categorize_http_error(status_code: int) -> str:
        if status_code in {401, 403}:
            return "invalid_api_key"
        if status_code == 429:
            return "rate_limit"
        if status_code == 404:
            return "not_found"
        if status_code in TRANSIENT_STATUS_CODES:
            return "transient_http"
        return "http_error"
