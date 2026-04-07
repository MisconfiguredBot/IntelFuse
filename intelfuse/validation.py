"""Input validation helpers."""

from __future__ import annotations

import ipaddress

from .errors import InputValidationError


def validate_ip_address(value: str) -> str:
    """Return a normalized IPv4 or IPv6 string or raise an input error."""
    stripped = value.strip()
    if not stripped:
        raise InputValidationError("Empty IP address provided.")

    try:
        parsed = ipaddress.ip_address(stripped)
    except ValueError as exc:
        raise InputValidationError(f"Invalid IP address: {value}") from exc

    return parsed.compressed
