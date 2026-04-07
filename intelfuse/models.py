"""Shared dataclasses used across the CLI."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field


@dataclass(frozen=True)
class LookupTarget:
    raw_value: str
    kind: str
    endpoint_value: str
    local_path: str | None = None


@dataclass
class ProviderEnvelope:
    provider: str
    ok: bool
    data: dict | None = None
    error: str | None = None
    category: str | None = None
    status_code: int | None = None

    def asdict(self) -> dict:
        return asdict(self)


@dataclass
class Verdict:
    label: str
    severity: int
    confidence: str
    explanation: str
    reasons: list[str] = field(default_factory=list)

    def asdict(self) -> dict:
        return asdict(self)
