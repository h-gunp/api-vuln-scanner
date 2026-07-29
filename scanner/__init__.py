"""API vulnerability scanner worker package."""

from importlib import import_module
from typing import Any

from scanner.scanner import (
    DiscoveryJobError,
    DiscoveryOutcome,
    ExecutionJobError,
    ExecutionOutcome,
    Scanner,
)


def __getattr__(name: str) -> Any:
    if name in {"JobRegistry", "app", "create_app"}:
        return getattr(import_module("scanner.api"), name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "DiscoveryJobError",
    "DiscoveryOutcome",
    "ExecutionJobError",
    "ExecutionOutcome",
    "JobRegistry",
    "Scanner",
    "app",
    "create_app",
]
