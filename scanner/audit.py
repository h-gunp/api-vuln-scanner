"""Redacted audit event boundary for scanner worker activity."""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any, Mapping, Protocol

from scanner.artifacts import Redactor


@dataclass(frozen=True)
class AuditEvent:
    code: str
    level: str
    job_id: str | None
    scan_id: str | None
    operation_id: str | None
    module_id: str | None
    details: Mapping[str, Any]


class AuditSink(Protocol):
    def emit(self, event: AuditEvent) -> None: ...


class InMemoryAuditSink:
    def __init__(self, redactor: Redactor | None = None) -> None:
        self._redactor = redactor or Redactor()
        self.events: list[AuditEvent] = []

    def emit(self, event: AuditEvent) -> None:
        self.events.append(
            replace(event, details=self._remove_textual_details(event.details))
        )

    def _remove_textual_details(self, value: Any) -> Any:
        redacted = self._redactor.redact(value)
        if isinstance(redacted, Mapping):
            return {
                str(key): self._remove_textual_details(item)
                for key, item in redacted.items()
            }
        if isinstance(redacted, (list, tuple, set, frozenset)):
            return [self._remove_textual_details(item) for item in redacted]
        if isinstance(redacted, (str, BaseException)):
            return "[REDACTED]"
        return redacted
