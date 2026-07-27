"""Redaction and deterministic artifact serialization for scanner outputs."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Iterable, Mapping
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


REDACTED = "[REDACTED]"
SENSITIVE_KEYS = frozenset(
    {
        "authorization",
        "cookie",
        "set-cookie",
        "password",
        "passwd",
        "token",
        "access_token",
        "refresh_token",
        "secret",
        "api_key",
        "pin",
        "cvv",
        "session",
        "response",
        "response_body",
        "body",
        "object_id",
        "account_id",
        "parameter_value",
        "observed_value",
    }
)


@dataclass(frozen=True)
class ArtifactEnvelope:
    scan_id: str
    artifact_type: str
    schema_version: str | None
    content: bytes
    sha256: str
    size: int


class Redactor:
    """Removes credential-bearing keys and supplied runtime values."""

    def redact(self, value: Any, sensitive_values: Iterable[Any] = ()) -> Any:
        values = tuple(sensitive_values)
        string_values = tuple(
            sorted(
                {item for item in values if isinstance(item, str) and item},
                key=len,
                reverse=True,
            )
        )
        return self._redact_value(value, values, string_values)

    def _redact_value(
        self,
        value: Any,
        sensitive_values: tuple[Any, ...],
        string_values: tuple[str, ...],
    ) -> Any:
        if isinstance(value, Mapping):
            return {
                str(key): (
                    REDACTED
                    if str(key).casefold() in SENSITIVE_KEYS
                    else self._redact_value(item, sensitive_values, string_values)
                )
                for key, item in value.items()
            }
        if isinstance(value, (list, tuple, set, frozenset)):
            return [
                self._redact_value(item, sensitive_values, string_values) for item in value
            ]
        if isinstance(value, BaseException):
            return REDACTED
        if isinstance(value, str):
            return self._redact_string(value, string_values)
        if any(type(value) is type(item) and value == item for item in sensitive_values):
            return REDACTED
        return value

    def _redact_string(self, value: str, sensitive_values: tuple[str, ...]) -> str:
        redacted = self._redact_url_query(value)
        for sensitive_value in sensitive_values:
            redacted = redacted.replace(sensitive_value, REDACTED)
        return redacted

    def _redact_url_query(self, value: str) -> str:
        parsed = urlsplit(value)
        if not parsed.query:
            return value
        query = [
            (key, REDACTED if key.casefold() in SENSITIVE_KEYS else item)
            for key, item in parse_qsl(parsed.query, keep_blank_values=True)
        ]
        return urlunsplit(
            (parsed.scheme, parsed.netloc, parsed.path, urlencode(query), parsed.fragment)
        )


class ArtifactBuilder:
    def __init__(self, redactor: Redactor) -> None:
        self._redactor = redactor

    def build(
        self,
        *,
        scan_id: str,
        artifact_type: str,
        schema_version: str | None,
        payload: Mapping[str, Any],
        sensitive_values: Iterable[str] = (),
    ) -> ArtifactEnvelope:
        cleaned = self._redactor.redact(payload, sensitive_values)
        content = json.dumps(
            cleaned,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
        return ArtifactEnvelope(
            scan_id=scan_id,
            artifact_type=artifact_type,
            schema_version=schema_version,
            content=content,
            sha256=hashlib.sha256(content).hexdigest(),
            size=len(content),
        )
