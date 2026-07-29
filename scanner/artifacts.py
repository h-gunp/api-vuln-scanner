"""Redaction and deterministic artifact serialization for scanner outputs."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Iterable, Mapping
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from pydantic import ValidationError

from scanner.contracts import EvidenceArtifact, NormalizedApiGraph, ScanResult


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
    }
)
STRUCTURAL_ARTIFACT_TYPES = frozenset({"normalized_api_graph", "scan_result"})
SAFE_NUMERIC_ARTIFACT_KEYS = frozenset(
    {
        "count",
        "counts",
        "progress",
        "requests_used",
        "status",
        "status_code",
    }
)
MIN_SENSITIVE_SUBSTRING_LENGTH = 4


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

    @staticmethod
    def _matches_sensitive(value: Any, sensitive_values: tuple[Any, ...]) -> bool:
        return any(
            type(value) is type(item) and value == item for item in sensitive_values
        )

    def _redact_value(
        self,
        value: Any,
        sensitive_values: tuple[Any, ...],
        string_values: tuple[str, ...],
    ) -> Any:
        if isinstance(value, Mapping):
            return {
                (
                    REDACTED
                    if not isinstance(key, str)
                    or self._matches_sensitive(key, sensitive_values)
                    else key
                ): (
                    REDACTED
                    if str(key).casefold() in SENSITIVE_KEYS
                    or self._matches_sensitive(key, sensitive_values)
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
        if self._matches_sensitive(value, sensitive_values):
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
        sensitive_values: Iterable[Any] = (),
    ) -> ArtifactEnvelope:
        if artifact_type == "evidence":
            canonical = self._canonicalize_evidence_payload(schema_version, payload)
            protected_values = _fixed_evidence_semantic_values(canonical)
            evidence_values = tuple(sensitive_values)
            short_sensitive_values = {
                value
                for value in evidence_values
                if isinstance(value, str)
                and value
                and len(value) < MIN_SENSITIVE_SUBSTRING_LENGTH
                and value not in protected_values
            }
            if _contains_exact_string_value(canonical, short_sensitive_values):
                raise ValueError("invalid evidence artifact payload")
            evidence_sensitive_values = tuple(
                value
                for value in evidence_values
                if not isinstance(value, str)
                or (
                    len(value) >= MIN_SENSITIVE_SUBSTRING_LENGTH
                    and value not in protected_values
                )
            )
            cleaned = self._redactor.redact(canonical, evidence_sensitive_values)
            if cleaned != canonical:
                raise ValueError("invalid evidence artifact payload")
            cleaned = self._canonicalize_evidence_payload(schema_version, cleaned)
        else:
            cleaned = self._redactor.redact(payload, sensitive_values)
        if artifact_type in STRUCTURAL_ARTIFACT_TYPES:
            cleaned = self._canonicalize_structural_payload(
                artifact_type, schema_version, cleaned
            )
        elif artifact_type != "evidence":
            cleaned = self._remove_untyped_runtime_values(cleaned)
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

    def _canonicalize_evidence_payload(
        self,
        schema_version: str | None,
        payload: Mapping[str, Any],
    ) -> dict[str, Any]:
        if schema_version is not None:
            raise ValueError("unsupported evidence artifact schema")
        try:
            return EvidenceArtifact.model_validate(payload).model_dump(mode="json")
        except ValidationError:
            raise ValueError("invalid evidence artifact payload") from None

    def _canonicalize_structural_payload(
        self,
        artifact_type: str,
        schema_version: str | None,
        payload: Mapping[str, Any],
    ) -> dict[str, Any]:
        model_type = {
            ("normalized_api_graph", "1.1"): NormalizedApiGraph,
            ("scan_result", "1.2"): ScanResult,
        }.get((artifact_type, schema_version))
        if model_type is None:
            raise ValueError("unsupported structural artifact schema")
        try:
            return model_type.model_validate(payload).model_dump(mode="json")
        except ValidationError:
            raise ValueError("invalid structural artifact payload") from None

    def _remove_untyped_runtime_values(
        self, value: Any, allow_numeric: bool = False
    ) -> Any:
        if isinstance(value, Mapping):
            return {
                (
                    str(key)
                    if str(key).casefold() in SAFE_NUMERIC_ARTIFACT_KEYS
                    or str(key) == REDACTED
                    else REDACTED
                ): self._remove_untyped_runtime_values(
                    item, str(key).casefold() in SAFE_NUMERIC_ARTIFACT_KEYS
                )
                for key, item in value.items()
            }
        if isinstance(value, (list, tuple, set, frozenset)):
            return [
                self._remove_untyped_runtime_values(item, allow_numeric) for item in value
            ]
        if isinstance(value, str):
            return REDACTED
        if isinstance(value, (int, float, bool)) and not allow_numeric:
            return REDACTED
        return value


def _fixed_evidence_semantic_values(payload: Mapping[str, Any]) -> set[str]:
    protected = {
        str(payload.get("module_id", "")),
        str(payload.get("rule_id", "")),
    }
    protected.update(
        item
        for item in payload.get("verified_conditions", ())
        if isinstance(item, str)
    )
    for observation_name in ("baseline", "variant"):
        observation = payload.get(observation_name)
        if isinstance(observation, Mapping):
            actor_id = observation.get("actor_id")
            if isinstance(actor_id, str):
                protected.add(actor_id)
    affected_fields = payload.get("affected_fields")
    if isinstance(affected_fields, list):
        for item in affected_fields:
            if not isinstance(item, Mapping):
                continue
            for key in ("location", "data_class"):
                value = item.get(key)
                if isinstance(value, str):
                    protected.add(value)
    protected.discard("")
    return protected


def _contains_exact_string_value(value: Any, sensitive_values: set[str]) -> bool:
    if isinstance(value, Mapping):
        return any(
            _contains_exact_string_value(item, sensitive_values)
            for item in value.values()
        )
    if isinstance(value, (list, tuple)):
        return any(
            _contains_exact_string_value(item, sensitive_values) for item in value
        )
    return isinstance(value, str) and value in sensitive_values
