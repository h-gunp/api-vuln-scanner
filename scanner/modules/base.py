"""Shared fixed-rule module contracts and operation binding."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Mapping
from urllib.parse import quote

from scanner.auth.session_manager import RuntimeContext
from scanner.contracts import AffectedField, InputBinding, Operation, ScanStep
from scanner.http_client import SafeHttpClient


class BindingError(Exception):
    """A fixed, runtime-value-free operation binding failure."""


class ModuleVerdict(StrEnum):
    VERIFIED = "verified"
    NOT_FOUND = "not_found"
    INCONCLUSIVE = "inconclusive"


@dataclass(frozen=True)
class ModuleOutcome:
    verdict: ModuleVerdict
    rule_id: str
    conditions: tuple[str, ...] = ()
    affected_fields: tuple[AffectedField, ...] = ()
    evidence: Mapping[str, object] = field(default_factory=dict, repr=False)
    reason_code: str | None = None


@dataclass
class ModuleExecutionContext:
    scan_id: str
    base_url: str
    operation: Operation
    step: ScanStep
    runtime: RuntimeContext
    client: SafeHttpClient


@dataclass(frozen=True)
class BoundRequest:
    path: str = field(repr=False)
    query: Mapping[str, object] = field(repr=False)
    headers: Mapping[str, str] = field(repr=False)
    json_body: object | None = field(repr=False)


def bind_operation(
    *,
    operation: Operation,
    bindings: list[InputBinding],
    runtime: RuntimeContext,
) -> BoundRequest:
    inputs = {(item.location, item.field_path): item for item in operation.inputs}
    bound_keys: set[tuple[str, str]] = set()
    resolved: list[tuple[InputBinding, str]] = []

    for binding in bindings:
        key = (binding.location, binding.parameter)
        if key not in inputs or key in bound_keys:
            raise BindingError("operation binding failed")
        value = _resolve_binding(operation, binding, runtime)
        bound_keys.add(key)
        resolved.append((binding, value))

    required = set(runtime.required_inputs.get(operation.operation_id, set()))
    required.update(
        (item.location, item.field_path)
        for item in operation.inputs
        if item.location == "body"
    )
    required.update(("path", name) for name in _path_parameters(operation.path_template))
    if not required.issubset(bound_keys):
        raise BindingError("operation binding failed")

    path = operation.path_template
    query: dict[str, object] = {}
    headers: dict[str, str] = {}
    json_body: dict[str, object] = {}
    has_body = False
    for binding, value in resolved:
        if binding.location == "path":
            marker = "{" + binding.parameter + "}"
            if marker not in path:
                raise BindingError("operation binding failed")
            path = path.replace(marker, quote(value, safe=""))
        elif binding.location == "query":
            query[binding.parameter] = value
        elif binding.location == "header":
            headers[binding.parameter] = value
        else:
            _assign_body_value(json_body, binding.parameter, value)
            has_body = True

    if _path_parameters(path):
        raise BindingError("operation binding failed")
    return BoundRequest(
        path=path,
        query=query,
        headers=headers,
        json_body=json_body if has_body else None,
    )


def _resolve_binding(
    operation: Operation,
    binding: InputBinding,
    runtime: RuntimeContext,
) -> str:
    if binding.binding_type == "object_binding":
        if binding.object_type is None or binding.owner is None:
            raise BindingError("operation binding failed")
        values = (
            runtime.object_ids.get(binding.owner, {}).get(binding.object_type, set())
        )
    else:
        if binding.object_type is not None or binding.owner is not None:
            raise BindingError("operation binding failed")
        values = runtime.parameter_examples.get(
            (operation.operation_id, binding.location, binding.parameter),
            set(),
        )
    if not values:
        raise BindingError("operation binding failed")
    return sorted(_reveal_runtime_value(value) for value in values)[0]


def _reveal_runtime_value(value: object) -> str:
    reveal = getattr(value, "reveal", None)
    if callable(reveal):
        revealed = reveal()
        if isinstance(revealed, str):
            return revealed
    if isinstance(value, str):
        return value
    raise BindingError("operation binding failed")


def _path_parameters(path_template: str) -> tuple[str, ...]:
    return tuple(re.findall(r"\{([^{}]+)\}", path_template))


def _assign_body_value(body: dict[str, object], field_path: str, value: str) -> None:
    if "[" in field_path or "]" in field_path:
        raise BindingError("operation binding failed")
    parts = field_path.split(".")
    if not parts or any(not part for part in parts):
        raise BindingError("operation binding failed")
    cursor = body
    for part in parts[:-1]:
        existing = cursor.setdefault(part, {})
        if not isinstance(existing, dict):
            raise BindingError("operation binding failed")
        cursor = existing
    if parts[-1] in cursor:
        raise BindingError("operation binding failed")
    cursor[parts[-1]] = value
