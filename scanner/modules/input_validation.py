"""Fixed-rule input validation probe."""

from __future__ import annotations

import copy
import hashlib
import re
from collections.abc import Iterable
from decimal import Decimal, InvalidOperation
from urllib.parse import urljoin

from scanner.artifacts import Redactor
from scanner.contracts import AffectedField, InputBinding, InputField
from scanner.http_client import ResponseSnapshot
from scanner.modules.base import (
    BindingError,
    BoundRequest,
    ModuleExecutionContext,
    ModuleOutcome,
    ModuleVerdict,
    bind_operation,
)
from scanner.modules.data_exposure import _sensitive_matches
from scanner.policy import PolicyViolation


RULE_ID = "VERIFY-INPUT-001"
VERIFIED_CONDITION = "INPUT_INVALID_VALUE_EXPANDED_SCOPE"
MODULE_ID = "INPUT-001"
_OVERFLOW_CANDIDATE = "2147483648"


class _InMemoryEvidence(dict[str, object]):
    """Evidence remains available in memory without rendering runtime values."""

    def __repr__(self) -> str:
        return "_InMemoryEvidence([REDACTED])"

    __str__ = __repr__


class InputValidationModule:
    def run(self, context: ModuleExecutionContext) -> ModuleOutcome:
        if context.operation.method != "GET":
            return _inconclusive("INPUT_NON_GET_OPERATION")
        if any(
            binding.location not in {"path", "query"}
            for binding in context.step.input_bindings
        ):
            return _inconclusive("INPUT_UNSAFE_INPUT_LOCATION")

        selected = _selected_binding(context)
        if selected is None:
            return _inconclusive("INPUT_BINDING_UNAVAILABLE")
        binding, input_field = selected
        baseline_value = _baseline_value(context, binding)
        if baseline_value is None:
            return _inconclusive("INPUT_BASELINE_UNAVAILABLE")
        invalid_value = _invalid_value(
            context.operation.operation_id,
            binding,
            input_field,
            baseline_value,
        )
        if invalid_value is None:
            return _inconclusive("INPUT_BASELINE_UNAVAILABLE")

        baseline_runtime = _runtime_with_value(
            context,
            binding,
            baseline_value,
        )
        variant_runtime = _runtime_with_value(
            context,
            binding,
            invalid_value,
        )
        try:
            baseline_request = bind_operation(
                operation=context.operation,
                bindings=list(context.step.input_bindings),
                runtime=baseline_runtime,
            )
            variant_request = bind_operation(
                operation=context.operation,
                bindings=list(context.step.input_bindings),
                runtime=variant_runtime,
            )
        except BindingError:
            return _inconclusive("INPUT_BINDING_UNAVAILABLE")
        if (
            baseline_request == variant_request
            or baseline_request.json_body is not None
            or variant_request.json_body is not None
            or baseline_request.headers
            or variant_request.headers
        ):
            return _inconclusive("INPUT_BINDING_UNAVAILABLE")

        authorization = _authorization(context)
        if authorization is None:
            return _inconclusive("INPUT_SESSION_UNAVAILABLE")
        headers = {"Authorization": authorization}
        baseline_url = _request_url(context, baseline_request)
        variant_url = _request_url(context, variant_request)
        try:
            context.client.preflight(
                "GET",
                baseline_url,
                module_id=MODULE_ID,
                headers=headers,
            )
            context.client.preflight(
                "GET",
                variant_url,
                module_id=MODULE_ID,
                headers=headers,
            )
        except PolicyViolation:
            return _inconclusive("INPUT_POLICY_PREFLIGHT_FAILED")

        user_b_only = _user_b_only_values(context)
        sensitive_values = _transport_sensitive_values(context, user_b_only)
        baseline = _send(
            context,
            baseline_request,
            url=baseline_url,
            headers=headers,
            sensitive_values=sensitive_values,
        )
        variant = _send(
            context,
            variant_request,
            url=variant_url,
            headers=headers,
            sensitive_values=sensitive_values,
        )
        evidence = _evidence(context, baseline, variant)

        baseline_body = _runtime_json_body(baseline)
        if not baseline.is_success or baseline_body is None:
            return _inconclusive("INPUT_COMPARISON_UNAVAILABLE", evidence)
        if not variant.is_success:
            return ModuleOutcome(
                verdict=ModuleVerdict.NOT_FOUND,
                rule_id=RULE_ID,
                evidence=evidence,
                reason_code="INPUT_INVALID_VALUE_REJECTED",
            )
        variant_body = _runtime_json_body(variant)
        if variant_body is None:
            return _inconclusive("INPUT_COMPARISON_UNAVAILABLE", evidence)

        affected = _expanded_scope_fields(
            context,
            baseline_body,
            variant_body,
            user_b_only=user_b_only,
        )
        if not affected:
            return ModuleOutcome(
                verdict=ModuleVerdict.NOT_FOUND,
                rule_id=RULE_ID,
                evidence=evidence,
                reason_code="INPUT_SCOPE_NOT_EXPANDED",
            )
        return ModuleOutcome(
            verdict=ModuleVerdict.VERIFIED,
            rule_id=RULE_ID,
            conditions=(VERIFIED_CONDITION,),
            affected_fields=affected,
            evidence=evidence,
        )


def _selected_binding(
    context: ModuleExecutionContext,
) -> tuple[InputBinding, InputField] | None:
    inputs = {
        (item.location, item.field_path): item for item in context.operation.inputs
    }
    candidates: list[tuple[InputBinding, InputField]] = []
    for binding in context.step.input_bindings:
        input_field = inputs.get((binding.location, binding.parameter))
        if (
            input_field is not None
            and binding.binding_type == "parameter_binding"
            and binding.location in {"path", "query"}
            and binding.object_type is None
            and binding.owner is None
        ):
            candidates.append((binding, input_field))
    if not candidates:
        return None
    return sorted(
        candidates,
        key=lambda item: (item[0].location, item[0].parameter),
    )[0]


def _baseline_value(
    context: ModuleExecutionContext,
    binding: InputBinding,
) -> str | None:
    key = (
        context.operation.operation_id,
        binding.location,
        binding.parameter,
    )
    openapi_values = _reveal_values(
        context.runtime.openapi_parameter_examples.get(key, set())
    )
    if openapi_values:
        return sorted(openapi_values)[0]
    if binding.location != "query":
        return None
    observed_values = _reveal_values(
        context.runtime.observed_parameter_examples.get(key, set())
    )
    return sorted(observed_values)[0] if observed_values else None


def _invalid_value(
    operation_id: str,
    binding: InputBinding,
    input_field: InputField,
    baseline: str,
) -> str | None:
    if input_field.type in {"integer", "number"}:
        try:
            baseline_number = Decimal(baseline)
        except InvalidOperation:
            return None
        if not baseline_number.is_finite():
            return None
        if input_field.type == "integer" and baseline_number != baseline_number.to_integral():
            return None
        if baseline_number == Decimal("-1"):
            return "0"
        if baseline_number == Decimal("0"):
            return _OVERFLOW_CANDIDATE
        return "-1"
    if input_field.type == "string":
        material = f"{operation_id}:{binding.parameter}".encode("utf-8")
        digest = hashlib.sha256(material).hexdigest()[:16]
        candidate = f"invalid-{digest}"
        return candidate if candidate != baseline else f"{candidate}-x"
    return None


def _runtime_with_value(
    context: ModuleExecutionContext,
    binding: InputBinding,
    value: str,
):
    runtime = copy.copy(context.runtime)
    runtime.parameter_examples = dict(context.runtime.parameter_examples)
    key = (
        context.operation.operation_id,
        binding.location,
        binding.parameter,
    )
    runtime.parameter_examples[key] = {value}
    return runtime


def _authorization(context: ModuleExecutionContext) -> str | None:
    session = context.runtime.sessions.get("user_a")
    if session is None:
        return None
    authorization = session.authorization_headers().get("Authorization")
    if (
        not isinstance(authorization, str)
        or not authorization.startswith("Bearer ")
        or not authorization.removeprefix("Bearer ").strip()
    ):
        return None
    return authorization


def _request_url(
    context: ModuleExecutionContext,
    request: BoundRequest,
) -> str:
    return urljoin(
        f"{context.base_url.rstrip('/')}/",
        request.path.lstrip("/"),
    )


def _send(
    context: ModuleExecutionContext,
    request: BoundRequest,
    *,
    url: str,
    headers: dict[str, str],
    sensitive_values: set[str],
) -> ResponseSnapshot:
    return context.client.request(
        "GET",
        url,
        module_id=MODULE_ID,
        headers=headers,
        params=request.query,
        sensitive_values=sensitive_values,
        follow_redirects=False,
    )


def _runtime_json_body(snapshot: ResponseSnapshot) -> object | None:
    if snapshot.runtime_json_body is None:
        return None
    return snapshot.runtime_json_body.reveal()


def _user_b_only_values(
    context: ModuleExecutionContext,
) -> dict[str, set[str]]:
    selected: dict[str, set[str]] = {}
    user_a = context.runtime.object_ids.get("user_a", {})
    user_b = context.runtime.object_ids.get("user_b", {})
    for object_type in sorted(user_b):
        values = _reveal_values(user_b[object_type]) - _reveal_values(
            user_a.get(object_type, set())
        )
        if values:
            selected[object_type] = values
    return selected


def _transport_sensitive_values(
    context: ModuleExecutionContext,
    user_b_only: dict[str, set[str]],
) -> set[str]:
    values = _reveal_values(context.runtime.credentials)
    for session in context.runtime.sessions.values():
        if session.token is not None:
            values.update(_reveal_values((session.token,)))
        values.update(_reveal_values(session.cookies.values()))
    excluded = {item for items in user_b_only.values() for item in items}
    for actor_objects in context.runtime.object_ids.values():
        for identifiers in actor_objects.values():
            values.update(_reveal_values(identifiers) - excluded)
    return values


def _expanded_scope_fields(
    context: ModuleExecutionContext,
    baseline: object,
    variant: object,
    *,
    user_b_only: dict[str, set[str]],
) -> tuple[AffectedField, ...]:
    baseline_objects = _object_fields(baseline, user_b_only)
    variant_objects = _object_fields(variant, user_b_only)
    baseline_sensitive = {
        (match.field_path, match.data_class)
        for match in _sensitive_matches(baseline)
    }
    variant_sensitive = _sensitive_matches(variant)
    new_sensitive = [
        match
        for match in variant_sensitive
        if (match.field_path, match.data_class) not in baseline_sensitive
    ]
    secret_response_values = {match.value for match in new_sensitive}
    replacements = {
        value: "{runtime_value}" for value in context.runtime.sensitive_values()
    }
    replacements.update({value: "{sensitive_value}" for value in secret_response_values})

    affected: dict[str, str] = {}
    for path, object_type in sorted(variant_objects - baseline_objects):
        safe_path = _sanitize_path(path, replacements)
        affected.setdefault(safe_path, _object_data_class(object_type))
    for match in new_sensitive:
        safe_path = _sanitize_path(match.field_path, replacements)
        affected.setdefault(safe_path, match.data_class)
    return tuple(
        AffectedField(
            location="response",
            field_path=path,
            data_class=data_class,
        )
        for path, data_class in sorted(affected.items())
    )


def _object_fields(
    body: object,
    user_b_only: dict[str, set[str]],
) -> set[tuple[str, str]]:
    matches: set[tuple[str, str]] = set()
    for path, value in _scalar_fields(body):
        rendered = str(value)
        for object_type, values in user_b_only.items():
            if rendered in values and _is_identifying_path(path, object_type):
                matches.add((_render_path(path), object_type))
    return matches


def _scalar_fields(
    value: object,
    path: tuple[str, ...] = (),
) -> Iterable[tuple[tuple[str, ...], object]]:
    if isinstance(value, dict):
        for key in sorted(value, key=str):
            yield from _scalar_fields(value[key], (*path, str(key)))
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _scalar_fields(item, (*path, "[]"))
    elif isinstance(value, (str, int, float)) and not isinstance(value, bool):
        yield path or ("$",), value


def _is_identifying_path(path: tuple[str, ...], object_type: str) -> bool:
    terminal = path[-1].casefold()
    if terminal == f"{object_type}_id".casefold():
        return True
    if terminal != "id":
        return False
    parents = [part.casefold() for part in path[:-1] if part != "[]"]
    return bool(parents) and parents[-1] == object_type.casefold()


def _render_path(path: tuple[str, ...]) -> str:
    rendered = ""
    for part in path:
        if part == "[]":
            rendered += part
        elif rendered:
            rendered += f".{part}"
        else:
            rendered = part
    return rendered


def _sanitize_path(path: str, replacements: dict[str, str]) -> str:
    usable = {value: marker for value, marker in replacements.items() if value}
    if not usable:
        return path
    pattern = re.compile(
        "|".join(re.escape(value) for value in sorted(usable, key=len, reverse=True))
    )
    return pattern.sub(lambda match: usable[match.group(0)], path)


def _reveal_values(values: Iterable[object]) -> set[str]:
    revealed: set[str] = set()
    for value in values:
        reveal = getattr(value, "reveal", None)
        item = reveal() if callable(reveal) else value
        if isinstance(item, str):
            revealed.add(item)
    return revealed


def _object_data_class(object_type: str) -> str:
    if object_type == "account":
        return "account"
    if object_type in {"card", "transaction"}:
        return "financial"
    return "other"


def _evidence(
    context: ModuleExecutionContext,
    baseline: ResponseSnapshot,
    variant: ResponseSnapshot,
) -> _InMemoryEvidence:
    values = set(context.runtime.sensitive_values())
    for snapshot in (baseline, variant):
        body = _runtime_json_body(snapshot)
        if body is not None:
            values.update(match.value for match in _sensitive_matches(body))
    redactor = Redactor()
    return _InMemoryEvidence(
        request=_InMemoryEvidence(
            operation_id=context.operation.operation_id,
            method="GET",
        ),
        baseline=_InMemoryEvidence(
            status_code=baseline.status_code,
            json_body=redactor.redact(baseline.json_body, values),
            url=redactor.redact(baseline.url, values),
        ),
        variant=_InMemoryEvidence(
            status_code=variant.status_code,
            json_body=redactor.redact(variant.json_body, values),
            url=redactor.redact(variant.url, values),
        ),
    )


def _inconclusive(
    reason_code: str,
    evidence: _InMemoryEvidence | None = None,
) -> ModuleOutcome:
    return ModuleOutcome(
        verdict=ModuleVerdict.INCONCLUSIVE,
        rule_id=RULE_ID,
        evidence=evidence or _InMemoryEvidence(),
        reason_code=reason_code,
    )
