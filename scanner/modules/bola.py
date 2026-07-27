"""Fixed-rule BOLA authorization probe."""

from __future__ import annotations

import copy
from collections.abc import Iterable
from urllib.parse import urljoin

from scanner.auth.session_manager import RuntimeContext
from scanner.contracts import AffectedField, InputBinding
from scanner.http_client import ResponseSnapshot
from scanner.modules.base import (
    BindingError,
    BoundRequest,
    ModuleExecutionContext,
    ModuleOutcome,
    ModuleVerdict,
    bind_operation,
)


RULE_ID = "VERIFY-BOLA-001"
VERIFIED_CONDITION = "BOLA_FOREIGN_OBJECT_RETURNED"
MODULE_ID = "BOLA-001"


class _InMemoryEvidence(dict[str, object]):
    """Evidence that remains inspectable but never renders runtime values."""

    def __repr__(self) -> str:
        return "_InMemoryEvidence([REDACTED])"

    __str__ = __repr__


class BolaModule:
    def run(self, context: ModuleExecutionContext) -> ModuleOutcome:
        if context.operation.method != "GET":
            return _inconclusive("BOLA_NON_GET_OPERATION")

        session = context.runtime.sessions.get("user_a")
        if session is None:
            return _inconclusive("BOLA_SESSION_UNAVAILABLE")
        authorization = session.authorization_headers().get("Authorization")
        if (
            not isinstance(authorization, str)
            or not authorization.startswith("Bearer ")
            or not authorization.removeprefix("Bearer ").strip()
        ):
            return _inconclusive("BOLA_SESSION_UNAVAILABLE")

        variant_bindings = list(context.step.input_bindings)
        foreign_bindings = [
            binding
            for binding in variant_bindings
            if binding.binding_type == "object_binding" and binding.owner == "user_b"
        ]
        if not foreign_bindings:
            return _inconclusive("BOLA_BINDING_UNAVAILABLE")

        variant_runtime, selected_foreign_values = _foreign_runtime(
            context,
            foreign_bindings,
        )
        if not selected_foreign_values:
            return _inconclusive("BOLA_BINDING_UNAVAILABLE")

        baseline_bindings = [
            binding.model_copy(update={"owner": "user_a"})
            if binding.binding_type == "object_binding" and binding.owner == "user_b"
            else binding
            for binding in variant_bindings
        ]
        try:
            baseline_request = bind_operation(
                operation=context.operation,
                bindings=baseline_bindings,
                runtime=context.runtime,
            )
            variant_request = bind_operation(
                operation=context.operation,
                bindings=variant_bindings,
                runtime=variant_runtime,
            )
        except BindingError:
            return _inconclusive("BOLA_BINDING_UNAVAILABLE")

        if baseline_request == variant_request:
            return _inconclusive("BOLA_BINDING_UNAVAILABLE")
        if "%" in baseline_request.path or "%" in variant_request.path:
            return _inconclusive("BOLA_PATH_UNSAFE")

        sensitive_values = _session_sensitive_values(session)

        baseline = _send(
            context,
            baseline_request,
            authorization=authorization,
            sensitive_values=sensitive_values,
        )
        variant = _send(
            context,
            variant_request,
            authorization=authorization,
            sensitive_values=sensitive_values,
        )
        evidence = _evidence(
            context,
            baseline_request,
            variant_request,
            baseline,
            variant,
        )

        if not baseline.is_success:
            return _inconclusive("BOLA_BASELINE_FAILED", evidence)
        if baseline.json_body is None:
            return _inconclusive("BOLA_RESPONSE_NOT_JSON", evidence)
        if variant.status_code in {401, 403, 404}:
            return ModuleOutcome(
                verdict=ModuleVerdict.NOT_FOUND,
                rule_id=RULE_ID,
                evidence=evidence,
                reason_code="BOLA_FOREIGN_OBJECT_REJECTED",
            )
        if variant.json_body is None:
            return _inconclusive("BOLA_RESPONSE_NOT_JSON", evidence)
        if not variant.is_success:
            return _inconclusive("BOLA_VARIANT_FAILED", evidence)

        matches = _foreign_object_matches(
            selected_foreign_values,
            variant.json_body,
        )
        if not matches:
            return ModuleOutcome(
                verdict=ModuleVerdict.NOT_FOUND,
                rule_id=RULE_ID,
                evidence=evidence,
                reason_code="BOLA_FOREIGN_OBJECT_NOT_IDENTIFIED",
            )

        matched_paths = tuple(path for path, _ in matches)
        evidence["matched_user_b_fields"] = matched_paths
        return ModuleOutcome(
            verdict=ModuleVerdict.VERIFIED,
            rule_id=RULE_ID,
            conditions=(VERIFIED_CONDITION,),
            affected_fields=tuple(
                AffectedField(
                    location="response",
                    field_path=path,
                    data_class=_data_class(object_type),
                )
                for path, object_type in matches
            ),
            evidence=evidence,
        )


def _send(
    context: ModuleExecutionContext,
    request: BoundRequest,
    *,
    authorization: str,
    sensitive_values: set[str],
) -> ResponseSnapshot:
    headers = {
        name: value
        for name, value in request.headers.items()
        if name.casefold() != "authorization"
    }
    headers["Authorization"] = authorization
    return context.client.request(
        "GET",
        urljoin(f"{context.base_url.rstrip('/')}/", request.path.lstrip("/")),
        module_id=MODULE_ID,
        headers=headers,
        params=request.query,
        json_body=request.json_body,
        sensitive_values=sensitive_values,
    )


def _foreign_object_matches(
    selected_values: dict[str, str],
    body: object,
) -> tuple[tuple[str, str], ...]:
    matches: dict[str, str] = {}
    for path, value in _scalar_fields(body):
        rendered = str(value)
        for object_type in sorted(selected_values):
            if rendered == selected_values[object_type]:
                matches.setdefault(path, object_type)
    return tuple(sorted(matches.items()))


def _foreign_runtime(
    context: ModuleExecutionContext,
    bindings: list[InputBinding],
) -> tuple[RuntimeContext, dict[str, str]]:
    runtime = copy.copy(context.runtime)
    runtime.object_ids = {
        actor_id: dict(object_types)
        for actor_id, object_types in context.runtime.object_ids.items()
    }
    user_b_objects = runtime.object_ids.setdefault("user_b", {})
    selected_values: dict[str, str] = {}
    for binding in bindings:
        object_type = binding.object_type
        if object_type is None:
            continue
        user_a_values = context.runtime.object_ids.get("user_a", {}).get(
            object_type,
            set(),
        )
        user_b_values = context.runtime.object_ids.get("user_b", {}).get(
            object_type,
            set(),
        )
        user_b_only = set(user_b_values) - set(user_a_values)
        if not user_b_only:
            continue
        user_b_objects[object_type] = user_b_only
        selected_values[object_type] = sorted(_reveal_values(user_b_only))[0]
    return runtime, selected_values


def _scalar_fields(value: object, path: str = "") -> Iterable[tuple[str, object]]:
    if isinstance(value, dict):
        for key in sorted(value, key=str):
            field_path = f"{path}.{key}" if path else str(key)
            yield from _scalar_fields(value[key], field_path)
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            field_path = f"{path}[{index}]" if path else f"[{index}]"
            yield from _scalar_fields(item, field_path)
    elif isinstance(value, (str, int, float)) and not isinstance(value, bool):
        yield path or "$", value


def _reveal_values(values: Iterable[object]) -> set[str]:
    revealed: set[str] = set()
    for value in values:
        reveal = getattr(value, "reveal", None)
        if callable(reveal):
            item = reveal()
        else:
            item = value
        if isinstance(item, str):
            revealed.add(item)
    return revealed


def _session_sensitive_values(session: object) -> set[str]:
    values: set[str] = set()
    token = getattr(session, "token", None)
    if token is not None:
        values.update(_reveal_values((token,)))
    cookies = getattr(session, "cookies", {})
    if isinstance(cookies, dict):
        values.update(_reveal_values(cookies.values()))
    return values


def _evidence(
    context: ModuleExecutionContext,
    baseline_request: BoundRequest,
    variant_request: BoundRequest,
    baseline: ResponseSnapshot,
    variant: ResponseSnapshot,
) -> _InMemoryEvidence:
    return _InMemoryEvidence(
        request=_InMemoryEvidence(
            operation_id=context.operation.operation_id,
            method="GET",
            baseline_path=baseline_request.path,
            variant_path=variant_request.path,
        ),
        baseline=_InMemoryEvidence(
            status_code=baseline.status_code,
            json_body=baseline.json_body,
            url=baseline.url,
        ),
        variant=_InMemoryEvidence(
            status_code=variant.status_code,
            json_body=variant.json_body,
            url=variant.url,
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


def _data_class(object_type: str) -> str:
    if object_type == "account":
        return "account"
    if object_type in {"transaction", "card"}:
        return "financial"
    return "other"
