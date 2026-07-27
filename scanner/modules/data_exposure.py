"""Fixed-rule sensitive data exposure probe."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal
from urllib.parse import urljoin

from scanner.artifacts import Redactor
from scanner.contracts import AffectedField
from scanner.http_client import ResponseSnapshot
from scanner.modules.base import (
    BindingError,
    BoundRequest,
    ModuleExecutionContext,
    ModuleOutcome,
    ModuleVerdict,
    bind_operation,
)
from scanner.policy import PolicyViolation


RULE_ID = "VERIFY-DATA-001"
VERIFIED_CONDITION = "DATA_SENSITIVE_FIELD_UNMASKED"
MODULE_ID = "DATA-001"
DataClass = Literal["identity", "financial", "authentication"]

@dataclass(frozen=True)
class SensitiveField:
    field_path: str
    data_class: DataClass


@dataclass(frozen=True)
class _SensitiveMatch:
    field_path: str
    data_class: DataClass
    value: str


class _InMemoryEvidence(dict[str, object]):
    """Evidence remains available in memory without rendering raw values."""

    def __repr__(self) -> str:
        return "_InMemoryEvidence([REDACTED])"

    __str__ = __repr__


def find_sensitive_fields(value: object) -> list[SensitiveField]:
    return [
        SensitiveField(match.field_path, match.data_class)
        for match in _sensitive_matches(value)
    ]


class DataExposureModule:
    def run(self, context: ModuleExecutionContext) -> ModuleOutcome:
        if context.operation.method != "GET":
            return _inconclusive("DATA_NON_GET_OPERATION")
        authorization = _authorization(context)
        if authorization is None:
            return _inconclusive("DATA_SESSION_UNAVAILABLE")
        try:
            request = bind_operation(
                operation=context.operation,
                bindings=list(context.step.input_bindings),
                runtime=context.runtime,
            )
        except BindingError:
            return _inconclusive("DATA_BINDING_UNAVAILABLE")

        url, headers = _prepare_request(
            context,
            request,
            authorization=authorization,
        )
        try:
            context.client.preflight(
                "GET",
                url,
                module_id=MODULE_ID,
                headers=headers,
            )
        except PolicyViolation:
            return _inconclusive("DATA_POLICY_PREFLIGHT_FAILED")

        response = context.client.request(
            "GET",
            url,
            module_id=MODULE_ID,
            headers=headers,
            params=request.query,
            json_body=request.json_body,
            sensitive_values=context.runtime.sensitive_values(),
            follow_redirects=False,
        )
        evidence = _evidence(context, response)
        body = _runtime_json_body(response)
        if not response.is_success or body is None:
            return _inconclusive("DATA_RESPONSE_UNAVAILABLE", evidence)

        matches = _sensitive_matches(body)
        if not matches:
            return ModuleOutcome(
                verdict=ModuleVerdict.NOT_FOUND,
                rule_id=RULE_ID,
                evidence=evidence,
                reason_code="DATA_FORBIDDEN_FIELD_ABSENT",
            )

        replacements = {
            value: "{runtime_value}" for value in context.runtime.sensitive_values()
        }
        replacements.update(
            {match.value: "{sensitive_value}" for match in matches if match.value}
        )
        affected: dict[str, DataClass] = {}
        for match in matches:
            path = _sanitize_path(match.field_path, replacements)
            affected.setdefault(path, match.data_class)
        return ModuleOutcome(
            verdict=ModuleVerdict.VERIFIED,
            rule_id=RULE_ID,
            conditions=(VERIFIED_CONDITION,),
            affected_fields=tuple(
                AffectedField(
                    location="response",
                    field_path=path,
                    data_class=data_class,
                )
                for path, data_class in sorted(affected.items())
            ),
            evidence=evidence,
        )


def _sensitive_matches(value: object) -> list[_SensitiveMatch]:
    matches: dict[tuple[str, DataClass], _SensitiveMatch] = {}
    for path, item in _scalar_fields(value):
        classified = _classify(path[-1], item)
        if classified is None:
            continue
        data_class, rendered = classified
        field_path = _render_path(path)
        matches.setdefault(
            (field_path, data_class),
            _SensitiveMatch(field_path, data_class, rendered),
        )
    return [matches[key] for key in sorted(matches)]


def _classify(key: str, value: object) -> tuple[DataClass, str] | None:
    normalized_key = _normalize_key(key)
    if normalized_key == "id" or normalized_key.endswith("_id"):
        return None
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        return None
    rendered = str(value).strip()
    if not rendered or _is_masked(rendered):
        return None

    digits = re.sub(r"[\s-]", "", rendered)
    if normalized_key in {"card_number", "credit_card_number", "pan"}:
        if digits.isdigit() and 13 <= len(digits) <= 19 and _passes_luhn(digits):
            return "financial", rendered
        return None
    if normalized_key in {"account_number", "bank_account_number"}:
        if digits.isdigit() and 8 <= len(digits) <= 20:
            return "financial", rendered
        return None
    if normalized_key in {
        "resident_number",
        "resident_registration_number",
        "rrn",
    }:
        if digits.isdigit() and len(digits) == 13:
            return "identity", rendered
        return None
    if normalized_key in {"cvv", "cvc", "card_security_code"}:
        if digits.isdigit() and len(digits) in {3, 4}:
            return "financial", rendered
        return None
    if normalized_key == "pin" or normalized_key.endswith("_pin"):
        if digits.isdigit() and 4 <= len(digits) <= 6:
            return "authentication", rendered
        return None
    if (
        normalized_key in {"password", "passwd", "password_hash", "hashed_password"}
        or normalized_key.endswith("_password")
        or normalized_key.endswith("_password_hash")
    ):
        return "authentication", rendered
    if (
        normalized_key in {
            "token",
            "access_token",
            "refresh_token",
            "auth_token",
            "session_token",
            "api_key",
            "apikey",
            "secret",
            "client_secret",
        }
        or normalized_key.endswith("_api_key")
        or normalized_key.endswith("_secret")
    ):
        return "authentication", rendered
    return None


def _scalar_fields(
    value: object,
    path: tuple[str, ...] = (),
):
    if isinstance(value, dict):
        for key in sorted(value, key=str):
            yield from _scalar_fields(value[key], (*path, str(key)))
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _scalar_fields(item, (*path, "[]"))
    elif isinstance(value, (str, int, float)) and not isinstance(value, bool):
        yield path or ("$",), value


def _normalize_key(key: str) -> str:
    snake = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", key)
    return re.sub(r"[^a-z0-9]+", "_", snake.casefold()).strip("_")


def _is_masked(value: str) -> bool:
    lowered = value.casefold()
    return (
        any(marker in value for marker in ("*", "•", "●"))
        or "redacted" in lowered
        or "masked" in lowered
        or re.search(r"x{2,}", lowered) is not None
    )


def _passes_luhn(digits: str) -> bool:
    total = 0
    parity = len(digits) % 2
    for index, character in enumerate(digits):
        number = int(character)
        if index % 2 == parity:
            number *= 2
            if number > 9:
                number -= 9
        total += number
    return total % 10 == 0


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


def _prepare_request(
    context: ModuleExecutionContext,
    request: BoundRequest,
    *,
    authorization: str,
) -> tuple[str, dict[str, str]]:
    headers = {
        name: value
        for name, value in request.headers.items()
        if name.casefold() != "authorization"
    }
    headers["Authorization"] = authorization
    return (
        urljoin(
            f"{context.base_url.rstrip('/')}/",
            request.path.lstrip("/"),
        ),
        headers,
    )


def _runtime_json_body(snapshot: ResponseSnapshot) -> object | None:
    if snapshot.runtime_json_body is None:
        return None
    return snapshot.runtime_json_body.reveal()


def _evidence(
    context: ModuleExecutionContext,
    response: ResponseSnapshot,
) -> _InMemoryEvidence:
    values = set(context.runtime.sensitive_values())
    body = _runtime_json_body(response)
    if body is not None:
        values.update(match.value for match in _sensitive_matches(body))
    redactor = Redactor()
    return _InMemoryEvidence(
        request=_InMemoryEvidence(
            operation_id=context.operation.operation_id,
            method="GET",
        ),
        response=_InMemoryEvidence(
            status_code=response.status_code,
            json_body=redactor.redact(response.json_body, values),
            url=redactor.redact(response.url, values),
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
