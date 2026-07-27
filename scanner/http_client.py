"""HTTPX transport wrapper that enforces scanner policy at every request hop."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping
from urllib.parse import urljoin

import httpx

from scanner.artifacts import REDACTED, Redactor, SENSITIVE_KEYS
from scanner.audit import AuditEvent, AuditSink
from scanner.policy import PolicyEnforcer, PolicyViolation, RequestBudget


ROUTING_OVERRIDE_HEADERS = frozenset(
    {
        "host",
        "authority",
        ":authority",
        "forwarded",
        "x-forwarded-host",
        "x-forwarded-proto",
        "x-forwarded-port",
        "x-forwarded-uri",
        "x-forwarded-url",
        "x-forwarded-prefix",
        "x-original-url",
        "x-original-uri",
        "x-rewrite-url",
        "x-http-method-override",
        "x-http-method",
        "x-method-override",
        "x-forwarded-method",
    }
)
RESPONSE_SENSITIVE_KEYS = frozenset(
    {
        "password",
        "passwd",
        "password_hash",
        "hashed_password",
        "token",
        "access_token",
        "refresh_token",
        "auth_token",
        "session_token",
        "api_key",
        "apikey",
        "secret",
        "client_secret",
        "pin",
        "cvv",
        "cvc",
        "card_security_code",
        "resident_number",
        "resident_registration_number",
        "rrn",
        "card_number",
        "credit_card_number",
        "pan",
        "account_number",
        "bank_account_number",
    }
)


class ScannerRequestError(Exception):
    """A sanitized transport failure that contains no target runtime values."""


class _RuntimeJsonBody:
    """Raw response JSON that requires deliberate in-memory access."""

    __slots__ = ("_value",)

    def __init__(self, value: object) -> None:
        self._value = value

    def reveal(self) -> object:
        return self._value

    def __repr__(self) -> str:
        return "[REDACTED]"

    __str__ = __repr__

    def __deepcopy__(self, memo: dict[int, object]) -> str:
        return "[REDACTED]"


@dataclass(frozen=True)
class ResponseSnapshot:
    status_code: int
    headers: Mapping[str, str]
    cookies: Mapping[str, str]
    json_body: object | None
    url: str
    runtime_json_body: _RuntimeJsonBody | None = field(
        default=None,
        repr=False,
        compare=False,
    )

    @property
    def is_success(self) -> bool:
        return 200 <= self.status_code < 300


class SafeHttpClient:
    def __init__(
        self,
        *,
        policy: PolicyEnforcer,
        budget: RequestBudget,
        transport: httpx.BaseTransport | None = None,
        redactor: Redactor | None = None,
        audit_sink: AuditSink | None = None,
    ) -> None:
        self._policy = policy
        self._budget = budget
        self._client = httpx.Client(transport=transport, follow_redirects=False)
        self._redactor = redactor or Redactor()
        self._audit_sink = audit_sink

    def request(
        self,
        method: str,
        url: str,
        *,
        module_id: str | None = None,
        is_login: bool = False,
        is_state_change: bool = False,
        headers: Mapping[str, str] | None = None,
        params: Mapping[str, object] | None = None,
        json_body: object | None = None,
        sensitive_values: set[str] | None = None,
        login_response_consumer: Callable[[httpx.Response], None] | None = None,
        follow_redirects: bool = True,
    ) -> ResponseSnapshot:
        if login_response_consumer is not None and not is_login:
            self._emit("POLICY_DENIED")
            raise PolicyViolation("request violates scanner safety policy")

        current_url = url
        current_params = params
        values = sensitive_values if sensitive_values is not None else set()
        self._client.cookies.clear()
        try:
            while True:
                self.preflight(
                    method,
                    current_url,
                    module_id=module_id,
                    is_login=is_login,
                    is_state_change=is_state_change,
                    headers=headers,
                )
                self._budget.reserve()
                try:
                    response = self._client.request(
                        method,
                        current_url,
                        headers=headers,
                        params=current_params,
                        json=json_body,
                    )
                except httpx.HTTPError:
                    self._emit("REQUEST_FAILED")
                    raise ScannerRequestError("scanner request failed") from None

                if response.is_redirect and response.headers.get("location"):
                    if not follow_redirects:
                        return self._snapshot(
                            response,
                            values,
                            hide_login_response=is_login,
                        )
                    current_url = urljoin(str(response.url), response.headers["location"])
                    current_params = None
                    continue

                if login_response_consumer is not None and not response.is_redirect:
                    login_response_consumer(response)
                    login_response_consumer = None
                return self._snapshot(response, values, hide_login_response=is_login)
        finally:
            self._client.cookies.clear()

    def preflight(
        self,
        method: str,
        url: str,
        *,
        module_id: str | None = None,
        is_login: bool = False,
        is_state_change: bool = False,
        headers: Mapping[str, str] | None = None,
    ) -> None:
        """Authorize a request without cancellation, rate, budget, or transport work."""

        try:
            self._validate_headers(headers)
            self._policy.authorize(
                method,
                url,
                module_id=module_id,
                is_login=is_login,
                is_state_change=is_state_change,
            )
        except PolicyViolation:
            self._emit("POLICY_DENIED")
            raise

    def ensure_capacity(self, count: int) -> None:
        """Check shared request capacity without reserving a transport request."""

        self._budget.ensure_capacity(count)

    def _snapshot(
        self,
        response: httpx.Response,
        sensitive_values: set[str],
        *,
        hide_login_response: bool = False,
    ) -> ResponseSnapshot:
        if hide_login_response:
            body: object | None = None
            runtime_body: _RuntimeJsonBody | None = None
            clean_headers: Mapping[str, str] = {}
        else:
            try:
                raw_body = response.json()
            except (json.JSONDecodeError, UnicodeDecodeError):
                body = None
                runtime_body = None
            else:
                body = self._redactor.redact(
                    _redact_response_sensitive_fields(raw_body),
                    sensitive_values,
                )
                runtime_body = _RuntimeJsonBody(raw_body)
            clean_headers = {
                key.casefold(): self._redactor.redact(value, sensitive_values)
                for key, value in response.headers.items()
                if key.casefold() not in SENSITIVE_KEYS
            }
        return ResponseSnapshot(
            status_code=response.status_code,
            headers=clean_headers,
            cookies={},
            json_body=body,
            url="[REDACTED]"
            if hide_login_response
            else self._redactor.redact(str(response.url), sensitive_values),
            runtime_json_body=runtime_body,
        )

    @staticmethod
    def _validate_headers(headers: Mapping[str, str] | None) -> None:
        if headers is not None and any(
            name.casefold() in ROUTING_OVERRIDE_HEADERS for name in headers
        ):
            raise PolicyViolation("request violates scanner safety policy")

    def _emit(self, code: str) -> None:
        if self._audit_sink is not None:
            self._audit_sink.emit(
                AuditEvent(
                    code=code,
                    level="WARNING",
                    job_id=None,
                    scan_id=None,
                    operation_id=None,
                    module_id=None,
                    details={},
                )
            )


def _redact_response_sensitive_fields(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {
            key: (
                REDACTED
                if (
                    isinstance(key, str)
                    and _is_response_sensitive_key(key)
                    and not isinstance(item, (Mapping, list, tuple))
                )
                else _redact_response_sensitive_fields(item)
            )
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [_redact_response_sensitive_fields(item) for item in value]
    return value


def _is_response_sensitive_key(key: str) -> bool:
    snake = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", key)
    normalized = re.sub(r"[^a-z0-9]+", "_", snake.casefold()).strip("_")
    return (
        normalized in RESPONSE_SENSITIVE_KEYS
        or normalized.endswith("_password")
        or normalized.endswith("_password_hash")
        or normalized.endswith("_api_key")
        or normalized.endswith("_secret")
        or normalized.endswith("_pin")
    )
