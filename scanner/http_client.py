"""HTTPX transport wrapper that enforces scanner policy at every request hop."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Mapping
from urllib.parse import urljoin

import httpx

from scanner.artifacts import Redactor, SENSITIVE_KEYS
from scanner.audit import AuditEvent, AuditSink
from scanner.policy import PolicyEnforcer, PolicyViolation, RequestBudget


class ScannerRequestError(Exception):
    """A sanitized transport failure that contains no target runtime values."""


@dataclass(frozen=True)
class ResponseSnapshot:
    status_code: int
    headers: Mapping[str, str]
    cookies: Mapping[str, str]
    json_body: object | None
    url: str

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
    ) -> ResponseSnapshot:
        current_url = url
        current_params = params
        values = sensitive_values or set()

        while True:
            try:
                self._policy.authorize(
                    method,
                    current_url,
                    module_id=module_id,
                    is_login=is_login,
                    is_state_change=is_state_change,
                )
            except PolicyViolation:
                self._emit("POLICY_DENIED")
                raise
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
                current_url = urljoin(str(response.url), response.headers["location"])
                current_params = None
                continue
            return self._snapshot(response, values)

    def _snapshot(self, response: httpx.Response, sensitive_values: set[str]) -> ResponseSnapshot:
        try:
            body: object | None = response.json()
        except (json.JSONDecodeError, UnicodeDecodeError):
            body = None
        clean_headers = {
            key.casefold(): self._redactor.redact(value, sensitive_values)
            for key, value in response.headers.items()
            if key.casefold() not in SENSITIVE_KEYS
        }
        return ResponseSnapshot(
            status_code=response.status_code,
            headers=clean_headers,
            cookies={},
            json_body=self._redactor.redact(body, sensitive_values),
            url=self._redactor.redact(str(response.url), sensitive_values),
        )

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
