from __future__ import annotations

import json

import httpx
import pytest

from scanner.audit import InMemoryAuditSink
from scanner.artifacts import Redactor
from scanner.contracts import TargetProfile
from scanner.http_client import SafeHttpClient, ScannerRequestError
from scanner.integration.backend_client import FakeBackendClient
from scanner.policy import CancellationGuard, PolicyEnforcer, PolicyViolation, RequestBudget


@pytest.fixture
def profile() -> TargetProfile:
    return TargetProfile.model_validate(
        {
            "schema_version": "1.1",
            "scan_id": "scan-001",
            "target": {
                "base_url": "http://vuln-bank.local",
                "allowed_paths": ["/api/*"],
                "allowed_methods": ["GET"],
            },
            "discovery": {"sources": ["openapi"], "max_depth": 1},
            "authentication": {
                "login": {
                    "method": "POST",
                    "path": "/api/login",
                    "content_type": "application/json",
                    "username_field": "username",
                    "password_field": "password",
                    "session": {"type": "bearer", "token_field": "access_token"},
                },
                "actors": [
                    {"actor_id": "user_a", "username_env": "A_U", "password_env": "A_P"},
                    {"actor_id": "user_b", "username_env": "B_U", "password_env": "B_P"},
                ],
            },
            "safety_policy": {
                "max_requests": 3,
                "requests_per_second": 100,
                "state_change_policy": "deny",
                "approved_modules": ["authz", "input_validation", "data_exposure"],
            },
        }
    )


def make_client(
    profile: TargetProfile, handler, *, backend: FakeBackendClient | None = None
) -> tuple[SafeHttpClient, RequestBudget]:
    backend = backend or FakeBackendClient()
    budget = RequestBudget(
        max_requests=3,
        requests_per_second=100,
        cancellation_guard=CancellationGuard(backend),
        job_id="job-001",
    )
    return (
        SafeHttpClient(
            policy=PolicyEnforcer(profile),
            budget=budget,
            transport=httpx.MockTransport(handler),
            redactor=Redactor(),
            audit_sink=InMemoryAuditSink(),
        ),
        budget,
    )


def test_rejected_policy_never_reaches_transport(profile: TargetProfile):
    calls = []
    client, budget = make_client(profile, lambda request: calls.append(request) or httpx.Response(200))

    with pytest.raises(PolicyViolation):
        client.request("POST", "http://vuln-bank.local/api/accounts", module_id="BOLA-001")

    assert calls == []
    assert budget.requests_used == 0


def test_allowed_get_reaches_transport_once_and_consumes_budget(profile: TargetProfile):
    calls = []
    client, budget = make_client(
        profile,
        lambda request: calls.append(request) or httpx.Response(200, json={"balance": 10}),
    )

    snapshot = client.request("GET", "http://vuln-bank.local/api/accounts", module_id="BOLA-001")

    assert len(calls) == 1
    assert budget.requests_used == 1
    assert snapshot.is_success is True
    assert snapshot.json_body == {"balance": 10}


def test_allowed_same_origin_redirect_is_reauthorized_and_consumes_second_request(
    profile: TargetProfile,
):
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        if request.url.path == "/api/start":
            return httpx.Response(302, headers={"Location": "/api/final"}, request=request)
        return httpx.Response(200, json={"ok": True}, request=request)

    client, budget = make_client(profile, handler)
    snapshot = client.request("GET", "http://vuln-bank.local/api/start", module_id="BOLA-001")

    assert calls == ["http://vuln-bank.local/api/start", "http://vuln-bank.local/api/final"]
    assert budget.requests_used == 2
    assert snapshot.url == "http://vuln-bank.local/api/final"


@pytest.mark.parametrize("location", ["http://attacker.local/api/final", "/private/final"])
def test_rejected_redirect_never_reaches_second_transport(
    profile: TargetProfile, location: str
):
    calls = []
    client, budget = make_client(
        profile,
        lambda request: calls.append(request) or httpx.Response(302, headers={"Location": location}),
    )

    with pytest.raises(PolicyViolation):
        client.request("GET", "http://vuln-bank.local/api/start", module_id="BOLA-001")

    assert len(calls) == 1
    assert budget.requests_used == 1


def test_cancellation_before_redirect_hop_prevents_second_transport(profile: TargetProfile):
    backend = FakeBackendClient()
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        backend.cancel("job-001")
        return httpx.Response(302, headers={"Location": "/api/final"}, request=request)

    client, budget = make_client(profile, handler, backend=backend)

    with pytest.raises(Exception, match="cancelled"):
        client.request("GET", "http://vuln-bank.local/api/start", module_id="BOLA-001")

    assert len(calls) == 1
    assert budget.requests_used == 1


def test_network_errors_are_sanitized_and_never_leak_credentials(profile: TargetProfile):
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("token-a Cookie=sid-a", request=request)

    client, _ = make_client(profile, handler)

    with pytest.raises(ScannerRequestError) as error:
        client.request(
            "GET",
            "http://vuln-bank.local/api/accounts",
            module_id="BOLA-001",
            headers={"Authorization": "Bearer token-a", "Cookie": "sid-a"},
            sensitive_values={"token-a", "sid-a"},
        )

    rendered = str(error.value)
    assert "token-a" not in rendered
    assert "sid-a" not in rendered
    assert "Cookie" not in rendered


def test_snapshot_never_exposes_authorization_or_cookie_headers(profile: TargetProfile):
    client, _ = make_client(
        profile,
        lambda request: httpx.Response(
            200,
            headers={"Authorization": "Bearer token-a", "Cookie": "sid-a", "X-Trace": "safe"},
            json={"access_token": "token-a"},
        ),
    )

    snapshot = client.request(
        "GET",
        "http://vuln-bank.local/api/accounts",
        module_id="BOLA-001",
        sensitive_values={"token-a", "sid-a"},
    )

    rendered = json.dumps({"headers": snapshot.headers, "body": snapshot.json_body})
    assert "authorization" not in rendered.casefold()
    assert "cookie" not in rendered.casefold()
    assert "token-a" not in rendered
    assert snapshot.headers["x-trace"] == "safe"
