from __future__ import annotations

import dataclasses
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


@pytest.mark.parametrize(
    ("method", "url", "module_id", "is_login", "is_state_change"),
    [
        ("GET", "http://vuln-bank.local/api/accounts", "AUTHN-001", False, False),
        ("GET", "http://vuln-bank.local/api/accounts", "TRANSACTION-001", False, False),
        ("GET", "http://vuln-bank.local/api/accounts", "UNKNOWN-001", False, False),
        ("GET", "http://vuln-bank.local/api/accounts", "BOLA-001", False, True),
        ("POST", "http://vuln-bank.local/api/login", None, True, True),
        ("GET", "http://vuln-bank.local/api/%2e%2e/admin", "BOLA-001", False, False),
    ],
)
def test_unsafe_requests_never_reach_transport(
    profile: TargetProfile, method: str, url: str, module_id: str | None, is_login: bool, is_state_change: bool
):
    calls = []
    client, budget = make_client(profile, lambda request: calls.append(request) or httpx.Response(200))

    with pytest.raises(PolicyViolation):
        client.request(
            method,
            url,
            module_id=module_id,
            is_login=is_login,
            is_state_change=is_state_change,
        )

    assert calls == []
    assert budget.requests_used == 0


@pytest.mark.parametrize(
    "headers",
    [
        {"Host": "attacker.local"},
        {"X-HTTP-Method-Override": "POST"},
        {"X-Original-URL": "/private/accounts"},
        {"Forwarded": "host=attacker.local;proto=https"},
        {"X-Forwarded-Host": "attacker.local"},
    ],
)
def test_routing_override_headers_never_reach_transport(profile: TargetProfile, headers: dict[str, str]):
    calls = []
    client, budget = make_client(profile, lambda request: calls.append(request) or httpx.Response(200))

    with pytest.raises(PolicyViolation):
        client.request(
            "GET",
            "http://vuln-bank.local/api/accounts",
            module_id="BOLA-001",
            headers=headers,
        )

    assert calls == []
    assert budget.requests_used == 0


def test_authorization_and_cookie_work_for_allowed_request_but_not_snapshot(profile: TargetProfile):
    received_headers = {}

    def handler(request: httpx.Request) -> httpx.Response:
        received_headers.update(request.headers)
        return httpx.Response(200, headers={"X-Trace": "safe"}, json={"ok": True})

    client, _ = make_client(profile, handler)
    snapshot = client.request(
        "GET",
        "http://vuln-bank.local/api/accounts",
        module_id="BOLA-001",
        headers={"Authorization": "Bearer token-a", "Cookie": "sid-a"},
        sensitive_values={"token-a", "sid-a"},
    )

    assert received_headers["authorization"] == "Bearer token-a"
    assert received_headers["cookie"] == "sid-a"
    assert "authorization" not in snapshot.headers
    assert "cookie" not in snapshot.headers


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


def test_preflight_authorizes_without_budget_or_transport(profile: TargetProfile):
    calls = []
    client, budget = make_client(
        profile,
        lambda request: calls.append(request) or httpx.Response(200),
    )

    client.preflight(
        "GET",
        "http://vuln-bank.local/api/accounts/acct-a-1",
        module_id="BOLA-001",
        headers={"Authorization": "Bearer token-a"},
    )

    assert calls == []
    assert budget.requests_used == 0


@pytest.mark.parametrize(
    ("url", "headers"),
    [
        ("http://vuln-bank.local/private/account", None),
        (
            "http://vuln-bank.local/api/accounts/acct-a-1",
            {"X-Original-URL": "/private/account"},
        ),
    ],
)
def test_preflight_rejects_policy_or_headers_without_budget_or_transport(
    profile: TargetProfile,
    url: str,
    headers: dict[str, str] | None,
):
    calls = []
    client, budget = make_client(
        profile,
        lambda request: calls.append(request) or httpx.Response(200),
    )

    with pytest.raises(PolicyViolation):
        client.preflight(
            "GET",
            url,
            module_id="BOLA-001",
            headers=headers,
        )

    assert calls == []
    assert budget.requests_used == 0


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


def test_redirect_following_can_be_disabled_for_exactly_one_transport(
    profile: TargetProfile,
):
    calls = []
    client, budget = make_client(
        profile,
        lambda request: calls.append(str(request.url))
        or httpx.Response(
            302,
            headers={"Location": "/api/final"},
            request=request,
        ),
    )

    snapshot = client.request(
        "GET",
        "http://vuln-bank.local/api/start",
        module_id="BOLA-001",
        follow_redirects=False,
    )

    assert calls == ["http://vuln-bank.local/api/start"]
    assert budget.requests_used == 1
    assert snapshot.status_code == 302
    assert snapshot.url == "http://vuln-bank.local/api/start"


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


def test_encoded_traversal_redirect_never_reaches_second_transport(profile: TargetProfile):
    calls = []
    client, budget = make_client(
        profile,
        lambda request: calls.append(str(request.url))
        or httpx.Response(302, headers={"Location": "/api/%2e%2e/admin"}, request=request),
    )

    with pytest.raises(PolicyViolation):
        client.request("GET", "http://vuln-bank.local/api/start", module_id="BOLA-001")

    assert calls == ["http://vuln-bank.local/api/start"]
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


def test_snapshot_keeps_raw_json_only_in_explicit_runtime_wrapper(
    profile: TargetProfile,
):
    raw_body = {
        "password": "custom-password-value",
        "token": "custom-token-value",
        "secret": "custom-secret-value",
    }
    client, _ = make_client(
        profile,
        lambda request: httpx.Response(200, json=raw_body),
    )

    snapshot = client.request(
        "GET",
        "http://vuln-bank.local/api/accounts",
        module_id="DATA-001",
    )

    assert snapshot.json_body == {
        "password": "[REDACTED]",
        "token": "[REDACTED]",
        "secret": "[REDACTED]",
    }
    assert snapshot.runtime_json_body is not None
    assert snapshot.runtime_json_body.reveal() == raw_body
    rendered = (
        repr(snapshot)
        + str(snapshot.runtime_json_body)
        + repr(dataclasses.asdict(snapshot))
        + json.dumps(dataclasses.asdict(snapshot))
    )
    for value in raw_body.values():
        assert value not in rendered


def test_login_response_consumer_receives_raw_response_before_snapshot_redaction(
    profile: TargetProfile,
):
    received: list[object] = []
    client, _ = make_client(
        profile,
        lambda request: httpx.Response(
            200,
            headers={"Set-Cookie": "sid-a=cookie-a; HttpOnly"},
            json={"access_token": "token-a"},
        ),
    )

    snapshot = client.request(
        "POST",
        "http://vuln-bank.local/api/login",
        is_login=True,
        is_state_change=False,
        login_response_consumer=lambda response: received.append(
            (response.json()["access_token"], dict(response.cookies))
        ),
    )

    assert received == [("token-a", {"sid-a": "cookie-a"})]
    assert snapshot.json_body is None
    assert snapshot.runtime_json_body is None
    assert "token-a" not in repr(snapshot)
    assert "sid-a" not in repr(snapshot)
    assert "cookie-a" not in repr(snapshot)


def test_login_snapshot_drops_custom_configured_token_field_after_consumer(
    profile: TargetProfile,
):
    received: list[str] = []
    client, _ = make_client(
        profile,
        lambda request: httpx.Response(200, json={"custom_session": "token-a"}),
    )

    snapshot = client.request(
        "POST",
        "http://vuln-bank.local/api/login",
        is_login=True,
        login_response_consumer=lambda response: received.append(
            response.json()["custom_session"]
        ),
    )

    assert received == ["token-a"]
    assert snapshot.json_body is None
    assert snapshot.runtime_json_body is None
    assert "token-a" not in repr(snapshot)


def test_login_response_consumer_is_rejected_before_non_login_transport(profile: TargetProfile):
    calls = []
    client, budget = make_client(
        profile, lambda request: calls.append(request) or httpx.Response(200)
    )

    with pytest.raises(PolicyViolation):
        client.request(
            "GET",
            "http://vuln-bank.local/api/accounts",
            module_id="BOLA-001",
            login_response_consumer=lambda response: None,
        )

    assert calls == []
    assert budget.requests_used == 0


def test_login_response_consumer_is_called_once_on_final_login_response(profile: TargetProfile):
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        if len(calls) == 1:
            return httpx.Response(302, headers={"Location": "/api/login"}, request=request)
        return httpx.Response(200, json={"access_token": "token-a"}, request=request)

    client, _ = make_client(profile, handler)
    received_statuses = []

    snapshot = client.request(
        "POST",
        "http://vuln-bank.local/api/login",
        is_login=True,
        login_response_consumer=lambda response: received_statuses.append(response.status_code),
    )

    assert received_statuses == [200]
    assert snapshot.json_body is None


def test_automatic_cookie_state_does_not_cross_login_requests(profile: TargetProfile):
    received_cookies: list[str | None] = []

    def handler(request: httpx.Request) -> httpx.Response:
        received_cookies.append(request.headers.get("cookie"))
        return httpx.Response(
            200,
            headers={"Set-Cookie": "sid=actor-a-cookie; HttpOnly"},
            json={"access_token": "token-a"},
        )

    client, _ = make_client(profile, handler)
    for _ in range(2):
        client.request(
            "POST",
            "http://vuln-bank.local/api/login",
            is_login=True,
            login_response_consumer=lambda response: response.json(),
        )

    assert received_cookies == [None, None]


def test_login_snapshot_redacts_custom_token_in_final_redirect_url(profile: TargetProfile):
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if calls == 1:
            return httpx.Response(
                302,
                headers={"Location": "/api/login?custom_session=token-a"},
                request=request,
            )
        return httpx.Response(200, json={"custom_session": "token-a"}, request=request)

    client, _ = make_client(profile, handler)
    snapshot = client.request(
        "POST",
        "http://vuln-bank.local/api/login",
        is_login=True,
        login_response_consumer=lambda response: response.json(),
    )

    assert snapshot.url == "[REDACTED]"
    assert "token-a" not in repr(snapshot)


def test_login_redirect_forwards_handshake_cookie_only_within_logical_request(
    profile: TargetProfile,
):
    received_cookies: list[str | None] = []

    def handler(request: httpx.Request) -> httpx.Response:
        received_cookies.append(request.headers.get("cookie"))
        if len(received_cookies) == 1:
            return httpx.Response(
                302,
                headers={
                    "Location": "/api/login",
                    "Set-Cookie": "handshake=required-cookie; HttpOnly",
                },
                request=request,
            )
        return httpx.Response(200, json={"access_token": "token-a"}, request=request)

    client, _ = make_client(profile, handler)
    snapshot = client.request(
        "POST",
        "http://vuln-bank.local/api/login",
        is_login=True,
        login_response_consumer=lambda response: response.json(),
    )

    assert snapshot.is_success is True
    assert received_cookies == [None, "handshake=required-cookie"]
