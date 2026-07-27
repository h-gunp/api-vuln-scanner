from __future__ import annotations

import dataclasses
import json
import traceback

import httpx
import pytest
from pydantic import TypeAdapter
from pydantic_core import PydanticSerializationError

from scanner.audit import InMemoryAuditSink
from scanner.auth.session_manager import (
    ActorSession,
    AuthenticationError,
    RuntimeContext,
    SessionManager,
)
from scanner.contracts import TargetProfile
from scanner.http_client import SafeHttpClient
from scanner.integration.backend_client import FakeBackendClient
from scanner.policy import CancellationGuard, PolicyEnforcer, RequestBudget


def target_profile(*, token_field: str = "access_token") -> TargetProfile:
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
                    "session": {"type": "bearer", "token_field": token_field},
                },
                "actors": [
                    {
                        "actor_id": "user_a",
                        "username_env": "USER_A_USERNAME",
                        "password_env": "USER_A_PASSWORD",
                    },
                    {
                        "actor_id": "user_b",
                        "username_env": "USER_B_USERNAME",
                        "password_env": "USER_B_PASSWORD",
                    },
                ],
            },
            "safety_policy": {
                "max_requests": 10,
                "requests_per_second": 1000,
                "state_change_policy": "deny",
                "approved_modules": ["authz", "input_validation", "data_exposure"],
            },
        }
    )


def make_manager(handler):
    profile = target_profile()
    audit_sink = InMemoryAuditSink()
    client = SafeHttpClient(
        policy=PolicyEnforcer(profile),
        budget=RequestBudget(
            max_requests=10,
            requests_per_second=1000,
            cancellation_guard=CancellationGuard(FakeBackendClient()),
            job_id="job-001",
        ),
        transport=httpx.MockTransport(handler),
        audit_sink=audit_sink,
    )
    return profile, SessionManager(client), audit_sink


@pytest.fixture(autouse=True)
def actor_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("USER_A_USERNAME", "user-a")
    monkeypatch.setenv("USER_A_PASSWORD", "pw-a")
    monkeypatch.setenv("USER_B_USERNAME", "user-b")
    monkeypatch.setenv("USER_B_PASSWORD", "pw-b")


def test_authenticate_keeps_actor_sessions_and_credentials_runtime_only():
    received_bodies: list[dict[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        received_bodies.append(json.loads(request.content))
        username = received_bodies[-1]["username"]
        return httpx.Response(200, json={"access_token": f"token-{username[-1]}"})

    profile, manager, audit_sink = make_manager(handler)

    runtime = manager.authenticate(profile)

    assert set(runtime.sessions) == {"user_a", "user_b"}
    assert runtime.sessions["user_a"].authorization_headers() == {
        "Authorization": "Bearer token-a"
    }
    assert runtime.sessions["user_b"].authorization_headers() == {
        "Authorization": "Bearer token-b"
    }
    assert received_bodies == [
        {"username": "user-a", "password": "pw-a"},
        {"username": "user-b", "password": "pw-b"},
    ]
    assert runtime.sensitive_values() >= {
        "user-a",
        "user-b",
        "pw-a",
        "pw-b",
        "token-a",
        "token-b",
    }

    rendered = repr(runtime.sessions["user_a"])
    assert "token-a" not in rendered
    assert "user-a" not in rendered
    assert "token-a" not in repr(runtime)
    assert "token-a" not in json.dumps(audit_sink.events, default=str)


@pytest.mark.parametrize(
    "missing_name",
    ["USER_A_USERNAME", "USER_A_PASSWORD", "USER_B_USERNAME", "USER_B_PASSWORD"],
)
def test_authenticate_rejects_missing_environment_credentials_without_leaking_values(
    monkeypatch: pytest.MonkeyPatch, missing_name: str
):
    monkeypatch.delenv(missing_name)
    profile, manager, _ = make_manager(lambda request: httpx.Response(200))

    with pytest.raises(AuthenticationError, match="^runtime authentication failed$") as error:
        manager.authenticate(profile)

    assert missing_name not in str(error.value)
    assert "user-a" not in str(error.value)
    assert "pw-a" not in str(error.value)


@pytest.mark.parametrize(
    "response",
    [
        lambda request: httpx.Response(401, json={"detail": "user-a / pw-a denied"}),
        lambda request: httpx.Response(200, json={"message": "no token-a here"}),
        lambda request: httpx.Response(200, content=b"token-a is not JSON"),
    ],
)
def test_authenticate_sanitizes_failed_or_malformed_login_responses(response):
    profile, manager, _ = make_manager(response)

    with pytest.raises(AuthenticationError, match="^runtime authentication failed$") as error:
        manager.authenticate(profile)

    rendered = str(error.value)
    assert "user-a" not in rendered
    assert "pw-a" not in rendered
    assert "token-a" not in rendered


def test_authenticate_redacts_transport_exception_details():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("user-a pw-a token-a", request=request)

    profile, manager, _ = make_manager(handler)

    with pytest.raises(AuthenticationError, match="^runtime authentication failed$") as error:
        manager.authenticate(profile)

    assert str(error.value) == "runtime authentication failed"


def test_authenticate_exception_has_no_raw_context_cause_or_traceback_values():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"user-a pw-a token-a not-json")

    profile, manager, _ = make_manager(handler)

    with pytest.raises(AuthenticationError) as error:
        manager.authenticate(profile)

    rendered = "".join(traceback.format_exception(error.value))
    assert error.value.__context__ is None
    assert error.value.__cause__ is None
    assert "user-a" not in rendered
    assert "pw-a" not in rendered
    assert "token-a" not in rendered


def test_authenticate_uses_final_redirect_login_response():
    requests = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal requests
        requests += 1
        if requests == 1:
            return httpx.Response(302, headers={"Location": "/api/login"}, request=request)
        return httpx.Response(200, json={"access_token": "token-a"}, request=request)

    profile, manager, _ = make_manager(handler)

    runtime = manager.authenticate(profile)

    assert requests == 3
    assert runtime.sessions["user_a"].authorization_headers() == {
        "Authorization": "Bearer token-a"
    }


def test_authenticate_drops_incidental_login_cookies_for_bearer_sessions():
    observed_requests: list[tuple[str, str | None]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        username = json.loads(request.content)["username"]
        observed_requests.append((username, request.headers.get("cookie")))
        return httpx.Response(
            200,
            headers={"Set-Cookie": "sid=incidental-cookie; HttpOnly"},
            json={"access_token": f"token-{username[-1]}"},
        )

    profile, manager, _ = make_manager(handler)

    runtime = manager.authenticate(profile)

    assert runtime.sessions["user_a"].cookies == {}
    assert runtime.sessions["user_a"].authorization_headers() == {
        "Authorization": "Bearer token-a"
    }
    assert "incidental-cookie" not in runtime.sensitive_values()
    assert observed_requests == [("user-a", None), ("user-b", None)]


def test_authenticate_supports_custom_token_field_without_snapshot_leakage():
    profile = target_profile(token_field="custom_session")
    client = SafeHttpClient(
        policy=PolicyEnforcer(profile),
        budget=RequestBudget(max_requests=10, requests_per_second=1000),
        transport=httpx.MockTransport(
            lambda request: httpx.Response(200, json={"custom_session": "token-a"})
        ),
    )

    runtime = SessionManager(client).authenticate(profile)

    assert runtime.sessions["user_a"].authorization_headers() == {
        "Authorization": "Bearer token-a"
    }


def test_collect_response_keeps_object_ids_and_examples_private():
    profile, manager, _ = make_manager(lambda request: httpx.Response(200))
    runtime = RuntimeContext(scan_id=profile.scan_id)

    manager.collect_response(
        runtime,
        actor_id="user_b",
        operation_id="GET:/api/accounts",
        body={
            "items": [{"account_id": "acct-b-1"}],
            "next_page": 2,
            "nested": {"transaction_id": 41, "card_id": "card-b-1"},
        },
        observed_query={"page": "1"},
    )

    assert runtime.object_ids["user_b"]["account"] == {"acct-b-1"}
    assert runtime.object_ids["user_b"]["transaction"] == {"41"}
    assert runtime.object_ids["user_b"]["card"] == {"card-b-1"}
    assert runtime.parameter_examples[("GET:/api/accounts", "query", "page")] == {"1"}
    assert runtime.sensitive_values() >= {"acct-b-1", "41", "card-b-1", "1"}

    assert "acct-b-1" not in repr(runtime)
    assert "card-b-1" not in repr(runtime)
    with pytest.raises(TypeError):
        json.dumps(runtime)
    with pytest.raises(PydanticSerializationError):
        TypeAdapter(RuntimeContext).dump_json(runtime)


def test_actor_session_hides_cookie_and_token_from_repr_and_serialization():
    session = ActorSession(
        actor_id="user_a",
        token="token-a",
        cookies={"sid": "cookie-a"},
    )

    assert "token-a" not in repr(session)
    assert "cookie-a" not in repr(session)
    with pytest.raises(PydanticSerializationError):
        TypeAdapter(ActorSession).dump_json(session)


def test_asdict_and_json_redact_runtime_secret_values_while_runtime_access_works():
    profile, manager, _ = make_manager(
        lambda request: httpx.Response(200, json={"access_token": "token-a"})
    )
    runtime = manager.authenticate(profile)
    manager.collect_response(
        runtime,
        actor_id="user_b",
        operation_id="GET:/api/accounts",
        body={"account_id": "acct-b-1"},
        observed_query={"page": "1"},
    )

    as_dict = dataclasses.asdict(runtime)
    serialized = json.dumps(as_dict, default=list, skipkeys=True)

    for value in ("user-a", "pw-a", "token-a", "acct-b-1", '"1"'):
        assert value not in repr(as_dict)
        assert value not in serialized
    assert runtime.sessions["user_a"].authorization_headers() == {
        "Authorization": "Bearer token-a"
    }
    assert runtime.sensitive_values() >= {"user-a", "pw-a", "token-a", "acct-b-1", "1"}
