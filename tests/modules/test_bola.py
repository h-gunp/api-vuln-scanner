from __future__ import annotations

from typing import cast

import httpx
import pytest

from scanner.auth.session_manager import ActorSession, RuntimeContext, SessionManager
from scanner.contracts import (
    InputBinding,
    InputField,
    Operation,
    ScanStep,
    TargetEndpoint,
    TargetProfile,
)
from scanner.http_client import SafeHttpClient
from scanner.modules.base import ModuleExecutionContext, ModuleVerdict
from scanner.modules.bola import BolaModule
from scanner.policy import PolicyEnforcer, RequestBudget


def target_profile() -> TargetProfile:
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
                "max_requests": 10,
                "requests_per_second": 1000,
                "state_change_policy": "deny",
                "approved_modules": ["authz"],
            },
        }
    )


def account_operation(*, method: str = "GET") -> Operation:
    return Operation(
        operation_id="get-account",
        method=method,
        path_template="/api/accounts/{account_id}",
        inputs=[InputField(location="path", field_path="account_id", type="string")],
        outputs=[],
    )


def account_step(*, owner: str = "user_b", method: str = "GET") -> ScanStep:
    return ScanStep(
        order=1,
        candidate_id="candidate-bola",
        module_id="BOLA-001",
        target_operation_id="get-account",
        target_endpoint=TargetEndpoint(
            method=method,
            path_template="/api/accounts/{account_id}",
        ),
        input_bindings=[
            InputBinding(
                parameter="account_id",
                location="path",
                binding_type="object_binding",
                object_type="account",
                owner=owner,
            )
        ],
    )


def discovered_runtime() -> RuntimeContext:
    runtime = RuntimeContext(
        scan_id="scan-001",
        sessions={
            "user_a": ActorSession(actor_id="user_a", token="token-a"),
            "user_b": ActorSession(actor_id="user_b", token="token-b"),
        },
    )
    collector = SessionManager(cast(SafeHttpClient, None))
    collector.collect_response(
        runtime,
        actor_id="user_a",
        operation_id="list-accounts",
        body={"account_id": "acct-a-1"},
    )
    collector.collect_response(
        runtime,
        actor_id="user_b",
        operation_id="list-accounts",
        body={"account_id": "acct-b-1"},
    )
    return runtime


def execution_context(
    handler,
    *,
    runtime: RuntimeContext | None = None,
    operation: Operation | None = None,
    step: ScanStep | None = None,
) -> ModuleExecutionContext:
    profile = target_profile()
    return ModuleExecutionContext(
        scan_id=profile.scan_id,
        base_url=profile.target.base_url,
        operation=operation or account_operation(),
        step=step or account_step(),
        runtime=runtime or discovered_runtime(),
        client=SafeHttpClient(
            policy=PolicyEnforcer(profile),
            budget=RequestBudget(max_requests=10, requests_per_second=1000),
            transport=httpx.MockTransport(handler),
        ),
    )


def test_bola_verifies_only_when_variant_returns_identifiable_user_b_data():
    requests: list[tuple[str, str | None]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append((request.url.path, request.headers.get("authorization")))
        if request.url.path.endswith("acct-a-1"):
            return httpx.Response(
                200,
                json={"account": {"account_id": "acct-a-1", "owner": "A"}},
            )
        return httpx.Response(
            200,
            json={"account": {"account_id": "acct-b-1", "owner": "B"}},
        )

    outcome = BolaModule().run(execution_context(handler))

    assert outcome.verdict is ModuleVerdict.VERIFIED
    assert outcome.rule_id == "VERIFY-BOLA-001"
    assert outcome.conditions == ("BOLA_FOREIGN_OBJECT_RETURNED",)
    assert [(field.location, field.field_path, field.data_class) for field in outcome.affected_fields] == [
        ("response", "account.account_id", "account")
    ]
    assert requests == [
        ("/api/accounts/acct-a-1", "Bearer token-a"),
        ("/api/accounts/acct-b-1", "Bearer token-a"),
    ]
    assert outcome.evidence["baseline"]["status_code"] == 200
    assert outcome.evidence["variant"]["status_code"] == 200
    assert outcome.evidence["matched_user_b_fields"] == ("account.account_id",)
    assert "acct-a-1" not in repr(outcome)
    assert "acct-b-1" not in repr(outcome.evidence)
    assert "token-a" not in repr(outcome.evidence)


@pytest.mark.parametrize("status_code", [401, 403, 404])
def test_bola_rejection_status_is_not_found(status_code: int):
    requests: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request.url.path)
        if request.url.path.endswith("acct-a-1"):
            return httpx.Response(200, json={"account_id": "acct-a-1"})
        return httpx.Response(status_code, json={"detail": "denied"})

    outcome = BolaModule().run(execution_context(handler))

    assert outcome.verdict is ModuleVerdict.NOT_FOUND
    assert outcome.conditions == ()
    assert requests == ["/api/accounts/acct-a-1", "/api/accounts/acct-b-1"]


def test_bola_non_json_rejection_status_is_still_not_found():
    requests: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request.url.path)
        if len(requests) == 1:
            return httpx.Response(200, json={"account_id": "acct-a-1"})
        return httpx.Response(403, text="denied")

    outcome = BolaModule().run(execution_context(handler))

    assert outcome.verdict is ModuleVerdict.NOT_FOUND
    assert requests == ["/api/accounts/acct-a-1", "/api/accounts/acct-b-1"]


def test_bola_success_without_identifiable_user_b_data_is_not_found():
    requests: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request.url.path)
        return httpx.Response(200, json={"message": "request accepted"})

    outcome = BolaModule().run(execution_context(handler))

    assert outcome.verdict is ModuleVerdict.NOT_FOUND
    assert outcome.conditions == ()
    assert len(requests) == 2


@pytest.mark.parametrize(
    ("baseline_response", "variant_response"),
    [
        (
            httpx.Response(500, json={"detail": "baseline failed"}),
            httpx.Response(200, json={"account_id": "acct-b-1"}),
        ),
        (
            httpx.Response(200, text="baseline is not json"),
            httpx.Response(200, json={"account_id": "acct-b-1"}),
        ),
        (
            httpx.Response(200, json={"account_id": "acct-a-1"}),
            httpx.Response(200, text="variant is not json"),
        ),
    ],
    ids=["baseline-failure", "baseline-non-json", "variant-non-json"],
)
def test_bola_non_comparable_responses_are_inconclusive(
    baseline_response: httpx.Response,
    variant_response: httpx.Response,
):
    requests: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request.url.path)
        return baseline_response if len(requests) == 1 else variant_response

    outcome = BolaModule().run(execution_context(handler))

    assert outcome.verdict is ModuleVerdict.INCONCLUSIVE
    assert outcome.conditions == ()
    assert len(requests) == 2


@pytest.mark.parametrize("missing_actor", ["user_a", "user_b"])
def test_bola_missing_actor_object_is_inconclusive_before_network(missing_actor: str):
    requests: list[httpx.Request] = []
    runtime = discovered_runtime()
    runtime.object_ids.pop(missing_actor)

    outcome = BolaModule().run(
        execution_context(
            lambda request: requests.append(request) or httpx.Response(200),
            runtime=runtime,
        )
    )

    assert outcome.verdict is ModuleVerdict.INCONCLUSIVE
    assert requests == []


def test_bola_requires_declared_user_b_binding_before_network():
    requests: list[httpx.Request] = []

    outcome = BolaModule().run(
        execution_context(
            lambda request: requests.append(request) or httpx.Response(200),
            step=account_step(owner="user_a"),
        )
    )

    assert outcome.verdict is ModuleVerdict.INCONCLUSIVE
    assert requests == []


def test_bola_missing_user_a_bearer_token_is_inconclusive_before_network():
    requests: list[httpx.Request] = []
    runtime = discovered_runtime()
    runtime.sessions["user_a"] = ActorSession(actor_id="user_a")

    outcome = BolaModule().run(
        execution_context(
            lambda request: requests.append(request) or httpx.Response(200),
            runtime=runtime,
        )
    )

    assert outcome.verdict is ModuleVerdict.INCONCLUSIVE
    assert requests == []


def test_bola_replaces_case_insensitive_bound_authorization_with_exact_user_a_header():
    requests: list[tuple[str, list[tuple[str, str]]]] = []
    operation = account_operation().model_copy(
        update={
            "inputs": [
                InputField(location="path", field_path="account_id", type="string"),
                InputField(location="header", field_path="authorization", type="string"),
            ]
        }
    )
    step = account_step().model_copy(
        update={
            "input_bindings": [
                *account_step().input_bindings,
                InputBinding(
                    parameter="authorization",
                    location="header",
                    binding_type="parameter_binding",
                ),
            ]
        }
    )
    runtime = discovered_runtime()
    runtime.parameter_examples[
        ("get-account", "header", "authorization")
    ] = {"Bearer attacker-token"}

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(
            (
                request.url.path,
                [
                    (name, value)
                    for name, value in request.headers.multi_items()
                    if name.casefold() == "authorization"
                ],
            )
        )
        return httpx.Response(
            200,
            json={
                "account_id": "acct-a-1"
                if request.url.path.endswith("acct-a-1")
                else "acct-b-1"
            },
        )

    outcome = BolaModule().run(
        execution_context(handler, runtime=runtime, operation=operation, step=step)
    )

    assert outcome.verdict is ModuleVerdict.VERIFIED
    assert requests == [
        ("/api/accounts/acct-a-1", [("authorization", "Bearer token-a")]),
        ("/api/accounts/acct-b-1", [("authorization", "Bearer token-a")]),
    ]


def test_bola_shared_only_actor_object_is_inconclusive_before_network():
    requests: list[httpx.Request] = []
    runtime = discovered_runtime()
    runtime.object_ids.clear()
    collector = SessionManager(cast(SafeHttpClient, None))
    for actor_id in ("user_a", "user_b"):
        collector.collect_response(
            runtime,
            actor_id=cast(str, actor_id),
            operation_id="list-accounts",
            body={"account_id": "00-shared"},
        )

    outcome = BolaModule().run(
        execution_context(
            lambda request: requests.append(request) or httpx.Response(200),
            runtime=runtime,
        )
    )

    assert outcome.verdict is ModuleVerdict.INCONCLUSIVE
    assert requests == []


def test_bola_shared_and_distinct_objects_selects_stable_user_b_only_value():
    requests: list[str] = []
    runtime = discovered_runtime()
    runtime.object_ids.clear()
    collector = SessionManager(cast(SafeHttpClient, None))
    collector.collect_response(
        runtime,
        actor_id="user_a",
        operation_id="list-accounts",
        body={"items": [{"account_id": "00-shared"}, {"account_id": "zz-a-only"}]},
    )
    collector.collect_response(
        runtime,
        actor_id="user_b",
        operation_id="list-accounts",
        body={"items": [{"account_id": "00-shared"}, {"account_id": "zz-b-only"}]},
    )

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request.url.path)
        return httpx.Response(
            200,
            json={
                "account_id": "00-shared"
                if request.url.path.endswith("00-shared")
                else "zz-b-only"
            },
        )

    outcome = BolaModule().run(execution_context(handler, runtime=runtime))

    assert outcome.verdict is ModuleVerdict.VERIFIED
    assert requests == [
        "/api/accounts/00-shared",
        "/api/accounts/zz-b-only",
    ]


def test_bola_encoded_object_path_is_inconclusive_before_any_request():
    requests: list[httpx.Request] = []
    runtime = discovered_runtime()
    runtime.object_ids.clear()
    collector = SessionManager(cast(SafeHttpClient, None))
    collector.collect_response(
        runtime,
        actor_id="user_a",
        operation_id="list-accounts",
        body={"account_id": "acct-a-1"},
    )
    collector.collect_response(
        runtime,
        actor_id="user_b",
        operation_id="list-accounts",
        body={"account_id": "acct b/1"},
    )

    outcome = BolaModule().run(
        execution_context(
            lambda request: requests.append(request) or httpx.Response(200),
            runtime=runtime,
        )
    )

    assert outcome.verdict is ModuleVerdict.INCONCLUSIVE
    assert requests == []


def test_bola_never_sends_non_get_operation():
    requests: list[httpx.Request] = []

    outcome = BolaModule().run(
        execution_context(
            lambda request: requests.append(request) or httpx.Response(200),
            operation=account_operation(method="POST"),
            step=account_step(method="POST"),
        )
    )

    assert outcome.verdict is ModuleVerdict.INCONCLUSIVE
    assert requests == []
