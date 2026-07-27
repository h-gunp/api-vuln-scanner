from __future__ import annotations

from collections.abc import Callable
from typing import cast

import httpx
import pytest

from scanner.auth.session_manager import (
    ActorSession,
    RuntimeContext,
    SessionManager,
)
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
from scanner.modules.input_validation import InputValidationModule
from scanner.policy import PolicyEnforcer, RequestBudget


def target_profile(*, allowed_paths: list[str] | None = None) -> TargetProfile:
    return TargetProfile.model_validate(
        {
            "schema_version": "1.1",
            "scan_id": "scan-001",
            "target": {
                "base_url": "http://vuln-bank.local",
                "allowed_paths": allowed_paths or ["/api/*"],
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
                    {
                        "actor_id": "user_a",
                        "username_env": "A_U",
                        "password_env": "A_P",
                    },
                    {
                        "actor_id": "user_b",
                        "username_env": "B_U",
                        "password_env": "B_P",
                    },
                ],
            },
            "safety_policy": {
                "max_requests": 10,
                "requests_per_second": 1000,
                "state_change_policy": "deny",
                "approved_modules": ["input_validation"],
            },
        }
    )


def operation(
    *,
    method: str = "GET",
    location: str = "query",
    field_path: str = "page",
    field_type: str = "integer",
) -> Operation:
    path_template = (
        f"/api/items/{{{field_path}}}" if location == "path" else "/api/items"
    )
    return Operation(
        operation_id="list-items",
        method=method,
        path_template=path_template,
        inputs=[
            InputField(
                location=location,
                field_path=field_path,
                type=field_type,
            )
        ],
        outputs=[],
    )


def step(
    *,
    method: str = "GET",
    location: str = "query",
    field_path: str = "page",
) -> ScanStep:
    path_template = (
        f"/api/items/{{{field_path}}}" if location == "path" else "/api/items"
    )
    return ScanStep(
        order=1,
        candidate_id="candidate-input",
        module_id="INPUT-001",
        target_operation_id="list-items",
        target_endpoint=TargetEndpoint(method=method, path_template=path_template),
        input_bindings=[
            InputBinding(
                parameter=field_path,
                location=location,
                binding_type="parameter_binding",
            )
        ],
    )


def runtime_with_example(
    value: str,
    *,
    location: str = "query",
    field_path: str = "page",
    source: str = "observed",
) -> RuntimeContext:
    key = ("list-items", location, field_path)
    runtime = RuntimeContext(
        scan_id="scan-001",
        sessions={"user_a": ActorSession(actor_id="user_a", token="token-a")},
        required_inputs={"list-items": {(location, field_path)}},
    )
    collector = SessionManager(cast(SafeHttpClient, None))
    collector.collect_response(
        runtime,
        actor_id="user_a",
        operation_id="list-items",
        body={"account_id": "acct-a-1"},
        **{f"observed_{location}": {field_path: value}},
    )
    collector.collect_response(
        runtime,
        actor_id="user_b",
        operation_id="list-items",
        body={"account_id": "acct-b-1"},
    )
    if source == "openapi":
        runtime.openapi_parameter_examples[key] = set(
            runtime.observed_parameter_examples.pop(key)
        )
    return runtime


def execution_context(
    handler: Callable[[httpx.Request], httpx.Response],
    *,
    runtime: RuntimeContext | None = None,
    target_operation: Operation | None = None,
    target_step: ScanStep | None = None,
    profile: TargetProfile | None = None,
) -> ModuleExecutionContext:
    profile = profile or target_profile()
    return ModuleExecutionContext(
        scan_id=profile.scan_id,
        base_url=profile.target.base_url,
        operation=target_operation or operation(),
        step=target_step or step(),
        runtime=runtime or runtime_with_example("1"),
        client=SafeHttpClient(
            policy=PolicyEnforcer(profile),
            budget=RequestBudget(max_requests=10, requests_per_second=1000),
            transport=httpx.MockTransport(handler),
        ),
    )


def test_input_uses_observed_query_baseline_and_one_numeric_invalid_variant():
    requests: list[tuple[str | None, str | None]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(
            (request.url.params.get("page"), request.headers.get("authorization"))
        )
        return httpx.Response(200, json={"items": []})

    outcome = InputValidationModule().run(execution_context(handler))

    assert outcome.verdict is ModuleVerdict.NOT_FOUND
    assert outcome.rule_id == "VERIFY-INPUT-001"
    assert requests == [("1", "Bearer token-a"), ("-1", "Bearer token-a")]
    assert "page=1" not in outcome.evidence["baseline"]["url"]


def test_input_prefers_openapi_example_over_sorted_observed_query_values():
    key = ("list-items", "query", "page")
    runtime = runtime_with_example("7", source="openapi")
    collector = SessionManager(cast(SafeHttpClient, None))
    for value in ("1", "3"):
        collector.collect_response(
            runtime,
            actor_id="user_a",
            operation_id="list-items",
            body={},
            observed_query={"page": value},
        )
    requests: list[str | None] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request.url.params.get("page"))
        return httpx.Response(200, json={"items": []})

    outcome = InputValidationModule().run(
        execution_context(handler, runtime=runtime)
    )

    assert outcome.verdict is ModuleVerdict.NOT_FOUND
    assert requests == ["7", "-1"]


def test_input_string_mutation_is_stable_and_invalid_format():
    requests: list[str | None] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request.url.params.get("filter"))
        return httpx.Response(200, json={"items": []})

    context = execution_context(
        handler,
        runtime=runtime_with_example(
            "2026-07-28",
            field_path="filter",
        ),
        target_operation=operation(field_path="filter", field_type="string"),
        target_step=step(field_path="filter"),
    )

    outcome = InputValidationModule().run(context)

    assert outcome.verdict is ModuleVerdict.NOT_FOUND
    assert requests == ["2026-07-28", "invalid-083ddbb62379d19f"]


@pytest.mark.parametrize(
    ("baseline", "expected_variant"),
    [("-1", "0"), ("0", "2147483648")],
)
def test_input_numeric_mutation_uses_first_distinct_candidate(
    baseline: str,
    expected_variant: str,
):
    requests: list[str | None] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request.url.params.get("page"))
        return httpx.Response(200, json={"items": []})

    outcome = InputValidationModule().run(
        execution_context(handler, runtime=runtime_with_example(baseline))
    )

    assert outcome.verdict is ModuleVerdict.NOT_FOUND
    assert requests == [baseline, expected_variant]


@pytest.mark.parametrize("status_code", [400, 422, 500])
def test_input_rejection_or_server_error_is_not_found(status_code: int):
    requests: list[str | None] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request.url.params.get("page"))
        if len(requests) == 1:
            return httpx.Response(200, json={"items": []})
        return httpx.Response(status_code, text="rejected")

    outcome = InputValidationModule().run(execution_context(handler))

    assert outcome.verdict is ModuleVerdict.NOT_FOUND
    assert outcome.conditions == ()
    assert requests == ["1", "-1"]


def test_input_invalid_success_without_response_expansion_is_not_found():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"items": [{"name": "same-shape"}]})

    outcome = InputValidationModule().run(execution_context(handler))

    assert outcome.verdict is ModuleVerdict.NOT_FOUND
    assert outcome.affected_fields == ()


def test_input_verifies_invalid_success_that_introduces_user_b_only_object():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.params.get("page") == "1":
            return httpx.Response(
                200,
                json={"items": [{"account_id": "acct-a-1"}]},
            )
        return httpx.Response(
            200,
            json={"items": [{"account_id": "acct-b-1"}]},
        )

    outcome = InputValidationModule().run(execution_context(handler))

    assert outcome.verdict is ModuleVerdict.VERIFIED
    assert outcome.rule_id == "VERIFY-INPUT-001"
    assert outcome.conditions == ("INPUT_INVALID_VALUE_EXPANDED_SCOPE",)
    assert [
        (field.location, field.field_path, field.data_class)
        for field in outcome.affected_fields
    ] == [("response", "items[].account_id", "account")]
    assert "acct-a-1" not in repr(outcome)
    assert "acct-b-1" not in repr(outcome.evidence)
    assert "token-a" not in repr(outcome.evidence)
    assert "acct-b-1" not in repr(outcome.evidence["variant"]["json_body"])


def test_input_verifies_invalid_success_that_introduces_sensitive_field():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.params.get("page") == "1":
            return httpx.Response(200, json={"profile": {"name": "A"}})
        return httpx.Response(
            200,
            json={"profile": {"name": "A", "password": "cleartext"}},
        )

    outcome = InputValidationModule().run(execution_context(handler))

    assert outcome.verdict is ModuleVerdict.VERIFIED
    assert outcome.conditions == ("INPUT_INVALID_VALUE_EXPANDED_SCOPE",)
    assert [
        (field.location, field.field_path, field.data_class)
        for field in outcome.affected_fields
    ] == [("response", "profile.password", "authentication")]
    assert "cleartext" not in repr(outcome.evidence)


@pytest.mark.parametrize(
    ("runtime", "target_step", "expected_reason"),
    [
        (
            RuntimeContext(
                scan_id="scan-001",
                sessions={
                    "user_a": ActorSession(actor_id="user_a", token="token-a")
                },
                required_inputs={"list-items": {("query", "page")}},
            ),
            step(),
            "INPUT_BASELINE_UNAVAILABLE",
        ),
        (
            runtime_with_example("1"),
            ScanStep(
                order=1,
                candidate_id="candidate-input",
                module_id="INPUT-001",
                target_operation_id="list-items",
                target_endpoint=TargetEndpoint(
                    method="GET",
                    path_template="/api/items",
                ),
                input_bindings=[],
            ),
            "INPUT_BINDING_UNAVAILABLE",
        ),
    ],
)
def test_input_missing_example_or_binding_is_inconclusive_without_network(
    runtime: RuntimeContext,
    target_step: ScanStep,
    expected_reason: str,
):
    requests: list[httpx.Request] = []

    outcome = InputValidationModule().run(
        execution_context(
            lambda request: requests.append(request) or httpx.Response(200),
            runtime=runtime,
            target_step=target_step,
        )
    )

    assert outcome.verdict is ModuleVerdict.INCONCLUSIVE
    assert outcome.reason_code == expected_reason
    assert requests == []


def test_input_missing_json_comparison_evidence_is_inconclusive():
    requests: list[str | None] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request.url.params.get("page"))
        if len(requests) == 1:
            return httpx.Response(200, text="not json")
        return httpx.Response(200, json={"items": []})

    outcome = InputValidationModule().run(execution_context(handler))

    assert outcome.verdict is ModuleVerdict.INCONCLUSIVE
    assert outcome.reason_code == "INPUT_COMPARISON_UNAVAILABLE"
    assert requests == ["1", "-1"]


@pytest.mark.parametrize(
    ("method", "location", "field_type"),
    [
        ("POST", "query", "integer"),
        ("GET", "header", "string"),
        ("GET", "body", "string"),
    ],
)
def test_input_state_changing_body_and_header_inputs_never_run(
    method: str,
    location: str,
    field_type: str,
):
    requests: list[httpx.Request] = []

    outcome = InputValidationModule().run(
        execution_context(
            lambda request: requests.append(request) or httpx.Response(200),
            runtime=runtime_with_example(
                "1",
                location=location,
                field_path="value",
            ),
            target_operation=operation(
                method=method,
                location=location,
                field_path="value",
                field_type=field_type,
            ),
            target_step=step(
                method=method,
                location=location,
                field_path="value",
            ),
        )
    )

    assert outcome.verdict is ModuleVerdict.INCONCLUSIVE
    assert requests == []


def test_input_preflights_both_specs_before_any_transport():
    requests: list[httpx.Request] = []

    outcome = InputValidationModule().run(
        execution_context(
            lambda request: requests.append(request) or httpx.Response(200),
            runtime=runtime_with_example(
                "1",
                location="path",
                field_path="item_id",
                source="openapi",
            ),
            target_operation=operation(
                location="path",
                field_path="item_id",
                field_type="integer",
            ),
            target_step=step(location="path", field_path="item_id"),
            profile=target_profile(allowed_paths=["/api/items/1"]),
        )
    )

    assert outcome.verdict is ModuleVerdict.INCONCLUSIVE
    assert outcome.reason_code == "INPUT_POLICY_PREFLIGHT_FAILED"
    assert requests == []
