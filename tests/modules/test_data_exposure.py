from __future__ import annotations

from collections.abc import Callable

import httpx
import pytest

from scanner.auth.session_manager import ActorSession, RuntimeContext
from scanner.contracts import Operation, ScanStep, TargetEndpoint, TargetProfile
from scanner.http_client import SafeHttpClient
from scanner.modules.base import ModuleExecutionContext, ModuleVerdict
from scanner.modules.data_exposure import (
    DataExposureModule,
    SensitiveField,
    find_sensitive_fields,
)
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
                "approved_modules": ["data_exposure"],
            },
        }
    )


def operation(
    *,
    method: str = "GET",
    path_template: str = "/api/profile",
) -> Operation:
    return Operation(
        operation_id="get-profile",
        method=method,
        path_template=path_template,
        inputs=[],
        outputs=[],
    )


def step(
    *,
    method: str = "GET",
    path_template: str = "/api/profile",
) -> ScanStep:
    return ScanStep(
        order=1,
        candidate_id="candidate-data",
        module_id="DATA-001",
        target_operation_id="get-profile",
        target_endpoint=TargetEndpoint(
            method=method,
            path_template=path_template,
        ),
        input_bindings=[],
    )


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
        runtime=runtime
        or RuntimeContext(
            scan_id="scan-001",
            sessions={
                "user_a": ActorSession(actor_id="user_a", token="token-a")
            },
        ),
        client=SafeHttpClient(
            policy=PolicyEnforcer(profile),
            budget=RequestBudget(max_requests=10, requests_per_second=1000),
            transport=httpx.MockTransport(handler),
        ),
    )


def test_find_sensitive_fields_required_examples():
    assert find_sensitive_fields({"password": "cleartext"}) == [
        SensitiveField("password", "authentication")
    ]
    assert find_sensitive_fields({"card_number": "4111111111111111"}) == [
        SensitiveField("card_number", "financial")
    ]
    assert find_sensitive_fields({"card_number": "4111-****-****-1111"}) == []
    assert find_sensitive_fields({"account_id": "acct-1"}) == []


@pytest.mark.parametrize(
    ("payload", "expected"),
    [
        (
            {"password_hash": "$2b$12$abcdefghijklmnopqrstuv"},
            [SensitiveField("password_hash", "authentication")],
        ),
        (
            {"access_token": "header.payload.signature"},
            [SensitiveField("access_token", "authentication")],
        ),
        (
            {"api_key": "key-live-123456"},
            [SensitiveField("api_key", "authentication")],
        ),
        (
            {"client_secret": "secret-live-123456"},
            [SensitiveField("client_secret", "authentication")],
        ),
        (
            {"pin": "1234"},
            [SensitiveField("pin", "authentication")],
        ),
        (
            {"cvv": "123"},
            [SensitiveField("cvv", "financial")],
        ),
        (
            {"resident_registration_number": "900101-1234567"},
            [SensitiveField("resident_registration_number", "identity")],
        ),
        (
            {"account_number": "110-123-456789"},
            [SensitiveField("account_number", "financial")],
        ),
        (
            {"users": [{"password": "cleartext"}]},
            [SensitiveField("users[].password", "authentication")],
        ),
    ],
)
def test_find_sensitive_fields_semantic_categories_and_nested_paths(
    payload: object,
    expected: list[SensitiveField],
):
    assert find_sensitive_fields(payload) == expected


@pytest.mark.parametrize(
    "payload",
    [
        {"password": ""},
        {"password": "   "},
        {"password": "********"},
        {"token": "[REDACTED]"},
        {"api_key": "xxxx-xxxx"},
        {"secret": "masked"},
        {"pin": "12ab"},
        {"cvv": "12"},
        {"resident_registration_number": "900101-123456"},
        {"account_number": "acct-1"},
        {"transaction_id": "txn-1"},
        {"card_id": "card-1"},
        {"resident_id": "resident-1"},
    ],
)
def test_find_sensitive_fields_excludes_empty_masked_invalid_and_ordinary_ids(
    payload: object,
):
    assert find_sensitive_fields(payload) == []


@pytest.mark.parametrize(
    "card_number",
    [
        "4222222222222",
        "4111111111111111",
        "4000000000000000006",
    ],
)
def test_find_sensitive_fields_accepts_luhn_cards_from_13_to_19_digits(
    card_number: str,
):
    assert find_sensitive_fields({"card_number": card_number}) == [
        SensitiveField("card_number", "financial")
    ]


@pytest.mark.parametrize(
    "card_number",
    [
        "411111111111",
        "4111111111111112",
        "41111111111111111111",
    ],
)
def test_find_sensitive_fields_rejects_card_length_and_luhn_boundaries(
    card_number: str,
):
    assert find_sensitive_fields({"card_number": card_number}) == []


def test_data_exposure_executes_one_authenticated_get_and_verifies_unmasked_field():
    requests: list[tuple[str, str | None]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append((request.url.path, request.headers.get("authorization")))
        return httpx.Response(
            200,
            json={"profile": {"password": "custom-cleartext-value"}},
        )

    outcome = DataExposureModule().run(execution_context(handler))

    assert outcome.verdict is ModuleVerdict.VERIFIED
    assert outcome.rule_id == "VERIFY-DATA-001"
    assert outcome.conditions == ("DATA_SENSITIVE_FIELD_UNMASKED",)
    assert [
        (field.location, field.field_path, field.data_class)
        for field in outcome.affected_fields
    ] == [("response", "profile.password", "authentication")]
    assert requests == [("/api/profile", "Bearer token-a")]
    assert "custom-cleartext-value" not in repr(outcome)
    assert "custom-cleartext-value" not in repr(outcome.evidence)
    assert "token-a" not in repr(outcome.evidence)


def test_data_exposure_success_without_forbidden_field_is_not_found():
    requests: list[httpx.Request] = []

    outcome = DataExposureModule().run(
        execution_context(
            lambda request: requests.append(request)
            or httpx.Response(200, json={"account_id": "acct-1"})
        )
    )

    assert outcome.verdict is ModuleVerdict.NOT_FOUND
    assert outcome.conditions == ()
    assert len(requests) == 1


def test_data_exposure_json_null_success_is_not_found():
    outcome = DataExposureModule().run(
        execution_context(
            lambda request: httpx.Response(
                200,
                content=b"null",
                headers={"Content-Type": "application/json"},
            )
        )
    )

    assert outcome.verdict is ModuleVerdict.NOT_FOUND
    assert outcome.reason_code == "DATA_FORBIDDEN_FIELD_ABSENT"


def test_data_exposure_evidence_redacts_non_keyed_secret_response_values():
    outcome = DataExposureModule().run(
        execution_context(
            lambda request: httpx.Response(
                200,
                json={"card_number": "4111111111111111"},
            )
        )
    )

    assert outcome.verdict is ModuleVerdict.VERIFIED
    assert outcome.evidence["response"]["json_body"] == {
        "card_number": "[REDACTED]"
    }


def test_data_exposure_masked_field_is_not_found():
    outcome = DataExposureModule().run(
        execution_context(
            lambda request: httpx.Response(
                200,
                json={"password": "********", "card_number": "4111********1111"},
            )
        )
    )

    assert outcome.verdict is ModuleVerdict.NOT_FOUND
    assert outcome.affected_fields == ()


@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(500, json={"password": "cleartext"}),
        httpx.Response(200, text="not json"),
    ],
)
def test_data_exposure_failed_or_non_json_response_is_inconclusive(
    response: httpx.Response,
):
    outcome = DataExposureModule().run(
        execution_context(lambda request: response)
    )

    assert outcome.verdict is ModuleVerdict.INCONCLUSIVE
    assert outcome.reason_code == "DATA_RESPONSE_UNAVAILABLE"


def test_data_exposure_redirect_following_is_disabled_for_exact_count():
    requests: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request.url.path)
        return httpx.Response(
            302,
            headers={"Location": "/api/final"},
            request=request,
        )

    outcome = DataExposureModule().run(execution_context(handler))

    assert outcome.verdict is ModuleVerdict.INCONCLUSIVE
    assert requests == ["/api/profile"]


@pytest.mark.parametrize(
    ("runtime", "target_operation", "target_step", "profile", "reason"),
    [
        (
            RuntimeContext(scan_id="scan-001"),
            operation(),
            step(),
            target_profile(),
            "DATA_SESSION_UNAVAILABLE",
        ),
        (
            RuntimeContext(
                scan_id="scan-001",
                sessions={
                    "user_a": ActorSession(actor_id="user_a", token="token-a")
                },
                required_inputs={"get-profile": {("path", "profile_id")}},
            ),
            operation(path_template="/api/profile/{profile_id}"),
            step(path_template="/api/profile/{profile_id}"),
            target_profile(),
            "DATA_BINDING_UNAVAILABLE",
        ),
        (
            RuntimeContext(
                scan_id="scan-001",
                sessions={
                    "user_a": ActorSession(actor_id="user_a", token="token-a")
                },
            ),
            operation(method="POST"),
            step(method="POST"),
            target_profile(),
            "DATA_NON_GET_OPERATION",
        ),
        (
            RuntimeContext(
                scan_id="scan-001",
                sessions={
                    "user_a": ActorSession(actor_id="user_a", token="token-a")
                },
            ),
            operation(),
            step(),
            target_profile(allowed_paths=["/api/allowed"]),
            "DATA_POLICY_PREFLIGHT_FAILED",
        ),
    ],
)
def test_data_exposure_denials_do_zero_network(
    runtime: RuntimeContext,
    target_operation: Operation,
    target_step: ScanStep,
    profile: TargetProfile,
    reason: str,
):
    requests: list[httpx.Request] = []

    outcome = DataExposureModule().run(
        execution_context(
            lambda request: requests.append(request) or httpx.Response(200),
            runtime=runtime,
            target_operation=target_operation,
            target_step=target_step,
            profile=profile,
        )
    )

    assert outcome.verdict is ModuleVerdict.INCONCLUSIVE
    assert outcome.reason_code == reason
    assert requests == []


def test_data_exposure_sanitizes_secret_response_values_from_affected_paths():
    outcome = DataExposureModule().run(
        execution_context(
            lambda request: httpx.Response(
                200,
                json={
                    "custom-cleartext-value": {
                        "password": "custom-cleartext-value"
                    }
                },
            )
        )
    )

    assert outcome.verdict is ModuleVerdict.VERIFIED
    assert tuple(field.field_path for field in outcome.affected_fields) == (
        "{sensitive_value}.password",
    )
    assert "custom-cleartext-value" not in repr(outcome.affected_fields)
