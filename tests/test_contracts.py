from pydantic import ValidationError
import pytest

from scanner.contracts import (
    ApprovalStatus,
    ContractSource,
    ModuleId,
    NormalizedApiGraph,
    PlanApprovalDecision,
    ScanResult,
    TargetProfile,
)


def target_profile_payload() -> dict:
    return {
        "schema_version": "1.1",
        "scan_id": "scan-001",
        "target": {
            "base_url": "http://vuln-bank.local",
            "allowed_paths": ["/api/*", "/openapi.json"],
            "allowed_methods": ["get"],
        },
        "discovery": {"sources": ["openapi", "crawl"], "max_depth": 3},
        "authentication": {
            "login": {
                "method": "POST",
                "path": "/api/login",
                "content_type": "application/json",
                "username_field": "username",
                "password_field": "password",
                "session": {"type": "bearer", "token_field": "token"},
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
            "max_requests": 300,
            "requests_per_second": 3,
            "state_change_policy": "deny",
            "approved_modules": ["authz", "input_validation", "data_exposure"],
        },
    }


def test_target_profile_accepts_only_version_11_and_two_fixed_actors():
    profile = TargetProfile.model_validate(target_profile_payload())
    assert profile.schema_version == "1.1"
    assert profile.target.allowed_methods == ["GET"]
    assert {actor.actor_id for actor in profile.authentication.actors} == {
        "user_a",
        "user_b",
    }


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("schema_version",), "1.2"),
        (("target", "base_url"), "ftp://vuln-bank.local"),
        (("safety_policy", "max_requests"), 0),
        (("safety_policy", "requests_per_second"), 0),
        (("safety_policy", "approved_modules"), ["authz", "authz"]),
        (("safety_policy", "approved_modules"), ["transaction"]),
        (("authentication", "actors"), []),
    ],
)
def test_target_profile_rejects_invalid_contract_values(path, value):
    payload = target_profile_payload()
    target = payload
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    with pytest.raises(ValidationError):
        TargetProfile.model_validate(payload)


def test_target_profile_rejects_extra_fields():
    payload = target_profile_payload()
    payload["unexpected"] = True
    with pytest.raises(ValidationError):
        TargetProfile.model_validate(payload)


def test_target_profile_rejects_duplicate_fixed_actors():
    payload = target_profile_payload()
    payload["authentication"]["actors"].append(
        {
            "actor_id": "user_a",
            "username_env": "SECOND_USER_A_USERNAME",
            "password_env": "SECOND_USER_A_PASSWORD",
        }
    )
    with pytest.raises(ValidationError):
        TargetProfile.model_validate(payload)


def test_graph_and_result_have_only_fixed_contract_fields():
    graph = NormalizedApiGraph(scan_id="scan-001", operations=[])
    result = ScanResult(scan_id="scan-001", findings=[])
    assert graph.model_dump() == {
        "schema_version": "1.1",
        "scan_id": "scan-001",
        "operations": [],
    }
    assert result.model_dump() == {
        "schema_version": "1.2",
        "scan_id": "scan-001",
        "findings": [],
    }
    assert ModuleId.BOLA.value == "BOLA-001"


def test_contract_source_requires_exactly_one_source():
    assert ContractSource(inline={"schema_version": "1.1"}).artifact_ref is None
    assert ContractSource(artifact_ref="artifacts/profile.json").inline is None
    with pytest.raises(ValidationError):
        ContractSource()
    with pytest.raises(ValidationError):
        ContractSource(inline={}, artifact_ref="artifacts/profile.json")


def test_plan_approval_decision_is_frozen_and_uses_approval_status():
    decision = PlanApprovalDecision(
        scan_id="scan-001",
        plan_id="plan-001",
        status=ApprovalStatus.APPROVED,
        reason_codes=("WITHIN_BUDGET",),
    )
    with pytest.raises(AttributeError):
        decision.status = ApprovalStatus.REJECTED
