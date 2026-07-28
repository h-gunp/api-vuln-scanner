from pydantic import ValidationError
import pytest

from scanner.contracts import (
    ApprovalStatus,
    BindingHint,
    ContractSource,
    InputBinding,
    ModuleId,
    NormalizedApiGraph,
    Operation,
    PlanApprovalDecision,
    Relationship,
    RelationshipAnalysis,
    ScanResult,
    ScanStep,
    TargetProfile,
    TargetEndpoint,
    TestCandidate as CandidateContract,
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


def test_target_profile_rejects_base_url_with_embedded_credentials():
    payload = target_profile_payload()
    payload["target"]["base_url"] = "https://user:password@example.test"
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


def operation_payload(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "operation_id": "GET:/api/accounts",
        "method": "GET",
        "path_template": "/api/accounts",
        "inputs": [],
        "outputs": [],
    }
    payload.update(overrides)
    return payload


def test_operation_requires_a_normalized_method_and_path_identity():
    operation = Operation.model_validate(
        operation_payload(method="get", operation_id="GET:/api/accounts")
    )

    assert operation.method == "GET"
    with pytest.raises(ValidationError):
        Operation.model_validate(
            operation_payload(method="get", operation_id="get:/api/accounts")
        )


def test_graph_rejects_duplicate_operation_ids():
    operation = Operation.model_validate(operation_payload())

    with pytest.raises(ValidationError):
        NormalizedApiGraph(
            scan_id="scan-001",
            operations=[operation, operation.model_copy(deep=True)],
        )


def test_relationship_rejects_an_unknown_contract_relationship_type():
    with pytest.raises(ValidationError):
        Relationship(
            relationship_id="rel-001",
            source_operation_id="GET:/api/accounts",
            target_operation_id="GET:/api/accounts/{account_id}",
            relationship_type="semantic_similarity",
            confidence=0.9,
        )


@pytest.mark.parametrize(
    "binding",
    [
        {
            "parameter": "account_id",
            "location": "path",
            "binding_type": "object_binding",
            "owner": "user_b",
        },
        {
            "parameter": "account_id",
            "location": "path",
            "binding_type": "object_binding",
            "object_type": "account",
        },
        {
            "parameter": "page",
            "location": "query",
            "binding_type": "parameter_binding",
            "object_type": "account",
        },
        {
            "parameter": "page",
            "location": "query",
            "binding_type": "parameter_binding",
            "owner": "user_b",
        },
    ],
)
def test_input_binding_rejects_fields_incompatible_with_its_binding_type(
    binding: dict[str, str]
):
    with pytest.raises(ValidationError):
        InputBinding.model_validate(binding)


def test_input_binding_accepts_complete_object_and_parameter_bindings():
    object_binding = InputBinding(
        parameter="account_id",
        location="path",
        binding_type="object_binding",
        object_type="account",
        owner="user_b",
    )
    parameter_binding = InputBinding(
        parameter="page",
        location="query",
        binding_type="parameter_binding",
    )

    assert object_binding.object_type == "account"
    assert object_binding.owner == "user_b"
    assert parameter_binding.object_type is None
    assert parameter_binding.owner is None


@pytest.mark.parametrize("model", [CandidateContract, ScanStep])
def test_executable_models_reject_inactive_authn_module_id(model: type[object]):
    if model is CandidateContract:
        payload: dict[str, object] = {
            "candidate_id": "candidate-001",
            "module_id": "AUTHN-001",
            "target_operation_id": "GET:/api/accounts",
            "required_object_types": [],
            "rationale": "contract test",
            "priority": 1,
            "executable": True,
            "missing_requirements": [],
            "binding_hints": [
                BindingHint(
                    parameter="page",
                    location="query",
                    binding_type="parameter_binding",
                )
            ],
        }
    else:
        payload = {
            "order": 1,
            "candidate_id": "candidate-001",
            "module_id": "AUTHN-001",
            "target_operation_id": "GET:/api/accounts",
            "target_endpoint": TargetEndpoint(
                method="GET", path_template="/api/accounts"
            ),
            "input_bindings": [],
        }

    with pytest.raises(ValidationError):
        model.model_validate(payload)  # type: ignore[attr-defined]


def test_relationship_analysis_preserves_authn_in_approved_module_ids():
    analysis = RelationshipAnalysis(
        schema_version="1.2",
        scan_id="scan-001",
        model_name="test-model",
        prompt_version="1",
        prompt_sha256="a" * 64,
        approved_module_ids=["BOLA-001", "AUTHN-001", "INPUT-001", "DATA-001"],
        relationships=[],
        test_candidates=[],
    )

    assert analysis.approved_module_ids[1] == "AUTHN-001"
