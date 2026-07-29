from __future__ import annotations

from dataclasses import FrozenInstanceError
from typing import Callable, NamedTuple

import pytest

from scanner.contracts import (
    ActorConfig,
    ApprovalStatus,
    AuthenticationConfig,
    BindingHint,
    DiscoveryConfig,
    InputBinding,
    InputField,
    LoginConfig,
    NormalizedApiGraph,
    Operation,
    PlanBudget,
    RelationshipAnalysis,
    SafetyPolicy,
    ScanPlan,
    ScanStep,
    SessionConfig,
    TargetConfig,
    TargetEndpoint,
    TargetProfile,
    TestCandidate as CandidateContract,
)
from scanner.executor import Executor, module_for_policy, policy_for_module
from scanner.integration.backend_client import FakeBackendClient, JobKind
from scanner.modules.auth import DisabledAuthModule, ModuleNotApproved


@pytest.mark.parametrize(
    ("policy", "module_id"),
    [
        ("authz", "BOLA-001"),
        ("input_validation", "INPUT-001"),
        ("data_exposure", "DATA-001"),
    ],
)
def test_module_for_policy_uses_only_fixed_active_mapping(
    policy: str,
    module_id: str,
) -> None:
    assert module_for_policy(policy) == module_id


@pytest.mark.parametrize(
    ("module_id", "policy"),
    [
        ("BOLA-001", "authz"),
        ("INPUT-001", "input_validation"),
        ("DATA-001", "data_exposure"),
        ("AUTHN-001", None),
        ("TRANSACTION-001", None),
        ("UNKNOWN-001", None),
    ],
)
def test_policy_for_module_maps_only_active_module_ids(
    module_id: str,
    policy: str | None,
) -> None:
    assert policy_for_module(module_id) == policy


def test_disabled_authn_raises_before_accessing_execution_context() -> None:
    module = DisabledAuthModule()

    with pytest.raises(ModuleNotApproved, match="^module is not approved$"):
        module.run(object())


class ApprovalDocuments(NamedTuple):
    profile: TargetProfile
    graph: NormalizedApiGraph
    analysis: RelationshipAnalysis
    plan: ScanPlan


class NeverRunModule:
    def __init__(self) -> None:
        self.calls = 0
        self.transport_calls = 0

    def run(self, context: object) -> None:
        self.calls += 1
        self.transport_calls += 1
        raise AssertionError("approval evaluation must not execute modules")


def _valid_documents() -> ApprovalDocuments:
    profile = TargetProfile(
        schema_version="1.1",
        scan_id="scan-001",
        target=TargetConfig(
            base_url="https://scanner.test",
            allowed_paths=["/api/*"],
            allowed_methods=["GET"],
        ),
        discovery=DiscoveryConfig(sources=["openapi"], max_depth=1),
        authentication=AuthenticationConfig(
            login=LoginConfig(
                method="POST",
                path="/api/login",
                content_type="application/json",
                username_field="username",
                password_field="password",
                session=SessionConfig(type="bearer", token_field="access_token"),
            ),
            actors=[
                ActorConfig(
                    actor_id="user_a",
                    username_env="SCANNER_USER_A",
                    password_env="SCANNER_PASS_A",
                ),
                ActorConfig(
                    actor_id="user_b",
                    username_env="SCANNER_USER_B",
                    password_env="SCANNER_PASS_B",
                ),
            ],
        ),
        safety_policy=SafetyPolicy(
            max_requests=10,
            requests_per_second=5,
            state_change_policy="deny",
            approved_modules=["authz", "input_validation", "data_exposure"],
        ),
    )
    graph = NormalizedApiGraph(
        schema_version="1.1",
        scan_id="scan-001",
        operations=[
            Operation(
                operation_id="GET:/api/accounts/{account_id}",
                method="GET",
                path_template="/api/accounts/{account_id}",
                inputs=[
                    InputField(
                        location="path",
                        field_path="account_id",
                        type="string",
                    )
                ],
                outputs=[],
            ),
            Operation(
                operation_id="GET:/api/items",
                method="GET",
                path_template="/api/items",
                inputs=[
                    InputField(location="query", field_path="q", type="string")
                ],
                outputs=[],
            ),
            Operation(
                operation_id="GET:/api/profile",
                method="GET",
                path_template="/api/profile",
                inputs=[],
                outputs=[],
            ),
        ],
    )
    analysis = RelationshipAnalysis(
        schema_version="1.2",
        scan_id="scan-001",
        model_name="test-model",
        prompt_version="1",
        prompt_sha256="a" * 64,
        approved_module_ids=["BOLA-001", "INPUT-001", "DATA-001"],
        relationships=[],
        test_candidates=[
            CandidateContract(
                candidate_id="candidate-bola",
                module_id="BOLA-001",
                target_operation_id="GET:/api/accounts/{account_id}",
                required_object_types=["account"],
                rationale="fixed test fixture",
                priority=1,
                executable=True,
                missing_requirements=[],
                binding_hints=[
                    BindingHint(
                        parameter="account_id",
                        location="path",
                        binding_type="object_binding",
                        object_type="account",
                    )
                ],
            ),
            CandidateContract(
                candidate_id="candidate-input",
                module_id="INPUT-001",
                target_operation_id="GET:/api/items",
                required_object_types=[],
                rationale="fixed test fixture",
                priority=2,
                executable=True,
                missing_requirements=[],
                binding_hints=[
                    BindingHint(
                        parameter="q",
                        location="query",
                        binding_type="parameter_binding",
                    )
                ],
            ),
            CandidateContract(
                candidate_id="candidate-data",
                module_id="DATA-001",
                target_operation_id="GET:/api/profile",
                required_object_types=[],
                rationale="fixed test fixture",
                priority=3,
                executable=True,
                missing_requirements=[],
                binding_hints=[],
            ),
        ],
    )
    plan = ScanPlan(
        schema_version="1.2",
        plan_id="plan-001",
        scan_id="scan-001",
        model_name="test-model",
        prompt_version="1",
        prompt_sha256="b" * 64,
        status="PENDING_APPROVAL",
        budget=PlanBudget(
            requests_already_used=3,
            estimated_execution_requests=5,
            max_requests=10,
            within_budget=True,
        ),
        steps=[
            ScanStep(
                order=1,
                candidate_id="candidate-bola",
                module_id="BOLA-001",
                target_operation_id="GET:/api/accounts/{account_id}",
                target_endpoint=TargetEndpoint(
                    method="GET",
                    path_template="/api/accounts/{account_id}",
                ),
                input_bindings=[
                    InputBinding(
                        parameter="account_id",
                        location="path",
                        binding_type="object_binding",
                        object_type="account",
                        owner="user_b",
                    )
                ],
            ),
            ScanStep(
                order=2,
                candidate_id="candidate-input",
                module_id="INPUT-001",
                target_operation_id="GET:/api/items",
                target_endpoint=TargetEndpoint(
                    method="GET",
                    path_template="/api/items",
                ),
                input_bindings=[
                    InputBinding(
                        parameter="q",
                        location="query",
                        binding_type="parameter_binding",
                    )
                ],
            ),
            ScanStep(
                order=3,
                candidate_id="candidate-data",
                module_id="DATA-001",
                target_operation_id="GET:/api/profile",
                target_endpoint=TargetEndpoint(
                    method="GET",
                    path_template="/api/profile",
                ),
                input_bindings=[],
            ),
        ],
    )
    return ApprovalDocuments(profile, graph, analysis, plan)


def _evaluate(
    documents: ApprovalDocuments,
    *,
    runtime_requests_used: int = 3,
) -> tuple[object, FakeBackendClient, tuple[NeverRunModule, ...]]:
    backend = FakeBackendClient()
    modules = (NeverRunModule(), NeverRunModule(), NeverRunModule())
    executor = Executor(
        backend,
        modules={
            "BOLA-001": modules[0],
            "INPUT-001": modules[1],
            "DATA-001": modules[2],
        },
    )
    decision = executor.evaluate_plan(
        job_id="job-001",
        profile=documents.profile,
        graph=documents.graph,
        analysis=documents.analysis,
        plan=documents.plan,
        runtime_requests_used=runtime_requests_used,
    )
    assert [
        (event.job_id, event.scan_id, event.job_kind)
        for event in backend.approval_events
    ] == [("job-001", "scan-001", JobKind.EXECUTION)]
    return decision, backend, modules


def _assert_single_rejection(
    mutate: Callable[[ApprovalDocuments], None],
    reason_code: str,
) -> None:
    documents = _valid_documents()
    mutate(documents)

    decision, backend, modules = _evaluate(documents)

    assert decision.status == ApprovalStatus.REJECTED
    assert decision.reason_codes == (reason_code,)
    assert backend.approval_decisions[-1] is decision
    assert all(module.calls == 0 for module in modules)
    assert all(module.transport_calls == 0 for module in modules)


def test_valid_plan_is_approved_and_publishes_same_immutable_decision() -> None:
    documents = _valid_documents()
    original_plan = documents.plan.model_dump(mode="json")

    decision, backend, modules = _evaluate(documents)

    assert decision.status == ApprovalStatus.APPROVED
    assert decision.reason_codes == ()
    assert decision.scan_id == "scan-001"
    assert decision.plan_id == "plan-001"
    assert backend.approval_decisions[-1] is decision
    assert len(backend.approval_decisions) == 1
    assert documents.plan.model_dump(mode="json") == original_plan
    assert documents.plan.status == "PENDING_APPROVAL"
    assert all(module.calls == 0 for module in modules)
    assert all(module.transport_calls == 0 for module in modules)
    with pytest.raises(FrozenInstanceError):
        decision.status = ApprovalStatus.REJECTED


def test_empty_steps_are_approved_when_zero_estimate_is_current() -> None:
    documents = _valid_documents()
    documents.plan.steps = []
    documents.plan.budget.estimated_execution_requests = 0

    decision, _, _ = _evaluate(documents)

    assert decision.status == ApprovalStatus.APPROVED
    assert decision.reason_codes == ()


def test_rejects_plan_scan_id_mismatch() -> None:
    _assert_single_rejection(
        lambda documents: setattr(documents.plan, "scan_id", "scan-other"),
        "PLAN_SCAN_ID_MISMATCH",
    )


def test_rejects_unknown_operation() -> None:
    def mutate(documents: ApprovalDocuments) -> None:
        documents.plan.steps[0].target_operation_id = "GET:/api/missing"
        documents.analysis.test_candidates[0].target_operation_id = "GET:/api/missing"

    _assert_single_rejection(mutate, "PLAN_OPERATION_UNKNOWN")


def test_rejects_unknown_candidate() -> None:
    _assert_single_rejection(
        lambda documents: setattr(
            documents.plan.steps[0],
            "candidate_id",
            "missing-candidate",
        ),
        "PLAN_CANDIDATE_UNKNOWN",
    )


def test_rejects_candidate_that_is_not_executable() -> None:
    _assert_single_rejection(
        lambda documents: setattr(
            documents.analysis.test_candidates[0],
            "executable",
            False,
        ),
        "PLAN_CANDIDATE_NOT_EXECUTABLE",
    )


def test_rejects_endpoint_mismatch() -> None:
    _assert_single_rejection(
        lambda documents: setattr(
            documents.plan.steps[0].target_endpoint,
            "path_template",
            "/api/other/{account_id}",
        ),
        "PLAN_ENDPOINT_MISMATCH",
    )


def test_rejects_matching_graph_and_step_endpoint_outside_profile_paths() -> None:
    def mutate(documents: ApprovalDocuments) -> None:
        documents.graph.operations[0].path_template = (
            "/private/accounts/{account_id}"
        )
        documents.plan.steps[0].target_endpoint.path_template = (
            "/private/accounts/{account_id}"
        )

    _assert_single_rejection(mutate, "PLAN_ENDPOINT_MISMATCH")


def test_rejects_binding_mismatch() -> None:
    def mutate(documents: ApprovalDocuments) -> None:
        documents.plan.steps[0].input_bindings[0].parameter = "other_id"

    _assert_single_rejection(mutate, "PLAN_BINDING_MISMATCH")


@pytest.mark.parametrize("location", ["header", "body"])
def test_rejects_input_module_header_or_body_binding(location: str) -> None:
    def mutate(documents: ApprovalDocuments) -> None:
        documents.graph.operations[1].inputs[0].location = location
        documents.analysis.test_candidates[1].binding_hints[0].location = location
        documents.plan.steps[1].input_bindings[0].location = location

    _assert_single_rejection(mutate, "PLAN_BINDING_MISMATCH")


def test_rejects_bola_binding_that_does_not_select_user_b() -> None:
    def mutate(documents: ApprovalDocuments) -> None:
        documents.plan.steps[0].input_bindings[0].owner = "user_a"

    _assert_single_rejection(mutate, "PLAN_BINDING_MISMATCH")


def test_rejects_invalid_step_order() -> None:
    _assert_single_rejection(
        lambda documents: setattr(documents.plan.steps[1], "order", 1),
        "PLAN_STEP_ORDER_INVALID",
    )


def test_rejects_unknown_module_without_cascading_estimate_reason() -> None:
    def mutate(documents: ApprovalDocuments) -> None:
        documents.plan.steps[0].module_id = "UNKNOWN-001"
        documents.analysis.test_candidates[0].module_id = "UNKNOWN-001"

    _assert_single_rejection(mutate, "PLAN_MODULE_NOT_APPROVED")


def test_rejects_approved_module_set_mismatch() -> None:
    _assert_single_rejection(
        lambda documents: setattr(
            documents.analysis,
            "approved_module_ids",
            ["BOLA-001", "INPUT-001"],
        ),
        "PLAN_APPROVED_MODULE_SET_MISMATCH",
    )


def test_rejects_authn_module_with_specific_reason() -> None:
    def mutate(documents: ApprovalDocuments) -> None:
        documents.plan.steps[0].module_id = "AUTHN-001"
        documents.analysis.test_candidates[0].module_id = "AUTHN-001"

    _assert_single_rejection(mutate, "PLAN_AUTHN_NOT_APPROVED")


def test_rejects_non_get_operation_even_when_endpoint_matches() -> None:
    def mutate(documents: ApprovalDocuments) -> None:
        documents.graph.operations[0].method = "POST"
        documents.plan.steps[0].target_endpoint.method = "POST"

    _assert_single_rejection(mutate, "PLAN_METHOD_NOT_ALLOWED")


def test_rejects_stale_runtime_request_count() -> None:
    documents = _valid_documents()

    decision, backend, modules = _evaluate(
        documents,
        runtime_requests_used=4,
    )

    assert decision.status == ApprovalStatus.REJECTED
    assert decision.reason_codes == ("PLAN_REQUEST_COUNT_STALE",)
    assert backend.approval_decisions[-1] is decision
    assert all(module.calls == 0 for module in modules)
    assert all(module.transport_calls == 0 for module in modules)


def test_rejects_execution_request_estimate_mismatch() -> None:
    _assert_single_rejection(
        lambda documents: setattr(
            documents.plan.budget,
            "estimated_execution_requests",
            4,
        ),
        "PLAN_ESTIMATE_MISMATCH",
    )


def test_rejects_profile_and_plan_max_request_mismatch() -> None:
    _assert_single_rejection(
        lambda documents: setattr(documents.plan.budget, "max_requests", 11),
        "PLAN_MAX_REQUESTS_MISMATCH",
    )


def test_rejects_incorrect_within_budget_flag() -> None:
    _assert_single_rejection(
        lambda documents: setattr(documents.plan.budget, "within_budget", False),
        "PLAN_BUDGET_FLAG_INVALID",
    )


def test_rejects_plan_that_correctly_reports_exceeded_budget() -> None:
    def mutate(documents: ApprovalDocuments) -> None:
        documents.profile.safety_policy.max_requests = 7
        documents.plan.budget.max_requests = 7
        documents.plan.budget.within_budget = False

    _assert_single_rejection(mutate, "PLAN_REQUEST_BUDGET_EXCEEDED")


def test_rejects_invalid_true_budget_flag_and_reports_exceeded_budget() -> None:
    documents = _valid_documents()
    documents.profile.safety_policy.max_requests = 7
    documents.plan.budget.max_requests = 7
    documents.plan.budget.within_budget = True

    decision, backend, modules = _evaluate(documents)

    assert decision.status == ApprovalStatus.REJECTED
    assert decision.reason_codes == (
        "PLAN_BUDGET_FLAG_INVALID",
        "PLAN_REQUEST_BUDGET_EXCEEDED",
    )
    assert backend.approval_decisions[-1] is decision
    assert all(module.calls == 0 for module in modules)
    assert all(module.transport_calls == 0 for module in modules)


def test_rejection_reasons_are_sorted_and_deduplicated() -> None:
    documents = _valid_documents()
    documents.graph.scan_id = "scan-other"
    documents.analysis.scan_id = "scan-other"
    documents.plan.scan_id = "scan-other"
    documents.plan.steps[1].order = 1

    decision, _, _ = _evaluate(documents)

    assert decision.reason_codes == (
        "PLAN_SCAN_ID_MISMATCH",
        "PLAN_STEP_ORDER_INVALID",
    )


def test_one_invalid_step_rejects_entire_plan_without_module_or_transport_calls() -> None:
    documents = _valid_documents()
    documents.plan.steps[1].input_bindings[0].location = "header"

    decision, _, modules = _evaluate(documents)

    assert decision.status == ApprovalStatus.REJECTED
    assert decision.reason_codes == ("PLAN_BINDING_MISMATCH",)
    assert all(module.calls == 0 for module in modules)
    assert all(module.transport_calls == 0 for module in modules)
