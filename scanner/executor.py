"""Scanner-owned plan approval and fixed-module execution boundary."""

from __future__ import annotations

from collections.abc import Mapping

from scanner.contracts import (
    ApprovalStatus,
    BindingHint,
    InputBinding,
    NormalizedApiGraph,
    Operation,
    PlanApprovalDecision,
    RelationshipAnalysis,
    ScanPlan,
    ScanStep,
    TestCandidate,
    TargetProfile,
)
from scanner.integration.backend_client import BackendClient
from scanner.modules.bola import BolaModule
from scanner.modules.data_exposure import DataExposureModule
from scanner.modules.input_validation import InputValidationModule
from scanner.policy import path_is_allowed


_POLICY_MODULE_IDS = {
    "authz": "BOLA-001",
    "input_validation": "INPUT-001",
    "data_exposure": "DATA-001",
}
_MODULE_POLICIES = {module_id: policy for policy, module_id in _POLICY_MODULE_IDS.items()}
REQUEST_ESTIMATES = {
    "BOLA-001": 2,
    "INPUT-001": 2,
    "DATA-001": 1,
}


def module_for_policy(policy: str) -> str | None:
    return _POLICY_MODULE_IDS.get(policy)


def policy_for_module(module_id: str) -> str | None:
    return _MODULE_POLICIES.get(module_id)


class Executor:
    def __init__(
        self,
        backend: BackendClient,
        modules: Mapping[str, object] | None = None,
    ) -> None:
        self._backend = backend
        self._modules = dict(modules) if modules is not None else {
            "BOLA-001": BolaModule(),
            "INPUT-001": InputValidationModule(),
            "DATA-001": DataExposureModule(),
        }

    def evaluate_plan(
        self,
        *,
        job_id: str,
        profile: TargetProfile,
        graph: NormalizedApiGraph,
        analysis: RelationshipAnalysis,
        plan: ScanPlan,
        runtime_requests_used: int,
    ) -> PlanApprovalDecision:
        reasons: set[str] = set()
        approved_module_ids = {
            module_id
            for policy in profile.safety_policy.approved_modules
            if (module_id := module_for_policy(policy)) is not None
        }
        operations = {
            operation.operation_id: operation for operation in graph.operations
        }
        candidates = {
            candidate.candidate_id: candidate
            for candidate in analysis.test_candidates
        }

        if {
            profile.scan_id,
            graph.scan_id,
            analysis.scan_id,
            plan.scan_id,
        } != {profile.scan_id}:
            reasons.add("PLAN_SCAN_ID_MISMATCH")
        if set(analysis.approved_module_ids) != approved_module_ids:
            reasons.add("PLAN_APPROVED_MODULE_SET_MISMATCH")
        if [step.order for step in plan.steps] != list(
            range(1, len(plan.steps) + 1)
        ):
            reasons.add("PLAN_STEP_ORDER_INVALID")

        for candidate in analysis.test_candidates:
            _check_module(candidate.module_id, approved_module_ids, reasons)
        for step in plan.steps:
            _check_module(step.module_id, approved_module_ids, reasons)
            operation = operations.get(step.target_operation_id)
            candidate = candidates.get(step.candidate_id)

            if operation is None:
                reasons.add("PLAN_OPERATION_UNKNOWN")
            else:
                _check_operation(step, operation, profile, reasons)
            if candidate is None:
                reasons.add("PLAN_CANDIDATE_UNKNOWN")
            else:
                if not candidate.executable:
                    reasons.add("PLAN_CANDIDATE_NOT_EXECUTABLE")
                if operation is not None and not _bindings_match(
                    step,
                    candidate,
                    operation,
                ):
                    reasons.add("PLAN_BINDING_MISMATCH")

        budget = plan.budget
        if runtime_requests_used != budget.requests_already_used:
            reasons.add("PLAN_REQUEST_COUNT_STALE")
        estimates = [REQUEST_ESTIMATES.get(step.module_id) for step in plan.steps]
        if all(estimate is not None for estimate in estimates):
            estimated_requests = sum(
                estimate for estimate in estimates if estimate is not None
            )
            if estimated_requests != budget.estimated_execution_requests:
                reasons.add("PLAN_ESTIMATE_MISMATCH")
        if profile.safety_policy.max_requests != budget.max_requests:
            reasons.add("PLAN_MAX_REQUESTS_MISMATCH")
        calculated_within_budget = (
            budget.requests_already_used + budget.estimated_execution_requests
            <= budget.max_requests
        )
        if budget.within_budget != calculated_within_budget:
            reasons.add("PLAN_BUDGET_FLAG_INVALID")
        if not calculated_within_budget:
            reasons.add("PLAN_REQUEST_BUDGET_EXCEEDED")

        reason_codes = tuple(sorted(reasons))
        decision = PlanApprovalDecision(
            scan_id=profile.scan_id,
            plan_id=plan.plan_id,
            status=(
                ApprovalStatus.REJECTED
                if reason_codes
                else ApprovalStatus.APPROVED
            ),
            reason_codes=reason_codes,
        )
        self._backend.report_approval(job_id, decision)
        return decision


def _check_module(
    module_id: str,
    approved_module_ids: set[str],
    reasons: set[str],
) -> None:
    if module_id == "AUTHN-001":
        reasons.add("PLAN_AUTHN_NOT_APPROVED")
    elif module_id not in approved_module_ids or policy_for_module(module_id) is None:
        reasons.add("PLAN_MODULE_NOT_APPROVED")


def _check_operation(
    step: ScanStep,
    operation: Operation,
    profile: TargetProfile,
    reasons: set[str],
) -> None:
    if (
        step.target_endpoint.method != operation.method
        or step.target_endpoint.path_template != operation.path_template
        or not path_is_allowed(
            operation.path_template,
            profile.target.allowed_paths,
        )
    ):
        reasons.add("PLAN_ENDPOINT_MISMATCH")
    if (
        operation.method != "GET"
        or operation.method not in profile.target.allowed_methods
    ):
        reasons.add("PLAN_METHOD_NOT_ALLOWED")


def _bindings_match(
    step: ScanStep,
    candidate: TestCandidate,
    operation: Operation,
) -> bool:
    if (
        candidate.module_id != step.module_id
        or candidate.target_operation_id != step.target_operation_id
    ):
        return False
    operation_inputs = {
        (input_field.location, input_field.field_path)
        for input_field in operation.inputs
    }
    hints = [_hint_signature(hint) for hint in candidate.binding_hints]
    bindings = [_binding_signature(binding) for binding in step.input_bindings]
    if sorted(hints) != sorted(bindings):
        return False
    if any(
        (binding.location, binding.parameter) not in operation_inputs
        or not _binding_shape_is_valid(binding)
        for binding in step.input_bindings
    ):
        return False
    if step.module_id == "INPUT-001" and any(
        binding.location not in {"path", "query"}
        for binding in step.input_bindings
    ):
        return False
    if step.module_id == "BOLA-001" and not any(
        binding.binding_type == "object_binding" and binding.owner == "user_b"
        for binding in step.input_bindings
    ):
        return False
    return all(
        (hint.location, hint.parameter) in operation_inputs
        for hint in candidate.binding_hints
    )


def _hint_signature(hint: BindingHint) -> tuple[str, str, str, str]:
    return (
        hint.location,
        hint.parameter,
        hint.binding_type,
        hint.object_type or "",
    )


def _binding_signature(binding: InputBinding) -> tuple[str, str, str, str]:
    return (
        binding.location,
        binding.parameter,
        binding.binding_type,
        binding.object_type or "",
    )


def _binding_shape_is_valid(binding: InputBinding) -> bool:
    if binding.binding_type == "object_binding":
        return binding.object_type is not None and binding.owner is not None
    return binding.object_type is None and binding.owner is None
