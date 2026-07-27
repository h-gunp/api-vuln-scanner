import uuid

from app.core.enums import PlanStatus
from app.core.error_codes import ErrorCode
from app.core.exceptions import AppError
from app.schemas.contracts.relationship_analysis import RelationshipAnalysis
from app.schemas.contracts.scan_plan import ScanPlan
from app.schemas.contracts.target_profile import TargetProfile
from app.utils.url_utils import path_matches


class PlanValidationService:
    def validate(
        self,
        scan_id: uuid.UUID,
        plan: ScanPlan,
        profile: TargetProfile,
        analysis: RelationshipAnalysis,
        operation_ids: set[str],
        requests_used: int | None = None,
    ) -> ScanPlan:
        if plan.status != PlanStatus.PENDING_APPROVAL:
            self._invalid("승인 전 계획 상태는 PENDING_APPROVAL이어야 합니다.")
        budget = plan.budget
        if (
            requests_used is not None
            and budget.requests_already_used != requests_used
        ):
            self._invalid(
                "requests_already_used가 백엔드의 실제 요청 사용량과 일치하지 않습니다."
            )
        calculated_within_budget = (
            budget.requests_already_used + budget.estimated_execution_requests
            <= budget.max_requests
        )
        if budget.within_budget != calculated_within_budget:
            self._invalid("within_budget 값이 실제 요청 예산 계산과 일치하지 않습니다.")
        if budget.max_requests != profile.safety_policy.max_requests:
            self._invalid("계획의 max_requests가 Target Profile과 일치하지 않습니다.")
        if not calculated_within_budget:
            raise AppError(
                ErrorCode.SCAN_BUDGET_EXCEEDED,
                "스캔 요청 예산을 초과했습니다.",
                status_code=422,
            )
        if profile.safety_policy.state_change_policy != "deny":
            raise AppError(
                ErrorCode.SCAN_POLICY_VIOLATION,
                "MVP에서는 상태 변경 요청을 허용하지 않습니다.",
                status_code=422,
            )

        candidates = {candidate.candidate_id: candidate for candidate in analysis.test_candidates}
        actors = {actor.actor_id for actor in profile.authentication.actors}
        approved_modules = set(analysis.approved_module_ids)
        # TODO: Target Profile module categories and final module ID mapping contract pending.
        for step in plan.steps:
            candidate = candidates.get(step.candidate_id)
            if candidate is None:
                self._invalid(f"존재하지 않는 candidate_id입니다: {step.candidate_id}")
            if not candidate.executable:
                self._invalid(f"실행할 수 없는 candidate입니다: {step.candidate_id}")
            if step.module_id not in approved_modules or step.module_id != candidate.module_id:
                self._invalid(f"승인되지 않은 module_id입니다: {step.module_id}")
            if step.target_operation_id not in operation_ids:
                self._invalid(f"존재하지 않는 operation_id입니다: {step.target_operation_id}")
            expected_operation_id = (
                f"{step.target_endpoint.method}:{step.target_endpoint.path_template}"
            )
            if expected_operation_id != step.target_operation_id:
                self._invalid("target_endpoint와 target_operation_id가 일치하지 않습니다.")
            if step.target_endpoint.method not in profile.target.allowed_methods:
                raise AppError(
                    ErrorCode.SCAN_POLICY_VIOLATION,
                    "허용되지 않은 HTTP 메서드가 계획에 포함되었습니다.",
                    status_code=422,
                )
            if not any(
                path_matches(pattern, step.target_endpoint.path_template)
                for pattern in profile.target.allowed_paths
            ):
                raise AppError(
                    ErrorCode.SCAN_POLICY_VIOLATION,
                    "허용 범위를 벗어난 API 경로가 계획에 포함되었습니다.",
                    status_code=422,
                )
            for binding in step.input_bindings:
                if binding.owner not in actors:
                    self._invalid(f"존재하지 않는 actor입니다: {binding.owner}")

        approved = plan.model_copy(deep=True)
        approved.status = PlanStatus.APPROVED
        return approved

    @staticmethod
    def _invalid(message: str) -> None:
        raise AppError(
            ErrorCode.SCAN_PLAN_INVALID,
            message,
            status_code=422,
        )
