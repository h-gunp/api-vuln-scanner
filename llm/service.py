from __future__ import annotations

import json
import time
from fnmatch import fnmatchcase
from typing import Any, Callable, TypeVar
from uuid import NAMESPACE_URL, uuid5

from pydantic import BaseModel, ValidationError

from .contracts import (
    AiReport,
    BindingHint,
    Budget,
    Finding,
    InputBinding,
    ModuleId,
    NormalizedApiGraph,
    Operation,
    PlanDraft,
    PlanStep,
    Relationship,
    RelationshipAnalysis,
    RelationshipDraft,
    ReportDraft,
    ReportFinding,
    ScanPlan,
    ScanResult,
    TargetEndpoint,
    TargetProfile,
    TestCandidate,
)
from .errors import LLMError
from .prompts import (
    PLAN_PROMPT,
    PLAN_PROMPT_SHA256,
    PLAN_PROMPT_VERSION,
    RELATIONSHIP_PROMPT,
    RELATIONSHIP_PROMPT_SHA256,
    RELATIONSHIP_PROMPT_VERSION,
    REPORT_PROMPT,
    REPORT_PROMPT_SHA256,
    REPORT_PROMPT_VERSION,
)

MODEL_NAME = "gpt-4o-mini-2024-07-18"
MODULE_MAP: dict[str, ModuleId] = {
    "authz": "BOLA-001",
    "input_validation": "INPUT-001",
    "data_exposure": "DATA-001",
}
MODULE_REQUEST_COST: dict[ModuleId, int] = {
    "BOLA-001": 2,
    "INPUT-001": 2,
    "DATA-001": 1,
}
SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}

T = TypeVar("T", bound=BaseModel)
R = TypeVar("R")


class LLMService:
    def __init__(
        self,
        client: Any | None = None,
        *,
        model_name: str = MODEL_NAME,
        max_retries: int = 2,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.client = client
        self.model_name = model_name
        self.max_retries = max_retries
        self.sleep = sleep

    def analyze_relationships(
        self,
        target_profile: dict[str, Any] | TargetProfile,
        api_graph: dict[str, Any] | NormalizedApiGraph,
    ) -> RelationshipAnalysis:
        target = self._validate_input(TargetProfile, target_profile)
        graph = self._validate_input(NormalizedApiGraph, api_graph)
        self._require_same_scan_id(target.scan_id, graph.scan_id)

        return self._generate(
            "REL",
            RELATIONSHIP_PROMPT,
            {"normalized_api_graph": graph.model_dump(mode="json")},
            RelationshipDraft,
            lambda draft: self._build_relationship_analysis(target, graph, draft),
        )

    def create_scan_plan(
        self,
        target_profile: dict[str, Any] | TargetProfile,
        api_graph: dict[str, Any] | NormalizedApiGraph,
        relationship_analysis: dict[str, Any] | RelationshipAnalysis,
        *,
        requests_already_used: int,
    ) -> ScanPlan:
        target = self._validate_input(TargetProfile, target_profile)
        graph = self._validate_input(NormalizedApiGraph, api_graph)
        analysis = self._validate_input(
            RelationshipAnalysis, relationship_analysis
        )
        self._require_same_scan_id(target.scan_id, graph.scan_id, analysis.scan_id)
        if requests_already_used < 0:
            raise LLMError(
                "LLM_INVALID_INPUT",
                "requests_already_used must be zero or greater",
            )
        self._validate_analysis_against_graph(target, graph, analysis)

        candidates = [candidate for candidate in analysis.test_candidates if candidate.executable]
        if not candidates:
            return self._build_scan_plan(
                target, graph, candidates, [], requests_already_used
            )

        payload = {
            "relationships": [
                relationship.model_dump(mode="json")
                for relationship in analysis.relationships
            ],
            "test_candidates": [
                candidate.model_dump(mode="json") for candidate in candidates
            ],
        }
        return self._generate(
            "PLAN",
            PLAN_PROMPT,
            payload,
            PlanDraft,
            lambda draft: self._build_scan_plan(
                target,
                graph,
                candidates,
                self._validate_plan_order(candidates, draft),
                requests_already_used,
            ),
        )

    def create_ai_report(
        self,
        scan_result: dict[str, Any] | ScanResult,
    ) -> AiReport:
        result = self._validate_input(ScanResult, scan_result)
        if not result.findings:
            return AiReport(
                schema_version="1.2",
                scan_id=result.scan_id,
                model_name=self.model_name,
                prompt_version=REPORT_PROMPT_VERSION,
                prompt_sha256=REPORT_PROMPT_SHA256,
                overall_risk="low",
                overall_risk_basis="rule:max_verified_severity",
                summary="검증 규칙으로 확정된 취약점이 없습니다.",
                findings=[],
            )

        return self._generate(
            "REPORT",
            REPORT_PROMPT,
            {"scan_result": result.model_dump(mode="json")},
            ReportDraft,
            lambda draft: self._build_ai_report(result, draft),
        )

    def _generate(
        self,
        stage: str,
        system_prompt: str,
        payload: dict[str, Any],
        output_model: type[T],
        validate: Callable[[T], R],
    ) -> R:
        last_error: LLMError | None = None
        retry_instruction: str | None = None
        for attempt in range(self.max_retries + 1):
            try:
                if self.client is None:
                    self.client = self._default_client()
                messages = [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": self._prompt_input(payload)},
                ]
                if retry_instruction:
                    messages.append(
                        {"role": "user", "content": retry_instruction}
                    )
                response = self.client.responses.parse(
                    model=self.model_name,
                    temperature=0,
                    input=messages,
                    text_format=output_model,
                )
                parsed = getattr(response, "output_parsed", None)
                if parsed is None:
                    raise LLMError(
                        "LLM_REFUSAL",
                        "model returned no structured output",
                    )
                if not isinstance(parsed, output_model):
                    parsed = output_model.model_validate(parsed)
                return validate(parsed)
            except LLMError as error:
                last_error = error
                retry_instruction = self._retry_instruction(error.code)
            except ValidationError as error:
                last_error = LLMError(
                    f"LLM_{stage}_INVALID_OUTPUT",
                    str(error),
                    retryable=True,
                )
                retry_instruction = (
                    "이전 출력이 스키마 또는 교차 필드 규칙을 위반함. "
                    "필수 필드, enum과 null 규칙을 다시 확인하여 재생성함."
                )
            except Exception as error:  # SDK 예외를 설치 버전과 독립적으로 변환함.
                last_error = self._map_client_error(stage, error)

            if not last_error.retryable or attempt == self.max_retries:
                raise last_error
            self.sleep(0.5 * (2**attempt))

        raise last_error or LLMError("LLM_CLIENT_ERROR", "unknown LLM error")

    def _build_relationship_analysis(
        self,
        target: TargetProfile,
        graph: NormalizedApiGraph,
        draft: RelationshipDraft,
    ) -> RelationshipAnalysis:
        operations = {operation.operation_id: operation for operation in graph.operations}
        relationships: list[Relationship] = []
        seen: set[tuple[Any, ...]] = set()

        for item in draft.relationships:
            source = operations.get(item.source_operation_id)
            target_operation = operations.get(item.target_operation_id)
            if source is None or target_operation is None:
                raise self._hallucinated_reference("unknown operation_id")
            if item.source_field is not None and item.source_field not in {
                field.field_path for field in source.outputs
            }:
                raise self._hallucinated_reference("unknown source_field")
            if item.target_parameter is not None and (
                item.target_parameter,
                item.target_parameter_location,
            ) not in {
                (field.field_path, field.location)
                for field in target_operation.inputs
            }:
                raise self._hallucinated_reference("unknown target parameter")

            key = (
                item.source_operation_id,
                item.target_operation_id,
                item.source_field,
                item.target_parameter,
                item.target_parameter_location,
                item.relationship_type,
            )
            if key in seen:
                continue
            seen.add(key)
            relationships.append(
                Relationship(
                    relationship_id=f"rel-{len(relationships) + 1:03d}",
                    **item.model_dump(),
                )
            )

        relationships = self._recover_identifier_relationships(
            target,
            graph,
            relationships,
        )
        approved_ids = [
            MODULE_MAP[category]
            for category in target.safety_policy.approved_modules
        ]
        candidates = self._select_candidates(
            target, graph, relationships, approved_ids
        )
        return RelationshipAnalysis(
            schema_version="1.2",
            scan_id=target.scan_id,
            model_name=self.model_name,
            prompt_version=RELATIONSHIP_PROMPT_VERSION,
            prompt_sha256=RELATIONSHIP_PROMPT_SHA256,
            approved_module_ids=approved_ids,
            relationships=relationships,
            test_candidates=candidates,
        )

    @classmethod
    def _recover_identifier_relationships(
        cls,
        target: TargetProfile,
        graph: NormalizedApiGraph,
        relationships: list[Relationship],
    ) -> list[Relationship]:
        existing = {
            cls._relationship_key(relationship)
            for relationship in relationships
        }
        inferred: list[Relationship] = []
        for target_operation in graph.operations:
            if not cls._operation_in_scope(target, target_operation):
                continue
            for target_field in target_operation.inputs:
                if target_field.location not in {"path", "query"}:
                    continue
                target_type = cls._input_object_type(
                    target_field.field_path,
                    target_operation.path_template,
                )
                if target_type is None:
                    continue
                for source_operation in graph.operations:
                    if (
                        source_operation.operation_id
                        == target_operation.operation_id
                        and target_field.location == "path"
                    ):
                        continue
                    for source_field in source_operation.outputs:
                        if source_field.type != target_field.type:
                            continue
                        if (
                            cls._output_object_type(source_field.field_path)
                            != target_type
                        ):
                            continue
                        candidate = Relationship(
                            relationship_id="rel-pending",
                            source_operation_id=source_operation.operation_id,
                            target_operation_id=target_operation.operation_id,
                            source_field=source_field.field_path,
                            target_parameter=target_field.field_path,
                            target_parameter_location=target_field.location,
                            relationship_type="id_flow",
                            confidence=1.0,
                        )
                        key = cls._relationship_key(candidate)
                        if key in existing:
                            continue
                        existing.add(key)
                        inferred.append(candidate)

        inferred.sort(key=cls._relationship_key)
        return [
            relationship.model_copy(
                update={"relationship_id": f"rel-{index:03d}"}
            )
            for index, relationship in enumerate(
                [*relationships, *inferred],
                start=1,
            )
        ]

    @staticmethod
    def _relationship_key(relationship: Relationship) -> tuple[str, ...]:
        return (
            relationship.source_operation_id,
            relationship.target_operation_id,
            relationship.source_field or "",
            relationship.target_parameter or "",
            relationship.target_parameter_location or "",
            relationship.relationship_type,
        )

    @classmethod
    def _input_object_type(
        cls,
        field_path: str,
        path_template: str,
    ) -> str | None:
        leaf = field_path.rsplit(".", 1)[-1].replace("[]", "").casefold()
        if leaf == "account_number":
            return "account"
        if leaf.endswith("_id") and len(leaf) > 3:
            return leaf[:-3]
        if leaf == "id":
            return cls._object_type(field_path, path_template)
        return None

    @classmethod
    def _output_object_type(cls, field_path: str) -> str | None:
        parts = field_path.split(".")
        leaf = parts[-1].replace("[]", "").casefold()
        if leaf == "account_number":
            return "account"
        if leaf.endswith("_id") and len(leaf) > 3:
            return leaf[:-3]
        if leaf != "id" or len(parts) < 2:
            return None
        container = parts[-2].replace("[]", "").casefold()
        return cls._singularize(container)

    @staticmethod
    def _singularize(value: str) -> str:
        if value.endswith("ies") and len(value) > 3:
            return f"{value[:-3]}y"
        if value.endswith("s") and len(value) > 1:
            return value[:-1]
        return value

    def _select_candidates(
        self,
        target: TargetProfile,
        graph: NormalizedApiGraph,
        relationships: list[Relationship],
        approved_ids: list[ModuleId],
    ) -> list[TestCandidate]:
        operations = {
            operation.operation_id: operation
            for operation in graph.operations
            if self._operation_in_scope(target, operation)
        }
        rows: list[tuple[ModuleId, Operation, list[BindingHint], str]] = []

        if "BOLA-001" in approved_ids:
            for relationship in relationships:
                operation = operations.get(relationship.target_operation_id)
                if (
                    operation is None
                    or relationship.relationship_type not in {"id_flow", "ownership"}
                    or relationship.target_parameter is None
                    or relationship.target_parameter_location is None
                    or not self._looks_like_identifier(relationship.target_parameter)
                ):
                    continue
                hint = BindingHint(
                    parameter=relationship.target_parameter,
                    location=relationship.target_parameter_location,
                    binding_type="object_binding",
                    object_type=self._object_type(
                        relationship.target_parameter, operation.path_template
                    ),
                )
                rows.append(
                    (
                        "BOLA-001",
                        operation,
                        [hint],
                        "상위 응답 식별자가 객체 조회 입력으로 연결됨",
                    )
                )

        for operation in operations.values():
            if "INPUT-001" in approved_ids:
                inputs = [
                    field
                    for field in operation.inputs
                    if field.location in {"path", "query"}
                ]
                if inputs:
                    rows.append(
                        (
                            "INPUT-001",
                            operation,
                            self._execution_hints(operation),
                            "GET path/query 입력의 형식·경계 검사가 가능함",
                        )
                    )
            if "DATA-001" in approved_ids and operation.outputs:
                rows.append(
                    (
                        "DATA-001",
                        operation,
                        self._execution_hints(operation),
                        "성공 응답 출력 필드에 데이터 노출 규칙을 적용할 수 있음",
                    )
                )

        unique: dict[tuple[str, str], tuple[ModuleId, Operation, list[BindingHint], str]] = {}
        for row in rows:
            unique.setdefault((row[0], row[1].operation_id), row)

        module_order = {"BOLA-001": 0, "INPUT-001": 1, "DATA-001": 2}
        ordered = sorted(
            unique.values(),
            key=lambda row: (module_order[row[0]], row[1].operation_id),
        )
        candidates: list[TestCandidate] = []
        for index, (module_id, operation, hints, rationale) in enumerate(
            ordered, start=1
        ):
            object_types = sorted(
                {
                    hint.object_type
                    for hint in hints
                    if hint.object_type is not None
                }
            )
            candidates.append(
                TestCandidate(
                    candidate_id=f"candidate-{index:03d}",
                    module_id=module_id,
                    target_operation_id=operation.operation_id,
                    required_object_types=object_types,
                    rationale=rationale,
                    priority=index,
                    executable=True,
                    missing_requirements=[],
                    binding_hints=hints,
                )
            )
        return candidates

    def _build_scan_plan(
        self,
        target: TargetProfile,
        graph: NormalizedApiGraph,
        candidates: list[TestCandidate],
        ordered_candidate_ids: list[str],
        requests_already_used: int,
    ) -> ScanPlan:
        by_candidate = {
            candidate.candidate_id: candidate for candidate in candidates
        }
        operations = {operation.operation_id: operation for operation in graph.operations}
        steps: list[PlanStep] = []

        for order, candidate_id in enumerate(ordered_candidate_ids, start=1):
            candidate = by_candidate[candidate_id]
            operation = operations[candidate.target_operation_id]
            bindings = [
                InputBinding(
                    parameter=hint.parameter,
                    location=hint.location,
                    binding_type=hint.binding_type,
                    object_type=hint.object_type,
                    owner=(
                        "user_b"
                        if hint.binding_type == "object_binding"
                        and candidate.module_id == "BOLA-001"
                        else "user_a"
                        if hint.binding_type == "object_binding"
                        else None
                    ),
                )
                for hint in candidate.binding_hints
            ]
            steps.append(
                PlanStep(
                    order=order,
                    candidate_id=candidate.candidate_id,
                    module_id=candidate.module_id,
                    target_operation_id=candidate.target_operation_id,
                    target_endpoint=TargetEndpoint(
                        method=operation.method,
                        path_template=operation.path_template,
                    ),
                    input_bindings=bindings,
                )
            )

        estimated = sum(
            MODULE_REQUEST_COST[step.module_id] for step in steps
        )
        candidate_key = ",".join(step.candidate_id for step in steps)
        return ScanPlan(
            schema_version="1.2",
            plan_id=str(uuid5(NAMESPACE_URL, f"scan-plan:{target.scan_id}:{candidate_key}")),
            scan_id=target.scan_id,
            model_name=self.model_name,
            prompt_version=PLAN_PROMPT_VERSION,
            prompt_sha256=PLAN_PROMPT_SHA256,
            status="PENDING_APPROVAL",
            budget=Budget(
                requests_already_used=requests_already_used,
                estimated_execution_requests=estimated,
                max_requests=target.safety_policy.max_requests,
                within_budget=(
                    requests_already_used + estimated
                    <= target.safety_policy.max_requests
                ),
            ),
            steps=steps,
        )

    def _build_ai_report(
        self, result: ScanResult, draft: ReportDraft
    ) -> AiReport:
        finding_ids = [finding.finding_id for finding in result.findings]
        draft_ids = [finding.finding_id for finding in draft.findings]
        if len(draft_ids) != len(set(draft_ids)):
            raise LLMError(
                "LLM_REPORT_DUPLICATE",
                "report contains a duplicate finding_id",
            )
        if set(draft_ids) != set(finding_ids):
            raise self._hallucinated_reference(
                "report finding_id set does not match scan_result"
            )

        source_by_id = {finding.finding_id: finding for finding in result.findings}
        report_findings = [
            self._merge_report_finding(
                result.scan_id, source_by_id[item.finding_id], item
            )
            for item in draft.findings
        ]
        risk = max(
            (finding.severity for finding in report_findings),
            key=SEVERITY_ORDER.__getitem__,
        )
        return AiReport(
            schema_version="1.2",
            scan_id=result.scan_id,
            model_name=self.model_name,
            prompt_version=REPORT_PROMPT_VERSION,
            prompt_sha256=REPORT_PROMPT_SHA256,
            overall_risk=risk,
            overall_risk_basis="rule:max_verified_severity",
            summary=(
                f"규칙 기반 검증으로 확정된 취약점 {len(report_findings)}건이 "
                f"확인되었으며 최고 심각도는 {risk}입니다."
            ),
            findings=report_findings,
        )

    @staticmethod
    def _merge_report_finding(
        scan_id: str, source: Finding, item: Any
    ) -> ReportFinding:
        return ReportFinding(
            finding_id=source.finding_id,
            analysis_id=str(
                uuid5(
                    NAMESPACE_URL,
                    f"finding-analysis:{scan_id}:{source.finding_id}",
                )
            ),
            root_cause=item.root_cause,
            attack_flow=item.attack_flow,
            impact=item.impact,
            recommendation=item.recommendation,
            severity=item.severity,
            evidence_refs=source.evidence_refs,
        )

    def _validate_analysis_against_graph(
        self,
        target: TargetProfile,
        graph: NormalizedApiGraph,
        analysis: RelationshipAnalysis,
    ) -> None:
        operations = {operation.operation_id: operation for operation in graph.operations}
        expected_modules = [
            MODULE_MAP[category]
            for category in target.safety_policy.approved_modules
        ]
        if analysis.approved_module_ids != expected_modules:
            raise LLMError(
                "LLM_PLAN_MODULE_NOT_APPROVED",
                "approved_module_ids does not match target_profile",
            )
        for relationship in analysis.relationships:
            source = operations.get(relationship.source_operation_id)
            target_operation = operations.get(relationship.target_operation_id)
            if source is None or target_operation is None:
                raise self._hallucinated_reference(
                    "relationship references an unknown operation"
                )
            if relationship.source_field is not None and relationship.source_field not in {
                field.field_path for field in source.outputs
            }:
                raise self._hallucinated_reference(
                    "relationship references an unknown output field"
                )
            if relationship.target_parameter is not None and (
                relationship.target_parameter,
                relationship.target_parameter_location,
            ) not in {
                (field.field_path, field.location)
                for field in target_operation.inputs
            }:
                raise self._hallucinated_reference(
                    "relationship references an unknown input parameter"
                )
        for candidate in analysis.test_candidates:
            operation = operations.get(candidate.target_operation_id)
            if (
                candidate.module_id not in expected_modules
                or operation is None
            ):
                raise LLMError(
                    "LLM_PLAN_MODULE_NOT_APPROVED",
                    "candidate module or operation is not approved",
                )
            input_refs = {
                (field.field_path, field.location)
                for field in operation.inputs
            }
            if any(
                (hint.parameter, hint.location) not in input_refs
                for hint in candidate.binding_hints
            ):
                raise self._hallucinated_reference(
                    "candidate binding references an unknown input parameter"
                )

    @staticmethod
    def _validate_plan_order(
        candidates: list[TestCandidate], draft: PlanDraft
    ) -> list[str]:
        expected = {candidate.candidate_id for candidate in candidates}
        actual = draft.ordered_candidate_ids
        if len(actual) != len(set(actual)) or set(actual) != expected:
            raise LLMError(
                "LLM_PLAN_INVALID_OUTPUT",
                "ordered_candidate_ids must contain each executable candidate once",
                retryable=True,
            )
        return actual

    @staticmethod
    def _execution_hints(operation: Operation) -> list[BindingHint]:
        hints: list[BindingHint] = []
        for field in operation.inputs:
            if field.location not in {"path", "query"}:
                continue
            is_object = LLMService._looks_like_identifier(field.field_path)
            hints.append(
                BindingHint(
                    parameter=field.field_path,
                    location=field.location,
                    binding_type=(
                        "object_binding" if is_object else "parameter_binding"
                    ),
                    object_type=(
                        LLMService._object_type(
                            field.field_path, operation.path_template
                        )
                        if is_object
                        else None
                    ),
                )
            )
        return hints

    @staticmethod
    def _object_type(parameter: str, path_template: str) -> str:
        leaf = parameter.rsplit(".", 1)[-1].replace("[]", "").casefold()
        if leaf == "account_number":
            return "account"
        if leaf.endswith("_id") and len(leaf) > 3:
            return leaf[:-3]
        segments = [
            segment
            for segment in path_template.split("/")
            if segment and not segment.startswith("{")
        ]
        resource = segments[-1] if segments else "object"
        return resource[:-1] if resource.endswith("s") else resource

    @staticmethod
    def _looks_like_identifier(field_path: str) -> bool:
        leaf = field_path.rsplit(".", 1)[-1].replace("[]", "").lower()
        return (
            leaf == "id"
            or leaf.endswith("_id")
            or leaf == "account_number"
        )

    @staticmethod
    def _operation_in_scope(
        target: TargetProfile, operation: Operation
    ) -> bool:
        if operation.method not in target.target.allowed_methods:
            return False
        if operation.path_template == target.authentication.login.path:
            return False
        return any(
            fnmatchcase(operation.path_template, pattern)
            for pattern in target.target.allowed_paths
        )

    @staticmethod
    def _prompt_input(payload: dict[str, Any]) -> str:
        serialized = json.dumps(
            payload,
            ensure_ascii=False,
            separators=(",", ":"),
            allow_nan=False,
        )
        return f"<input_data>\n{serialized}\n</input_data>"

    @staticmethod
    def _hallucinated_reference(message: str) -> LLMError:
        return LLMError(
            "LLM_HALLUCINATED_REFERENCE", message, retryable=True
        )

    @staticmethod
    def _retry_instruction(error_code: str) -> str | None:
        if error_code == "LLM_HALLUCINATED_REFERENCE":
            return (
                "이전 출력에 입력에 없는 참조가 있었음. operation, field, parameter와 "
                "finding 참조를 입력 JSON에 다시 대조하여 재생성함."
            )
        if error_code == "LLM_PLAN_INVALID_OUTPUT":
            return (
                "이전 출력의 후보 집합이 잘못됨. executable candidate_id를 각각 "
                "정확히 한 번 포함하여 재생성함."
            )
        return None

    @staticmethod
    def _require_same_scan_id(*scan_ids: str) -> None:
        if len(set(scan_ids)) != 1:
            raise LLMError(
                "LLM_INVALID_INPUT", "scan_id must match across all inputs"
            )

    @staticmethod
    def _validate_input(model: type[T], value: dict[str, Any] | T) -> T:
        try:
            return value if isinstance(value, model) else model.model_validate(value)
        except ValidationError as error:
            raise LLMError("LLM_INVALID_INPUT", str(error)) from error

    @staticmethod
    def _default_client() -> Any:
        try:
            from openai import OpenAI
        except ImportError as error:
            raise LLMError(
                "LLM_CLIENT_ERROR",
                "openai package is not installed; run pip install -e .",
            ) from error
        try:
            return OpenAI()
        except Exception as error:
            raise LLMError("LLM_AUTH_ERROR", str(error)) from error

    @staticmethod
    def _map_client_error(stage: str, error: Exception) -> LLMError:
        name = type(error).__name__.lower()
        status = getattr(error, "status_code", None)
        message = str(error)
        if "timeout" in name:
            return LLMError(f"LLM_{stage}_TIMEOUT", message, retryable=True)
        if status == 429 or "ratelimit" in name:
            return LLMError("LLM_RATE_LIMITED", message, retryable=True)
        if status in {401, 403} or "authentication" in name:
            return LLMError("LLM_AUTH_ERROR", message)
        if status is not None and status >= 500:
            return LLMError("LLM_UPSTREAM_ERROR", message, retryable=True)
        if status is not None and status >= 400:
            return LLMError("LLM_REQUEST_REJECTED", message)
        return LLMError("LLM_CLIENT_ERROR", message)
