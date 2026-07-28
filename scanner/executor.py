"""Scanner-owned plan approval and fixed-module execution boundary."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from urllib.parse import urljoin

from scanner.artifacts import REDACTED, ArtifactBuilder, Redactor
from scanner.audit import AuditEvent, AuditSink, InMemoryAuditSink
from scanner.auth.session_manager import RuntimeContext
from scanner.contracts import (
    AffectedField,
    ApprovalStatus,
    BindingHint,
    EvidenceArtifact,
    EvidenceObservation,
    Finding,
    InputBinding,
    NormalizedApiGraph,
    Operation,
    PlanApprovalDecision,
    RelationshipAnalysis,
    ScanPlan,
    ScanResult,
    ScanStep,
    TestCandidate,
    TargetProfile,
    Verification,
    VulnerabilityType,
)
from scanner.http_client import SafeHttpClient, ScannerRequestError
from scanner.integration.backend_client import (
    BackendClient,
    JobKind,
    ScannerErrorReport,
    ScannerStage,
)
from scanner.modules.base import (
    BindingError,
    ModuleExecutionContext,
    ModuleOutcome,
    ModuleVerdict,
)
from scanner.modules.bola import BolaModule
from scanner.modules.data_exposure import DataExposureModule
from scanner.modules.input_validation import InputValidationModule
from scanner.policy import (
    BudgetExceeded,
    CancellationGuard,
    CancellationRequested,
    PolicyViolation,
    path_is_allowed,
)


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
_MODULE_RESULT_CONTRACTS = {
    "BOLA-001": (
        VulnerabilityType.BOLA,
        "VERIFY-BOLA-001",
        ("BOLA_FOREIGN_OBJECT_RETURNED",),
    ),
    "INPUT-001": (
        VulnerabilityType.INPUT_VALIDATION,
        "VERIFY-INPUT-001",
        ("INPUT_INVALID_VALUE_EXPANDED_SCOPE",),
    ),
    "DATA-001": (
        VulnerabilityType.DATA_EXPOSURE,
        "VERIFY-DATA-001",
        ("DATA_SENSITIVE_FIELD_UNMASKED",),
    ),
}
_SAFE_INCONCLUSIVE_REASON_CODES = frozenset(
    {
        "BOLA_BASELINE_FAILED",
        "BOLA_BINDING_UNAVAILABLE",
        "BOLA_NON_GET_OPERATION",
        "BOLA_PATH_UNSAFE",
        "BOLA_POLICY_PREFLIGHT_FAILED",
        "BOLA_RESPONSE_NOT_JSON",
        "BOLA_SESSION_UNAVAILABLE",
        "BOLA_VARIANT_FAILED",
        "DATA_BINDING_UNAVAILABLE",
        "DATA_NON_GET_OPERATION",
        "DATA_POLICY_PREFLIGHT_FAILED",
        "DATA_RESPONSE_UNAVAILABLE",
        "DATA_SESSION_UNAVAILABLE",
        "INPUT_BASELINE_UNAVAILABLE",
        "INPUT_BINDING_UNAVAILABLE",
        "INPUT_COMPARISON_UNAVAILABLE",
        "INPUT_NON_GET_OPERATION",
        "INPUT_POLICY_PREFLIGHT_FAILED",
        "INPUT_SESSION_UNAVAILABLE",
        "INPUT_UNSAFE_INPUT_LOCATION",
    }
)
_OPAQUE_EVIDENCE_REFERENCE = re.compile(
    r"artifact:[A-Za-z0-9][A-Za-z0-9._-]*"
)
_MIN_RUNTIME_SUBSTRING_LENGTH = 4


def module_for_policy(policy: str) -> str | None:
    return _POLICY_MODULE_IDS.get(policy)


def policy_for_module(module_id: str) -> str | None:
    return _MODULE_POLICIES.get(module_id)


class Executor:
    def __init__(
        self,
        backend: BackendClient,
        modules: Mapping[str, object] | None = None,
        *,
        client: SafeHttpClient | None = None,
        artifact_builder: ArtifactBuilder | None = None,
        audit_sink: AuditSink | None = None,
    ) -> None:
        self._backend = backend
        self._modules = dict(modules) if modules is not None else {
            "BOLA-001": BolaModule(),
            "INPUT-001": InputValidationModule(),
            "DATA-001": DataExposureModule(),
        }
        self._client = client
        self._artifact_builder = artifact_builder or ArtifactBuilder(Redactor())
        self._audit_sink = audit_sink or InMemoryAuditSink()

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
        self._backend.report_approval(
            job_id,
            decision,
            scan_id=profile.scan_id,
            job_kind=JobKind.EXECUTION,
        )
        return decision

    def execute(
        self,
        *,
        job_id: str,
        profile: TargetProfile,
        graph: NormalizedApiGraph,
        analysis: RelationshipAnalysis,
        plan: ScanPlan,
        runtime: RuntimeContext,
        decision: PlanApprovalDecision,
    ) -> ScanResult:
        sensitive_values = runtime.sensitive_values()
        safe_scan_id = (
            profile.scan_id
            if _external_text_is_safe(profile.scan_id, sensitive_values)
            else REDACTED
        )
        result = ScanResult(scan_id=safe_scan_id, findings=[])
        if decision.status is not ApprovalStatus.APPROVED:
            return result
        if not all(
            _external_text_is_safe(value, sensitive_values)
            for value in (
                profile.scan_id,
                graph.scan_id,
                analysis.scan_id,
                plan.scan_id,
                runtime.scan_id,
                decision.scan_id,
                plan.plan_id,
                decision.plan_id,
            )
        ):
            self._report_failure(
                job_id,
                safe_scan_id,
                backend_scan_id=profile.scan_id,
                code="EXECUTION_STEP_INVALID",
                stage=ScannerStage.EXECUTING,
                retryable=False,
            )
            return result
        if (
            decision.scan_id != profile.scan_id
            or decision.plan_id != plan.plan_id
            or plan.scan_id != profile.scan_id
            or graph.scan_id != profile.scan_id
            or analysis.scan_id != profile.scan_id
            or runtime.scan_id != profile.scan_id
        ):
            self._report_failure(
                job_id,
                safe_scan_id,
                code="EXECUTION_DECISION_INVALID",
                stage=ScannerStage.EXECUTING,
                retryable=False,
            )
            return result
        if not plan.steps:
            return result
        if self._client is None:
            self._report_failure(
                job_id,
                safe_scan_id,
                code="EXECUTION_CLIENT_UNAVAILABLE",
                stage=ScannerStage.EXECUTING,
                retryable=False,
            )
            return result

        operations = {
            operation.operation_id: operation for operation in graph.operations
        }
        candidates = {
            candidate.candidate_id: candidate
            for candidate in analysis.test_candidates
        }
        cancellation = CancellationGuard(
            self._backend,
            scan_id=profile.scan_id,
            job_kind=JobKind.EXECUTION,
        )
        findings: dict[str, Finding] = {}
        for step in plan.steps:
            try:
                cancellation.raise_if_cancelled(job_id)
            except CancellationRequested:
                self._emit(
                    code="EXECUTION_CANCELLED",
                    level="INFO",
                    job_id=job_id,
                    scan_id=safe_scan_id,
                    operation_id=None,
                    module_id=(
                        step.module_id
                        if step.module_id in REQUEST_ESTIMATES
                        else None
                    ),
                )
                raise

            if step.module_id not in REQUEST_ESTIMATES:
                self._report_failure(
                    job_id,
                    safe_scan_id,
                    code="EXECUTION_MODULE_NOT_APPROVED",
                    stage=ScannerStage.EXECUTING,
                    retryable=False,
                    operation_id=None,
                    module_id=None,
                )
                break
            operation = operations.get(step.target_operation_id)
            candidate = candidates.get(step.candidate_id)
            if not _step_external_identifiers_are_safe(
                step=step,
                operation=operation,
                candidate=candidate,
                sensitive_values=sensitive_values,
            ):
                self._report_failure(
                    job_id,
                    safe_scan_id,
                    code="EXECUTION_STEP_INVALID",
                    stage=ScannerStage.EXECUTING,
                    retryable=False,
                    operation_id=None,
                    module_id=step.module_id,
                )
                break
            if not self._execution_step_is_valid(
                profile=profile,
                analysis=analysis,
                step=step,
                operation=operation,
                candidate=candidate,
            ):
                self._report_failure(
                    job_id,
                    safe_scan_id,
                    code="EXECUTION_STEP_INVALID",
                    stage=ScannerStage.EXECUTING,
                    retryable=False,
                    operation_id=(
                        operation.operation_id if operation is not None else None
                    ),
                    module_id=step.module_id,
                )
                break
            module = self._modules.get(step.module_id)
            run = getattr(module, "run", None)
            if not callable(run):
                self._report_failure(
                    job_id,
                    safe_scan_id,
                    code="EXECUTION_MODULE_UNAVAILABLE",
                    stage=ScannerStage.EXECUTING,
                    retryable=False,
                    operation_id=step.target_operation_id,
                    module_id=step.module_id,
                )
                break

            try:
                self._client.preflight(
                    operation.method,
                    urljoin(
                        f"{profile.target.base_url.rstrip('/')}/",
                        operation.path_template.lstrip("/"),
                    ),
                    module_id=step.module_id,
                )
                self._client.ensure_capacity(REQUEST_ESTIMATES[step.module_id])
            except CancellationRequested:
                self._emit(
                    code="EXECUTION_CANCELLED",
                    level="INFO",
                    job_id=job_id,
                    scan_id=safe_scan_id,
                    operation_id=operation.operation_id,
                    module_id=step.module_id,
                )
                raise
            except BudgetExceeded:
                self._report_failure(
                    job_id,
                    safe_scan_id,
                    code="EXECUTION_REQUEST_BUDGET_EXCEEDED",
                    stage=ScannerStage.EXECUTING,
                    retryable=False,
                    operation_id=operation.operation_id,
                    module_id=step.module_id,
                )
                break
            except PolicyViolation:
                self._report_failure(
                    job_id,
                    safe_scan_id,
                    code="EXECUTION_POLICY_DENIED",
                    stage=ScannerStage.EXECUTING,
                    retryable=False,
                    operation_id=operation.operation_id,
                    module_id=step.module_id,
                )
                break

            context = ModuleExecutionContext(
                scan_id=safe_scan_id,
                base_url=profile.target.base_url,
                operation=operation,
                step=step,
                runtime=runtime,
                client=self._client,
            )
            try:
                outcome = run(context)
            except CancellationRequested:
                self._emit(
                    code="EXECUTION_CANCELLED",
                    level="INFO",
                    job_id=job_id,
                    scan_id=safe_scan_id,
                    operation_id=operation.operation_id,
                    module_id=step.module_id,
                )
                raise
            except BudgetExceeded:
                self._report_failure(
                    job_id,
                    safe_scan_id,
                    code="EXECUTION_REQUEST_BUDGET_EXCEEDED",
                    stage=ScannerStage.EXECUTING,
                    retryable=False,
                    operation_id=operation.operation_id,
                    module_id=step.module_id,
                )
                break
            except PolicyViolation:
                self._report_failure(
                    job_id,
                    safe_scan_id,
                    code="EXECUTION_POLICY_DENIED",
                    stage=ScannerStage.EXECUTING,
                    retryable=False,
                    operation_id=operation.operation_id,
                    module_id=step.module_id,
                )
                continue
            except BindingError:
                self._report_failure(
                    job_id,
                    safe_scan_id,
                    code="EXECUTION_BINDING_FAILED",
                    stage=ScannerStage.EXECUTING,
                    retryable=False,
                    operation_id=operation.operation_id,
                    module_id=step.module_id,
                )
                continue
            except ScannerRequestError:
                self._report_failure(
                    job_id,
                    safe_scan_id,
                    code="EXECUTION_REQUEST_FAILED",
                    stage=ScannerStage.EXECUTING,
                    retryable=True,
                    operation_id=operation.operation_id,
                    module_id=step.module_id,
                )
                continue
            except Exception:
                self._report_failure(
                    job_id,
                    safe_scan_id,
                    code="EXECUTION_MODULE_FAILED",
                    stage=ScannerStage.EXECUTING,
                    retryable=False,
                    operation_id=operation.operation_id,
                    module_id=step.module_id,
                )
                continue

            if (
                not isinstance(outcome, ModuleOutcome)
                or type(outcome.verdict) is not ModuleVerdict
                or (
                    outcome.reason_code is not None
                    and not isinstance(outcome.reason_code, str)
                )
            ):
                self._report_failure(
                    job_id,
                    safe_scan_id,
                    code="EXECUTION_MODULE_FAILED",
                    stage=ScannerStage.EXECUTING,
                    retryable=False,
                    operation_id=operation.operation_id,
                    module_id=step.module_id,
                )
                continue
            if outcome.verdict is ModuleVerdict.NOT_FOUND:
                self._emit(
                    code="EXECUTION_MODULE_NOT_FOUND",
                    level="INFO",
                    job_id=job_id,
                    scan_id=safe_scan_id,
                    operation_id=operation.operation_id,
                    module_id=step.module_id,
                )
                continue
            if outcome.verdict is ModuleVerdict.INCONCLUSIVE:
                self._emit(
                    code=(
                        outcome.reason_code
                        if outcome.reason_code in _SAFE_INCONCLUSIVE_REASON_CODES
                        else "EXECUTION_MODULE_INCONCLUSIVE"
                    ),
                    level="WARNING",
                    job_id=job_id,
                    scan_id=safe_scan_id,
                    operation_id=operation.operation_id,
                    module_id=step.module_id,
                )
                continue
            try:
                finding = self._verified_finding(
                    job_id=job_id,
                    scan_id=safe_scan_id,
                    operation=operation,
                    module_id=step.module_id,
                    runtime=runtime,
                    outcome=outcome,
                )
            except Exception:
                self._report_failure(
                    job_id,
                    safe_scan_id,
                    code="EXECUTION_MODULE_FAILED",
                    stage=ScannerStage.VERIFYING,
                    retryable=False,
                    operation_id=operation.operation_id,
                    module_id=step.module_id,
                )
                continue
            if finding is not None:
                findings.setdefault(finding.finding_id, finding)

        return ScanResult(
            scan_id=safe_scan_id,
            findings=sorted(findings.values(), key=lambda finding: finding.finding_id),
        )

    @staticmethod
    def _execution_step_is_valid(
        *,
        profile: TargetProfile,
        analysis: RelationshipAnalysis,
        step: ScanStep,
        operation: Operation | None,
        candidate: TestCandidate | None,
    ) -> bool:
        approved_module_ids = {
            module_id
            for policy in profile.safety_policy.approved_modules
            if (module_id := module_for_policy(policy)) is not None
        }
        if (
            step.module_id not in approved_module_ids
            or set(analysis.approved_module_ids) != approved_module_ids
            or operation is None
            or candidate is None
            or not candidate.executable
        ):
            return False
        reasons: set[str] = set()
        _check_operation(step, operation, profile, reasons)
        return not reasons and _bindings_match(step, candidate, operation)

    def _verified_finding(
        self,
        *,
        job_id: str,
        scan_id: str,
        operation: Operation,
        module_id: str,
        runtime: RuntimeContext,
        outcome: ModuleOutcome,
    ) -> Finding | None:
        contract = _MODULE_RESULT_CONTRACTS[module_id]
        vulnerability_type, rule_id, expected_conditions = contract
        conditions = tuple(sorted(set(outcome.conditions)))
        if outcome.rule_id != rule_id or conditions != expected_conditions:
            self._emit(
                code="EXECUTION_MODULE_INCONCLUSIVE",
                level="WARNING",
                job_id=job_id,
                scan_id=scan_id,
                operation_id=operation.operation_id,
                module_id=module_id,
            )
            return None

        sensitive_values = runtime.sensitive_values()
        affected: dict[tuple[str, str, str], AffectedField] = {}
        for item in outcome.affected_fields:
            if not _external_text_is_safe(item.field_path, sensitive_values):
                raise ValueError("affected field path is invalid")
            cleaned = AffectedField(
                location=item.location,
                field_path=item.field_path,
                data_class=item.data_class,
            )
            affected[
                (cleaned.location, cleaned.field_path, cleaned.data_class)
            ] = cleaned
        affected_fields = tuple(affected[key] for key in sorted(affected))
        if not affected_fields:
            self._emit(
                code="EXECUTION_MODULE_INCONCLUSIVE",
                level="WARNING",
                job_id=job_id,
                scan_id=scan_id,
                operation_id=operation.operation_id,
                module_id=module_id,
            )
            return None

        try:
            evidence_payload = _project_evidence_artifact(
                scan_id=scan_id,
                operation_id=operation.operation_id,
                module_id=module_id,
                rule_id=rule_id,
                conditions=conditions,
                affected_fields=affected_fields,
                outcome_evidence=outcome.evidence,
            )
            envelope = self._artifact_builder.build(
                scan_id=scan_id,
                artifact_type="evidence",
                schema_version=None,
                payload=evidence_payload.model_dump(mode="json"),
                sensitive_values=sensitive_values,
            )
            evidence_ref = self._backend.publish_artifact(
                envelope,
                job_id=job_id,
                scan_id=scan_id,
                job_kind=JobKind.EXECUTION,
            )
            if (
                not isinstance(evidence_ref, str)
                or _OPAQUE_EVIDENCE_REFERENCE.fullmatch(evidence_ref) is None
                or not _external_text_is_safe(evidence_ref, sensitive_values)
            ):
                raise ValueError("evidence reference is invalid")
        except Exception:
            self._report_failure(
                job_id,
                scan_id,
                code="EXECUTION_EVIDENCE_PUBLISH_FAILED",
                stage=ScannerStage.VERIFYING,
                retryable=True,
                operation_id=operation.operation_id,
                module_id=module_id,
            )
            return None

        finding_id = _finding_id(
            scan_id=scan_id,
            operation_id=operation.operation_id,
            rule_id=rule_id,
            conditions=conditions,
            affected_field_paths=tuple(
                sorted(item.field_path for item in affected_fields)
            ),
        )
        return Finding(
            finding_id=finding_id,
            operation_id=operation.operation_id,
            vulnerability_type=vulnerability_type,
            verification=Verification(
                rule_id=rule_id,
                verified_conditions=list(conditions),
            ),
            affected_fields=list(affected_fields),
            evidence_refs=[evidence_ref],
        )
    def _report_failure(
        self,
        job_id: str,
        scan_id: str,
        *,
        backend_scan_id: str | None = None,
        code: str,
        stage: ScannerStage,
        retryable: bool,
        operation_id: str | None = None,
        module_id: str | None = None,
    ) -> None:
        self._backend.report_error(
            job_id,
            ScannerErrorReport(
                code=code,
                stage=stage,
                retryable=retryable,
            ),
            scan_id=backend_scan_id or scan_id,
            job_kind=JobKind.EXECUTION,
        )
        self._emit(
            code=code,
            level="WARNING",
            job_id=job_id,
            scan_id=scan_id,
            operation_id=operation_id,
            module_id=module_id,
        )

    def _emit(
        self,
        *,
        code: str,
        level: str,
        job_id: str,
        scan_id: str,
        operation_id: str | None,
        module_id: str | None,
    ) -> None:
        self._audit_sink.emit(
            AuditEvent(
                code=code,
                level=level,
                job_id=job_id,
                scan_id=scan_id,
                operation_id=operation_id,
                module_id=module_id,
                details={},
            )
        )


def _project_evidence_artifact(
    *,
    scan_id: str,
    operation_id: str,
    module_id: str,
    rule_id: str,
    conditions: tuple[str, ...],
    affected_fields: tuple[AffectedField, ...],
    outcome_evidence: Mapping[str, object],
) -> EvidenceArtifact:
    if not isinstance(outcome_evidence, Mapping):
        raise ValueError("module evidence is invalid")
    if module_id == "DATA-001":
        response = outcome_evidence.get("response")
        baseline_source = response
        variant_source = response
    else:
        baseline_source = outcome_evidence.get("baseline")
        variant_source = outcome_evidence.get("variant")

    observed_field_paths = tuple(
        sorted({item.field_path for item in affected_fields})
    )
    baseline = _project_evidence_observation(
        baseline_source,
        observed_field_paths=observed_field_paths,
    )
    variant = _project_evidence_observation(
        variant_source,
        observed_field_paths=observed_field_paths,
    )
    return EvidenceArtifact(
        scan_id=scan_id,
        operation_id=operation_id,
        module_id=module_id,
        rule_id=rule_id,
        verified_conditions=list(conditions),
        affected_fields=list(affected_fields),
        baseline=baseline,
        variant=variant,
    )


def _project_evidence_observation(
    source: object,
    *,
    observed_field_paths: tuple[str, ...],
) -> EvidenceObservation:
    if not isinstance(source, Mapping):
        raise ValueError("module evidence observation is invalid")
    status_code = source.get("status_code")
    if type(status_code) is not int:
        raise ValueError("module evidence status is invalid")
    json_body = source.get("json_body")
    structure = _response_structure(json_body)
    encoded_structure = json.dumps(
        structure,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return EvidenceObservation(
        actor_id="user_a",
        status_code=status_code,
        response_structure_sha256=hashlib.sha256(encoded_structure).hexdigest(),
        observed_field_paths=list(observed_field_paths),
    )


def _response_structure(value: object) -> object:
    if isinstance(value, Mapping):
        fields = [_response_structure(item) for item in value.values()]
        return {
            "type": "object",
            "fields": sorted(
                fields,
                key=lambda field: json.dumps(
                    field, sort_keys=True, separators=(",", ":")
                ),
            ),
        }
    if isinstance(value, (list, tuple)):
        structures = {
            json.dumps(
                _response_structure(item),
                sort_keys=True,
                separators=(",", ":"),
            )
            for item in value
        }
        return {
            "type": "array",
            "items": [json.loads(item) for item in sorted(structures)],
        }
    if value is None:
        return {"type": "null"}
    if type(value) is bool:
        return {"type": "boolean"}
    if type(value) is int:
        return {"type": "integer"}
    if type(value) is float:
        return {"type": "number"}
    if isinstance(value, str):
        return {"type": "string"}
    return {"type": "unknown"}


def _external_text_is_safe(
    value: str,
    sensitive_values: set[str],
) -> bool:
    runtime_strings = {item for item in sensitive_values if item}
    if value in runtime_strings:
        return False
    cleaned = Redactor().redact(
        value,
        {
            item
            for item in runtime_strings
            if len(item) >= _MIN_RUNTIME_SUBSTRING_LENGTH
        },
    )
    return isinstance(cleaned, str) and cleaned == value


def _step_external_identifiers_are_safe(
    *,
    step: ScanStep,
    operation: Operation | None,
    candidate: TestCandidate | None,
    sensitive_values: set[str],
) -> bool:
    values = [
        step.candidate_id,
        step.target_operation_id,
        step.target_endpoint.path_template,
        *(binding.parameter for binding in step.input_bindings),
    ]
    if operation is not None:
        values.extend(
            (
                operation.operation_id,
                operation.path_template,
                *(input_field.field_path for input_field in operation.inputs),
            )
        )
    if candidate is not None:
        values.extend(
            (
                candidate.candidate_id,
                candidate.target_operation_id,
                *(hint.parameter for hint in candidate.binding_hints),
            )
        )
    return all(
        _external_text_is_safe(value, sensitive_values) for value in values
    )


def _finding_id(
    *,
    scan_id: str,
    operation_id: str,
    rule_id: str,
    conditions: tuple[str, ...],
    affected_field_paths: tuple[str, ...],
) -> str:
    material = json.dumps(
        {
            "affected_field_paths": list(affected_field_paths),
            "conditions": list(conditions),
            "operation_id": operation_id,
            "rule_id": rule_id,
            "scan_id": scan_id,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return f"finding-{hashlib.sha256(material).hexdigest()[:24]}"


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
