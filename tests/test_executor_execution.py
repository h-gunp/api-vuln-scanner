from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass

import httpx
import pytest

from scanner.artifacts import ArtifactBuilder, Redactor
from scanner.audit import InMemoryAuditSink
from scanner.auth.session_manager import ActorSession, RuntimeContext, SessionManager
from scanner.contracts import (
    AffectedField,
    ApprovalStatus,
    NormalizedApiGraph,
    PlanApprovalDecision,
    RelationshipAnalysis,
    ScanPlan,
    ScanResult,
    VulnerabilityType,
)
from scanner.executor import Executor
from scanner.http_client import SafeHttpClient
from scanner.integration.backend_client import FakeBackendClient
from scanner.modules.base import ModuleOutcome, ModuleVerdict
from scanner.policy import CancellationGuard, PolicyEnforcer, RequestBudget


@dataclass(frozen=True)
class ExecutionDocuments:
    profile: object
    graph: NormalizedApiGraph
    analysis: RelationshipAnalysis
    plan: ScanPlan


class FixedOutcomeModule:
    def __init__(
        self,
        outcome: ModuleOutcome,
        *,
        requests: int = 0,
        backend_to_cancel: FakeBackendClient | None = None,
        error: Exception | None = None,
    ) -> None:
        self._outcome = outcome
        self._requests = requests
        self._backend_to_cancel = backend_to_cancel
        self._error = error
        self.calls = []

    def run(self, context):
        self.calls.append(context)
        for _ in range(self._requests):
            context.client.request(
                "GET",
                f"{context.base_url}/api/executor-probe",
                module_id=context.step.module_id,
                follow_redirects=False,
            )
        if self._backend_to_cancel is not None:
            self._backend_to_cancel.cancel("job-001")
        if self._error is not None:
            raise self._error
        return self._outcome


class SequenceModule:
    def __init__(self, outcomes: Iterable[ModuleOutcome]) -> None:
        self._outcomes = iter(outcomes)
        self.calls = []

    def run(self, context):
        self.calls.append(context)
        return next(self._outcomes)


class FailingArtifactBackend(FakeBackendClient):
    def publish_artifact(self, envelope):
        raise RuntimeError("raw-backend-secret")


class SecretReferenceBackend(FakeBackendClient):
    def publish_artifact(self, envelope):
        return "runtime-token-a"


def _documents(
    module_ids: tuple[str, ...] = ("BOLA-001", "INPUT-001", "DATA-001"),
    *,
    max_requests: int = 20,
    requests_already_used: int = 3,
) -> ExecutionDocuments:
    from scanner.contracts import TargetProfile

    profile = TargetProfile.model_validate(
        {
            "schema_version": "1.1",
            "scan_id": "scan-001",
            "target": {
                "base_url": "https://scanner.test",
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
                    {
                        "actor_id": "user_a",
                        "username_env": "SCANNER_USER_A",
                        "password_env": "SCANNER_PASS_A",
                    },
                    {
                        "actor_id": "user_b",
                        "username_env": "SCANNER_USER_B",
                        "password_env": "SCANNER_PASS_B",
                    },
                ],
            },
            "safety_policy": {
                "max_requests": max_requests,
                "requests_per_second": 1000,
                "state_change_policy": "deny",
                "approved_modules": [
                    "authz",
                    "input_validation",
                    "data_exposure",
                ],
            },
        }
    )
    operations = {
        "BOLA-001": {
            "operation_id": "get-account",
            "method": "GET",
            "path_template": "/api/accounts/{account_id}",
            "inputs": [
                {
                    "location": "path",
                    "field_path": "account_id",
                    "type": "string",
                }
            ],
            "outputs": [],
        },
        "INPUT-001": {
            "operation_id": "list-items",
            "method": "GET",
            "path_template": "/api/items",
            "inputs": [
                {"location": "query", "field_path": "q", "type": "string"}
            ],
            "outputs": [],
        },
        "DATA-001": {
            "operation_id": "get-profile",
            "method": "GET",
            "path_template": "/api/profile",
            "inputs": [],
            "outputs": [],
        },
        "AUTHN-001": {
            "operation_id": "authn-operation",
            "method": "GET",
            "path_template": "/api/authn",
            "inputs": [],
            "outputs": [],
        },
        "TRANSACTION-001": {
            "operation_id": "transaction-operation",
            "method": "GET",
            "path_template": "/api/transactions",
            "inputs": [],
            "outputs": [],
        },
        "UNKNOWN-001": {
            "operation_id": "unknown-operation",
            "method": "GET",
            "path_template": "/api/unknown",
            "inputs": [],
            "outputs": [],
        },
    }
    graph = NormalizedApiGraph(
        scan_id="scan-001",
        operations=[operations[module_id] for module_id in module_ids],
    )
    candidates = []
    steps = []
    estimates = {"BOLA-001": 2, "INPUT-001": 2, "DATA-001": 1}
    for order, module_id in enumerate(module_ids, start=1):
        operation = operations[module_id]
        input_bindings = []
        binding_hints = []
        if module_id == "BOLA-001":
            input_bindings = [
                {
                    "parameter": "account_id",
                    "location": "path",
                    "binding_type": "object_binding",
                    "object_type": "account",
                    "owner": "user_b",
                }
            ]
            binding_hints = [
                {
                    "parameter": "account_id",
                    "location": "path",
                    "binding_type": "object_binding",
                    "object_type": "account",
                }
            ]
        elif module_id == "INPUT-001":
            input_bindings = [
                {
                    "parameter": "q",
                    "location": "query",
                    "binding_type": "parameter_binding",
                }
            ]
            binding_hints = [
                {
                    "parameter": "q",
                    "location": "query",
                    "binding_type": "parameter_binding",
                }
            ]
        candidates.append(
            {
                "candidate_id": f"candidate-{order}",
                "module_id": module_id,
                "target_operation_id": operation["operation_id"],
                "required_object_types": [],
                "rationale": "fixed execution fixture",
                "priority": order,
                "executable": True,
                "missing_requirements": [],
                "binding_hints": binding_hints,
            }
        )
        steps.append(
            {
                "order": order,
                "candidate_id": f"candidate-{order}",
                "module_id": module_id,
                "target_operation_id": operation["operation_id"],
                "target_endpoint": {
                    "method": operation["method"],
                    "path_template": operation["path_template"],
                },
                "input_bindings": input_bindings,
            }
        )
    analysis = RelationshipAnalysis.model_validate(
        {
            "schema_version": "1.2",
            "scan_id": "scan-001",
            "model_name": "test-model",
            "prompt_version": "1",
            "prompt_sha256": "a" * 64,
            "approved_module_ids": [
                "BOLA-001",
                "INPUT-001",
                "DATA-001",
            ],
            "relationships": [],
            "test_candidates": candidates,
        }
    )
    plan = ScanPlan.model_validate(
        {
            "schema_version": "1.2",
            "plan_id": "plan-001",
            "scan_id": "scan-001",
            "model_name": "test-model",
            "prompt_version": "1",
            "prompt_sha256": "b" * 64,
            "status": "PENDING_APPROVAL",
            "budget": {
                "requests_already_used": requests_already_used,
                "estimated_execution_requests": sum(
                    estimates.get(module_id, 0) for module_id in module_ids
                ),
                "max_requests": max_requests,
                "within_budget": True,
            },
            "steps": steps,
        }
    )
    return ExecutionDocuments(profile, graph, analysis, plan)


def _runtime() -> RuntimeContext:
    runtime = RuntimeContext(
        scan_id="scan-001",
        sessions={
            "user_a": ActorSession(actor_id="user_a", token="runtime-token-a"),
            "user_b": ActorSession(actor_id="user_b", token="runtime-token-b"),
        },
    )
    SessionManager._collect_examples(
        runtime.parameter_examples,
        runtime.observed_parameter_examples,
        {},
        "list-items",
        "query",
        {"q": "runtime-query-value"},
    )
    runtime.object_ids = {
        "user_a": {"account": set()},
        "user_b": {"account": set()},
    }
    runtime.credentials = set()
    return runtime


def _decision(status: ApprovalStatus = ApprovalStatus.APPROVED):
    return PlanApprovalDecision(
        scan_id="scan-001",
        plan_id="plan-001",
        status=status,
        reason_codes=() if status is ApprovalStatus.APPROVED else ("REJECTED",),
    )


def _not_found(rule_id: str) -> ModuleOutcome:
    return ModuleOutcome(
        verdict=ModuleVerdict.NOT_FOUND,
        rule_id=rule_id,
        reason_code="FIXED_NOT_FOUND",
    )


def _verified(
    *,
    rule_id: str = "VERIFY-DATA-001",
    condition: str = "DATA_SENSITIVE_FIELD_UNMASKED",
    affected_fields: tuple[AffectedField, ...] | None = None,
    evidence: dict[str, object] | None = None,
) -> ModuleOutcome:
    return ModuleOutcome(
        verdict=ModuleVerdict.VERIFIED,
        rule_id=rule_id,
        conditions=(condition,),
        affected_fields=affected_fields
        or (
            AffectedField(
                location="response",
                field_path="profile.password",
                data_class="authentication",
            ),
        ),
        evidence=evidence or {"response": "untyped-response-value", "status": 200},
    )


def _execution_dependencies(
    documents: ExecutionDocuments,
    *,
    backend: FakeBackendClient | None = None,
    restored_requests: int | None = None,
):
    backend = backend or FakeBackendClient()
    audit = InMemoryAuditSink()
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(200, json={"ok": True})

    budget = RequestBudget(
        max_requests=documents.profile.safety_policy.max_requests,
        requests_per_second=1000,
        cancellation_guard=CancellationGuard(backend),
        job_id="job-001",
    )
    budget.restore(
        documents.plan.budget.requests_already_used
        if restored_requests is None
        else restored_requests
    )
    client = SafeHttpClient(
        policy=PolicyEnforcer(documents.profile),
        budget=budget,
        transport=httpx.MockTransport(handler),
        audit_sink=audit,
    )
    return backend, audit, budget, client, calls


def _execute(
    documents: ExecutionDocuments,
    *,
    modules: dict[str, object],
    backend: FakeBackendClient | None = None,
    restored_requests: int | None = None,
    decision: PlanApprovalDecision | None = None,
    client: SafeHttpClient | None | object = ...,
) -> tuple[ScanResult, FakeBackendClient, InMemoryAuditSink, RequestBudget, list]:
    backend, audit, budget, resolved_client, calls = _execution_dependencies(
        documents,
        backend=backend,
        restored_requests=restored_requests,
    )
    if client is ...:
        client = resolved_client
    executor = Executor(
        backend,
        modules=modules,
        client=client,
        artifact_builder=ArtifactBuilder(Redactor()),
        audit_sink=audit,
    )
    result = executor.execute(
        job_id="job-001",
        profile=documents.profile,
        graph=documents.graph,
        analysis=documents.analysis,
        plan=documents.plan,
        runtime=_runtime(),
        decision=decision or _decision(),
    )
    return result, backend, audit, budget, calls


def test_approved_steps_route_exact_modules_and_preserve_actual_request_count() -> None:
    documents = _documents()
    modules = {
        "BOLA-001": FixedOutcomeModule(
            _not_found("VERIFY-BOLA-001"),
            requests=2,
        ),
        "INPUT-001": FixedOutcomeModule(
            _not_found("VERIFY-INPUT-001"),
            requests=2,
        ),
        "DATA-001": FixedOutcomeModule(
            _not_found("VERIFY-DATA-001"),
            requests=1,
        ),
    }

    result, _, _, budget, transport_calls = _execute(
        documents,
        modules=modules,
    )

    assert result.findings == []
    assert [len(modules[module_id].calls) for module_id in modules] == [1, 1, 1]
    assert [call.url.path for call in transport_calls] == [
        "/api/executor-probe",
        "/api/executor-probe",
        "/api/executor-probe",
        "/api/executor-probe",
        "/api/executor-probe",
    ]
    assert budget.requests_used == 8


def test_rejected_decision_performs_zero_module_and_transport_requests() -> None:
    documents = _documents(("DATA-001",))
    module = FixedOutcomeModule(_verified(), requests=1)

    result, _, _, budget, transport_calls = _execute(
        documents,
        modules={"DATA-001": module},
        decision=_decision(ApprovalStatus.REJECTED),
    )

    assert result.findings == []
    assert module.calls == []
    assert transport_calls == []
    assert budget.requests_used == 3


def test_cancellation_between_steps_stops_all_remaining_requests() -> None:
    documents = _documents()
    backend = FakeBackendClient()
    modules = {
        "BOLA-001": FixedOutcomeModule(
            _not_found("VERIFY-BOLA-001"),
            requests=2,
            backend_to_cancel=backend,
        ),
        "INPUT-001": FixedOutcomeModule(
            _not_found("VERIFY-INPUT-001"),
            requests=2,
        ),
        "DATA-001": FixedOutcomeModule(
            _not_found("VERIFY-DATA-001"),
            requests=1,
        ),
    }

    result, backend, _, budget, transport_calls = _execute(
        documents,
        backend=backend,
        modules=modules,
    )

    assert result.findings == []
    assert len(modules["BOLA-001"].calls) == 1
    assert modules["INPUT-001"].calls == []
    assert modules["DATA-001"].calls == []
    assert len(transport_calls) == 2
    assert budget.requests_used == 5
    assert backend.error_reports[-1].code == "EXECUTION_CANCELLED"


def test_capacity_exhaustion_before_step_stops_remaining_modules_without_request() -> None:
    documents = _documents()
    modules = {
        "BOLA-001": FixedOutcomeModule(
            _not_found("VERIFY-BOLA-001"),
            requests=2,
        ),
        "INPUT-001": FixedOutcomeModule(
            _not_found("VERIFY-INPUT-001"),
            requests=2,
        ),
        "DATA-001": FixedOutcomeModule(
            _not_found("VERIFY-DATA-001"),
            requests=1,
        ),
    }

    _, backend, _, budget, transport_calls = _execute(
        documents,
        modules=modules,
        restored_requests=17,
    )

    assert len(modules["BOLA-001"].calls) == 1
    assert modules["INPUT-001"].calls == []
    assert modules["DATA-001"].calls == []
    assert len(transport_calls) == 2
    assert budget.requests_used == 19
    assert backend.error_reports[-1].code == "EXECUTION_REQUEST_BUDGET_EXCEEDED"


@pytest.mark.parametrize(
    "forbidden_module_id",
    ["AUTHN-001", "TRANSACTION-001", "UNKNOWN-001"],
)
def test_forged_approved_decision_never_routes_forbidden_modules(
    forbidden_module_id: str,
) -> None:
    documents = _documents((forbidden_module_id,))
    documents.plan.steps[0].target_operation_id = "runtime-token-a"
    forbidden = FixedOutcomeModule(_verified(), requests=1)

    result, backend, audit, budget, transport_calls = _execute(
        documents,
        modules={forbidden_module_id: forbidden},
    )

    assert result.findings == []
    assert forbidden.calls == []
    assert transport_calls == []
    assert budget.requests_used == 3
    assert backend.error_reports[-1].code == "EXECUTION_MODULE_NOT_APPROVED"
    assert audit.events[-1].code == "EXECUTION_MODULE_NOT_APPROVED"
    assert "runtime-token-a" not in repr((backend.error_reports, audit.events))


def test_nonempty_plan_without_shared_client_calls_no_module_and_reports_error() -> None:
    documents = _documents(("DATA-001",))
    module = FixedOutcomeModule(_verified(), requests=1)

    result, backend, audit, _, transport_calls = _execute(
        documents,
        modules={"DATA-001": module},
        client=None,
    )

    assert result.findings == []
    assert module.calls == []
    assert transport_calls == []
    assert backend.error_reports[-1].code == "EXECUTION_CLIENT_UNAVAILABLE"
    assert audit.events[-1].code == "EXECUTION_CLIENT_UNAVAILABLE"


def test_verified_outcome_publishes_redacted_evidence_and_verified_only_finding() -> None:
    documents = _documents(("DATA-001",))
    module = FixedOutcomeModule(
        _verified(
            evidence={
                "authorization": "runtime-token-a",
                "response": "raw-response-secret",
                "status": 200,
            }
        )
    )

    result, backend, _, _, _ = _execute(
        documents,
        modules={"DATA-001": module},
    )

    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.operation_id == "get-profile"
    assert finding.vulnerability_type == VulnerabilityType.DATA_EXPOSURE
    assert finding.verification.rule_id == "VERIFY-DATA-001"
    assert finding.verification.verified_conditions == [
        "DATA_SENSITIVE_FIELD_UNMASKED"
    ]
    assert finding.evidence_refs == ["artifact:1"]
    serialized = result.model_dump_json()
    assert "verdict" not in serialized
    assert "severity" not in serialized
    evidence = backend.fetch_artifact("artifact:1")
    assert b"runtime-token-a" not in evidence
    assert b"raw-response-secret" not in evidence


def test_finding_id_is_stable_for_sorted_conditions_and_affected_field_paths() -> None:
    documents = _documents(("DATA-001", "DATA-001"))
    first = _verified(
        affected_fields=(
            AffectedField(
                location="response",
                field_path="profile.token",
                data_class="authentication",
            ),
            AffectedField(
                location="response",
                field_path="profile.password",
                data_class="authentication",
            ),
        )
    )
    second = _verified(
        affected_fields=tuple(reversed(first.affected_fields)),
    )
    module = SequenceModule((first, second))

    result, _, _, _, _ = _execute(
        documents,
        modules={"DATA-001": module},
    )

    assert len(module.calls) == 2
    assert len(result.findings) == 1
    assert result.findings[0].finding_id == (
        "finding-c5386b92523d8d71ac6d3b70"
    )


def test_not_found_and_inconclusive_outcomes_emit_no_findings_and_audit_events() -> None:
    documents = _documents(("BOLA-001", "INPUT-001"))
    modules = {
        "BOLA-001": FixedOutcomeModule(
            ModuleOutcome(
                verdict=ModuleVerdict.NOT_FOUND,
                rule_id="VERIFY-BOLA-001",
                reason_code="BOLA_FOREIGN_OBJECT_REJECTED",
            )
        ),
        "INPUT-001": FixedOutcomeModule(
            ModuleOutcome(
                verdict=ModuleVerdict.INCONCLUSIVE,
                rule_id="VERIFY-INPUT-001",
                reason_code="INPUT_COMPARISON_UNAVAILABLE",
            )
        ),
    }

    result, _, audit, _, _ = _execute(documents, modules=modules)

    assert result.findings == []
    assert [event.code for event in audit.events[-2:]] == [
        "EXECUTION_MODULE_NOT_FOUND",
        "INPUT_COMPARISON_UNAVAILABLE",
    ]


def test_verified_evidence_upload_failure_becomes_inconclusive_without_finding() -> None:
    documents = _documents(("DATA-001",))
    backend = FailingArtifactBackend()
    module = FixedOutcomeModule(_verified())

    result, backend, audit, _, _ = _execute(
        documents,
        backend=backend,
        modules={"DATA-001": module},
    )

    assert result.findings == []
    assert backend.error_reports[-1].code == "EXECUTION_EVIDENCE_PUBLISH_FAILED"
    assert audit.events[-1].code == "EXECUTION_EVIDENCE_PUBLISH_FAILED"
    assert "raw-backend-secret" not in repr(backend.error_reports)
    assert "raw-backend-secret" not in repr(audit.events)


def test_module_exception_is_reported_without_raw_error_or_runtime_values() -> None:
    documents = _documents(("DATA-001",))
    module = FixedOutcomeModule(
        _verified(),
        error=RuntimeError("runtime-token-a raw-module-secret"),
    )

    result, backend, audit, _, _ = _execute(
        documents,
        modules={"DATA-001": module},
    )

    assert result.findings == []
    assert backend.error_reports[-1].code == "EXECUTION_MODULE_FAILED"
    rendered = json.dumps(
        {
            "backend": repr(backend.error_reports),
            "audit": repr(audit.events),
            "result": result.model_dump(mode="json"),
        }
    )
    assert "runtime-token-a" not in rendered
    assert "raw-module-secret" not in rendered


def test_forged_step_identifier_is_not_copied_to_audit_or_error_state() -> None:
    documents = _documents(("DATA-001",))
    documents.plan.steps[0].target_operation_id = "runtime-token-a"
    module = FixedOutcomeModule(_verified())

    result, backend, audit, _, _ = _execute(
        documents,
        modules={"DATA-001": module},
    )

    assert result.findings == []
    assert module.calls == []
    rendered = repr((backend.error_reports, audit.events))
    assert "runtime-token-a" not in rendered


def test_cancellation_does_not_copy_unvalidated_step_identifier_to_audit() -> None:
    documents = _documents(("DATA-001",))
    documents.plan.steps[0].target_operation_id = "runtime-token-a"
    backend = FakeBackendClient()
    backend.cancel("job-001")
    module = FixedOutcomeModule(_verified())

    result, backend, audit, _, _ = _execute(
        documents,
        backend=backend,
        modules={"DATA-001": module},
    )

    assert result.findings == []
    assert module.calls == []
    assert "runtime-token-a" not in repr((backend.error_reports, audit.events))


def test_malformed_verified_module_outcome_becomes_secret_free_module_failure() -> None:
    documents = _documents(("DATA-001",))
    malformed = ModuleOutcome(
        verdict=ModuleVerdict.VERIFIED,
        rule_id="VERIFY-DATA-001",
        conditions=("DATA_SENSITIVE_FIELD_UNMASKED",),
        affected_fields=("raw-module-secret",),  # type: ignore[arg-type]
        evidence={},
    )
    module = FixedOutcomeModule(malformed)

    result, backend, audit, _, _ = _execute(
        documents,
        modules={"DATA-001": module},
    )

    assert result.findings == []
    assert backend.error_reports[-1].code == "EXECUTION_MODULE_FAILED"
    assert "raw-module-secret" not in repr((backend.error_reports, audit.events))


def test_backend_reference_containing_runtime_secret_is_not_added_to_result() -> None:
    documents = _documents(("DATA-001",))
    backend = SecretReferenceBackend()
    module = FixedOutcomeModule(_verified())

    result, backend, audit, _, _ = _execute(
        documents,
        backend=backend,
        modules={"DATA-001": module},
    )

    assert result.findings == []
    assert backend.error_reports[-1].code == "EXECUTION_EVIDENCE_PUBLISH_FAILED"
    assert "runtime-token-a" not in result.model_dump_json()
    assert "runtime-token-a" not in repr((backend.error_reports, audit.events))


def test_empty_approved_plan_returns_valid_empty_scan_result_without_client() -> None:
    documents = _documents(())

    result, backend, audit, budget, transport_calls = _execute(
        documents,
        modules={},
        client=None,
    )

    assert result == ScanResult(scan_id="scan-001", findings=[])
    assert backend.error_reports == []
    assert audit.events == []
    assert budget.requests_used == 3
    assert transport_calls == []
