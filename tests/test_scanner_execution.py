from __future__ import annotations

import json
from dataclasses import dataclass

import httpx
import pytest

from scanner.artifacts import ArtifactEnvelope
from scanner.contracts import (
    ApprovalStatus,
    ContractSource,
    DiscoveryJobRequest,
    ExecutionJobRequest,
)
from scanner.crawler.katana_runner import KatanaRunResult
from scanner.integration.backend_client import FakeBackendClient, ScannerStage
from scanner.policy import CancellationRequested
from scanner.scanner import ExecutionJobError, Scanner


SCAN_ID = "scan-001"
DISCOVERY_JOB_ID = "discovery-job"
EXECUTION_JOB_ID = "execution-job"


def profile_payload(
    *,
    base_url: str = "http://vuln-bank.local",
) -> dict[str, object]:
    return {
        "schema_version": "1.1",
        "scan_id": SCAN_ID,
        "target": {
            "base_url": base_url,
            "allowed_paths": ["/api/*", "/openapi.json"],
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
            "max_requests": 30,
            "requests_per_second": 10000,
            "state_change_policy": "deny",
            "approved_modules": [
                "authz",
                "input_validation",
                "data_exposure",
            ],
        },
    }


def empty_analysis_payload() -> dict[str, object]:
    return {
        "schema_version": "1.2",
        "scan_id": SCAN_ID,
        "model_name": "fixture-model",
        "prompt_version": "fixture-v1",
        "prompt_sha256": "0" * 64,
        "approved_module_ids": ["BOLA-001", "INPUT-001", "DATA-001"],
        "relationships": [],
        "test_candidates": [],
    }


def empty_plan_payload(requests_used: int) -> dict[str, object]:
    return {
        "schema_version": "1.2",
        "plan_id": "plan-001",
        "scan_id": SCAN_ID,
        "model_name": "fixture-model",
        "prompt_version": "fixture-v1",
        "prompt_sha256": "0" * 64,
        "status": "PENDING_APPROVAL",
        "budget": {
            "requests_already_used": requests_used,
            "estimated_execution_requests": 0,
            "max_requests": 30,
            "within_budget": True,
        },
        "steps": [],
    }


def data_documents(requests_used: int) -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
    graph = {
        "schema_version": "1.1",
        "scan_id": SCAN_ID,
        "operations": [
            {
                "operation_id": "get-profile",
                "method": "GET",
                "path_template": "/api/profile",
                "inputs": [],
                "outputs": [{"field_path": "display_name", "type": "string"}],
            }
        ],
    }
    candidates = [
        {
            "candidate_id": f"data-{index}",
            "module_id": "DATA-001",
            "target_operation_id": "get-profile",
            "required_object_types": [],
            "rationale": "fixed local fixture",
            "priority": index,
            "executable": True,
            "missing_requirements": [],
            "binding_hints": [],
        }
        for index in (1, 2)
    ]
    analysis = empty_analysis_payload()
    analysis["test_candidates"] = candidates
    plan = empty_plan_payload(requests_used)
    plan["budget"]["estimated_execution_requests"] = 2  # type: ignore[index]
    plan["steps"] = [
        {
            "order": index,
            "candidate_id": f"data-{index}",
            "module_id": "DATA-001",
            "target_operation_id": "get-profile",
            "target_endpoint": {
                "method": "GET",
                "path_template": "/api/profile",
            },
            "input_bindings": [],
        }
        for index in (1, 2)
    ]
    return graph, analysis, plan


@dataclass
class NoopKatana:
    def run(self, *args: object, **kwargs: object) -> KatanaRunResult:
        return KatanaRunResult(records=(), requests_made=0)


class RecordingBackend(FakeBackendClient):
    def __init__(self) -> None:
        super().__init__()
        self.published: list[ArtifactEnvelope] = []
        self.timeline: list[str] = []

    def report_approval(self, job_id, decision) -> None:
        self.timeline.append(f"approval:{job_id}")
        super().report_approval(job_id, decision)

    def publish_artifact(self, envelope: ArtifactEnvelope) -> str:
        self.published.append(envelope)
        self.timeline.append(f"artifact:{envelope.artifact_type}")
        return super().publish_artifact(envelope)

    def report_progress(self, job_id, stage, progress, statistics) -> None:
        self.timeline.append(f"progress:{job_id}:{stage.value}")
        super().report_progress(job_id, stage, progress, statistics)


class ResultFailingBackend(RecordingBackend):
    def publish_artifact(self, envelope: ArtifactEnvelope) -> str:
        if envelope.artifact_type == "scan_result":
            raise RuntimeError("raw backend result failure")
        return super().publish_artifact(envelope)


class CancelOnProgressBackend(RecordingBackend):
    def __init__(self) -> None:
        super().__init__()
        self.cancel_stage: ScannerStage | None = None

    def report_progress(self, job_id, stage, progress, statistics) -> None:
        super().report_progress(job_id, stage, progress, statistics)
        if job_id == EXECUTION_JOB_ID and stage is self.cancel_stage:
            self.cancel(job_id)


@pytest.fixture(autouse=True)
def credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("USER_A_USERNAME", "actor-a")
    monkeypatch.setenv("USER_A_PASSWORD", "pw-a")
    monkeypatch.setenv("USER_B_USERNAME", "actor-b")
    monkeypatch.setenv("USER_B_PASSWORD", "pw-b")


def transport_for(
    calls: list[httpx.Request],
    *,
    backend: FakeBackendClient | None = None,
    cancel_after_profile: bool = False,
) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        if request.method == "POST" and request.url.path == "/api/login":
            username = json.loads(request.content)["username"]
            return httpx.Response(
                200,
                json={"access_token": f"token-{username[-1]}"},
                request=request,
            )
        if request.url.path == "/openapi.json":
            return httpx.Response(
                200,
                json={"openapi": "3.1.0", "paths": {}},
                request=request,
            )
        if request.url.path == "/api/profile":
            if cancel_after_profile and backend is not None:
                backend.cancel(EXECUTION_JOB_ID)
            return httpx.Response(
                200,
                json={"display_name": "safe fixture"},
                request=request,
            )
        if request.url.path == "/api/accounts":
            actor = "b" if request.headers.get("authorization") == "Bearer token-b" else "a"
            return httpx.Response(
                200,
                json={"items": [{"account_id": f"account-{actor}-runtime"}]},
                request=request,
            )
        return httpx.Response(404, json={}, request=request)

    return httpx.MockTransport(handler)


def discovery_request() -> DiscoveryJobRequest:
    return DiscoveryJobRequest(
        job_id=DISCOVERY_JOB_ID,
        scan_id=SCAN_ID,
        target_profile=ContractSource(inline=profile_payload()),
    )


def execution_request(
    graph_source: ContractSource,
    analysis_source: ContractSource,
    plan_source: ContractSource,
    *,
    profile_source: ContractSource | None = None,
) -> ExecutionJobRequest:
    return ExecutionJobRequest(
        job_id=EXECUTION_JOB_ID,
        scan_id=SCAN_ID,
        target_profile=profile_source or ContractSource(inline=profile_payload()),
        normalized_api_graph=graph_source,
        relationship_analysis=analysis_source,
        scan_plan=plan_source,
    )


def discover(
    backend: RecordingBackend,
    calls: list[httpx.Request],
) -> tuple[Scanner, dict[str, object], int]:
    scanner = Scanner(
        backend,
        transport=transport_for(calls),
        katana_runner=NoopKatana(),
    )
    outcome = scanner.run_discovery(discovery_request())
    return scanner, outcome.graph.model_dump(mode="json"), outcome.requests_used


@pytest.mark.parametrize("artifact_sources", [False, True])
def test_execution_loads_inline_or_artifact_graph_analysis_and_plan_and_reuses_runtime(
    artifact_sources: bool,
) -> None:
    backend = RecordingBackend()
    calls: list[httpx.Request] = []
    scanner, graph, requests_used = discover(backend, calls)
    analysis = empty_analysis_payload()
    plan = empty_plan_payload(requests_used)
    calls_before_execution = len(calls)

    if artifact_sources:
        backend.set_artifact("artifact:graph-input", json.dumps(graph).encode())
        backend.set_artifact("artifact:analysis-input", json.dumps(analysis).encode())
        backend.set_artifact("artifact:plan-input", json.dumps(plan).encode())
        sources = (
            ContractSource(artifact_ref="artifact:graph-input"),
            ContractSource(artifact_ref="artifact:analysis-input"),
            ContractSource(artifact_ref="artifact:plan-input"),
        )
    else:
        sources = (
            ContractSource(inline=graph),
            ContractSource(inline=analysis),
            ContractSource(inline=plan),
        )

    outcome = scanner.run_execution(execution_request(*sources))

    assert outcome.decision.status is ApprovalStatus.APPROVED
    assert outcome.scan_result is not None
    assert outcome.scan_result.model_dump(mode="json") == {
        "schema_version": "1.2",
        "scan_id": SCAN_ID,
        "findings": [],
    }
    assert outcome.result_artifact_ref
    assert len(calls) == calls_before_execution
    assert [event.job_id for event in backend.approval_events] == [EXECUTION_JOB_ID]
    assert backend.timeline.index(f"approval:{EXECUTION_JOB_ID}") < backend.timeline.index(
        "artifact:scan_result"
    )
    assert backend.progress_events[-1].stage is ScannerStage.COMPLETED


def test_missing_runtime_restores_count_then_reauthenticates_and_rejects_stale_plan() -> None:
    backend = RecordingBackend()
    backend.set_requests_used(EXECUTION_JOB_ID, 4)
    calls: list[httpx.Request] = []
    scanner = Scanner(
        backend,
        transport=transport_for(calls),
        katana_runner=NoopKatana(),
    )
    graph = {"schema_version": "1.1", "scan_id": SCAN_ID, "operations": []}

    outcome = scanner.run_execution(
        execution_request(
            ContractSource(inline=graph),
            ContractSource(inline=empty_analysis_payload()),
            ContractSource(inline=empty_plan_payload(4)),
        )
    )

    assert [request.method for request in calls] == ["POST", "POST"]
    assert outcome.decision.status is ApprovalStatus.REJECTED
    assert outcome.decision.reason_codes == ("PLAN_REQUEST_COUNT_STALE",)
    assert outcome.scan_result is None
    assert outcome.result_artifact_ref is None
    assert not any(item.artifact_type == "scan_result" for item in backend.published)
    assert len(backend.approval_events) == 1


def test_missing_runtime_rehydrates_actor_objects_from_loaded_graph_before_approval() -> None:
    backend = RecordingBackend()
    backend.set_requests_used(EXECUTION_JOB_ID, 4)
    calls: list[httpx.Request] = []
    scanner = Scanner(
        backend,
        transport=transport_for(calls),
        katana_runner=NoopKatana(),
    )
    graph = {
        "schema_version": "1.1",
        "scan_id": SCAN_ID,
        "operations": [
            {
                "operation_id": "get-accounts",
                "method": "GET",
                "path_template": "/api/accounts",
                "inputs": [],
                "outputs": [
                    {"field_path": "items[].account_id", "type": "string"}
                ],
            }
        ],
    }

    outcome = scanner.run_execution(
        execution_request(
            ContractSource(inline=graph),
            ContractSource(inline=empty_analysis_payload()),
            ContractSource(inline=empty_plan_payload(4)),
        )
    )

    assert outcome.decision.status is ApprovalStatus.REJECTED
    assert outcome.decision.reason_codes == ("PLAN_REQUEST_COUNT_STALE",)
    assert [
        (request.method, request.url.path)
        for request in calls
    ] == [
        ("POST", "/api/login"),
        ("POST", "/api/login"),
        ("GET", "/api/accounts"),
        ("GET", "/api/accounts"),
    ]


def test_contract_scan_id_mismatch_fails_before_authentication_or_approval() -> None:
    backend = RecordingBackend()
    calls: list[httpx.Request] = []
    scanner = Scanner(
        backend,
        transport=transport_for(calls),
        katana_runner=NoopKatana(),
    )
    graph = {"schema_version": "1.1", "scan_id": "wrong-scan", "operations": []}

    with pytest.raises(ExecutionJobError, match="^execution contract is invalid$"):
        scanner.run_execution(
            execution_request(
                ContractSource(inline=graph),
                ContractSource(inline=empty_analysis_payload()),
                ContractSource(inline=empty_plan_payload(0)),
            )
        )

    assert calls == []
    assert backend.approval_events == []
    assert backend.error_reports[-1].code == "EXECUTION_CONTRACT_INVALID"
    assert "wrong-scan" not in repr(backend.error_reports)


def test_runtime_sensitive_plan_identifier_fails_before_approval_or_result() -> None:
    backend = RecordingBackend()
    calls: list[httpx.Request] = []
    scanner, graph, requests_used = discover(backend, calls)
    plan = empty_plan_payload(requests_used)
    plan["plan_id"] = "token-a"

    with pytest.raises(ExecutionJobError, match="^execution contract is invalid$"):
        scanner.run_execution(
            execution_request(
                ContractSource(inline=graph),
                ContractSource(inline=empty_analysis_payload()),
                ContractSource(inline=plan),
            )
        )

    assert backend.approval_events == []
    assert not any(item.artifact_type == "scan_result" for item in backend.published)
    assert "token-a" not in repr(backend.error_reports)


def test_retained_runtime_rejects_changed_profile_before_old_bearer_reaches_new_origin() -> None:
    backend = RecordingBackend()
    calls: list[httpx.Request] = []
    scanner, _, requests_used = discover(backend, calls)
    graph, analysis, plan = data_documents(requests_used)
    execution_calls_start = len(calls)

    with pytest.raises(
        ExecutionJobError,
        match="^execution runtime is invalid$",
    ):
        scanner.run_execution(
            execution_request(
                ContractSource(inline=graph),
                ContractSource(inline=analysis),
                ContractSource(inline=plan),
                profile_source=ContractSource(
                    inline=profile_payload(
                        base_url="http://attacker.invalid",
                    )
                ),
            )
        )

    assert calls[execution_calls_start:] == []
    assert backend.approval_events == []
    assert backend.error_reports[-1].code == "EXECUTION_RUNTIME_INVALID"
    rendered = repr((backend.error_reports, scanner))
    assert "attacker.invalid" not in rendered
    assert "token-a" not in rendered


def test_cancellation_before_approval_sends_no_transport_or_result() -> None:
    backend = RecordingBackend()
    backend.cancel(EXECUTION_JOB_ID)
    calls: list[httpx.Request] = []
    scanner = Scanner(
        backend,
        transport=transport_for(calls),
        katana_runner=NoopKatana(),
    )
    graph = {"schema_version": "1.1", "scan_id": SCAN_ID, "operations": []}

    with pytest.raises(CancellationRequested, match="^scan cancelled$"):
        scanner.run_execution(
            execution_request(
                ContractSource(inline=graph),
                ContractSource(inline=empty_analysis_payload()),
                ContractSource(inline=empty_plan_payload(0)),
            )
        )

    assert calls == []
    assert backend.approval_events == []
    assert backend.published == []
    assert backend.progress_events[-1].stage is ScannerStage.CANCELED


def test_policy_progress_callback_cancellation_prevents_approval_side_effect() -> None:
    backend = CancelOnProgressBackend()
    calls: list[httpx.Request] = []
    scanner, graph, requests_used = discover(backend, calls)
    backend.cancel_stage = ScannerStage.POLICY_VALIDATION
    calls_before_execution = len(calls)

    with pytest.raises(CancellationRequested, match="^scan cancelled$"):
        scanner.run_execution(
            execution_request(
                ContractSource(inline=graph),
                ContractSource(inline=empty_analysis_payload()),
                ContractSource(inline=empty_plan_payload(requests_used)),
            )
        )

    assert len(calls) == calls_before_execution
    assert backend.approval_events == []
    assert not any(
        item.artifact_type == "scan_result" for item in backend.published
    )
    assert backend.progress_events[-1].stage is ScannerStage.CANCELED


def test_verifying_progress_callback_cancellation_prevents_result_publication() -> None:
    backend = CancelOnProgressBackend()
    calls: list[httpx.Request] = []
    scanner, graph, requests_used = discover(backend, calls)
    backend.cancel_stage = ScannerStage.VERIFYING

    with pytest.raises(CancellationRequested, match="^scan cancelled$"):
        scanner.run_execution(
            execution_request(
                ContractSource(inline=graph),
                ContractSource(inline=empty_analysis_payload()),
                ContractSource(inline=empty_plan_payload(requests_used)),
            )
        )

    assert len(backend.approval_events) == 1
    assert not any(
        item.artifact_type == "scan_result" for item in backend.published
    )
    assert backend.progress_events[-1].stage is ScannerStage.CANCELED


def test_cancellation_between_modules_publishes_no_result_or_later_request() -> None:
    backend = RecordingBackend()
    calls: list[httpx.Request] = []
    scanner = Scanner(
        backend,
        transport=transport_for(
            calls,
            backend=backend,
            cancel_after_profile=True,
        ),
        katana_runner=NoopKatana(),
    )
    requests_used = scanner.run_discovery(discovery_request()).requests_used
    graph, analysis, plan = data_documents(requests_used)
    execution_calls_start = len(calls)

    with pytest.raises(CancellationRequested, match="^scan cancelled$"):
        scanner.run_execution(
            execution_request(
                ContractSource(inline=graph),
                ContractSource(inline=analysis),
                ContractSource(inline=plan),
            )
        )

    assert [request.url.path for request in calls[execution_calls_start:]] == [
        "/api/profile"
    ]
    assert not any(item.artifact_type == "scan_result" for item in backend.published)
    assert backend.progress_events[-1].stage is ScannerStage.CANCELED


def test_result_artifact_failure_fails_job_without_exposing_backend_error() -> None:
    backend = ResultFailingBackend()
    calls: list[httpx.Request] = []
    scanner, graph, requests_used = discover(backend, calls)

    with pytest.raises(
        ExecutionJobError,
        match="^execution result publish failed$",
    ) as error:
        scanner.run_execution(
            execution_request(
                ContractSource(inline=graph),
                ContractSource(inline=empty_analysis_payload()),
                ContractSource(inline=empty_plan_payload(requests_used)),
            )
        )

    assert backend.error_reports[-1].code == "EXECUTION_RESULT_PUBLISH_FAILED"
    assert backend.error_reports[-1].stage is ScannerStage.VERIFYING
    assert "raw backend result failure" not in repr((error.value, backend.error_reports))


def test_scanner_completion_contains_only_scanner_statistics_not_ai_report_state() -> None:
    backend = RecordingBackend()
    calls: list[httpx.Request] = []
    scanner, graph, requests_used = discover(backend, calls)

    scanner.run_execution(
        execution_request(
            ContractSource(inline=graph),
            ContractSource(inline=empty_analysis_payload()),
            ContractSource(inline=empty_plan_payload(requests_used)),
        )
    )

    completion = backend.progress_events[-1]
    assert completion.job_id == EXECUTION_JOB_ID
    assert completion.stage is ScannerStage.COMPLETED
    assert completion.statistics == {
        "findings": 0,
        "requests_used": requests_used,
    }
    assert "report" not in repr(completion).casefold()
