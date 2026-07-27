"""Synchronous Discovery and Execution orchestration for the scanner worker."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Callable, Literal, TypeVar, cast
from urllib.parse import urlsplit
from uuid import UUID

import httpx
from pydantic import BaseModel, ValidationError

from scanner.artifacts import ArtifactBuilder, Redactor
from scanner.audit import AuditEvent, AuditSink, InMemoryAuditSink
from scanner.auth.session_manager import RuntimeContext, SessionManager
from scanner.contracts import (
    ApprovalStatus,
    ContractSource,
    DiscoveryJobRequest,
    ExecutionJobRequest,
    InputField,
    NormalizedApiGraph,
    Operation,
    OutputField,
    PlanApprovalDecision,
    PolicyModule,
    RelationshipAnalysis,
    ScanPlan,
    ScanResult,
    TargetProfile,
)
from scanner.crawler.katana_runner import (
    KatanaRecord,
    KatanaRunner,
)
from scanner.crawler.normalizer import (
    infer_output_fields,
    merge_katana_records,
    normalize_openapi,
)
from scanner.http_client import ResponseSnapshot, SafeHttpClient, ScannerRequestError
from scanner.executor import Executor
from scanner.integration.backend_client import (
    BackendClient,
    ScannerErrorReport,
    ScannerStage,
)
from scanner.policy import (
    BudgetLease,
    BudgetExceeded,
    CancellationGuard,
    CancellationRequested,
    PolicyEnforcer,
    PolicyViolation,
    RequestBudget,
)


OPENAPI_PATH_CANDIDATES = (
    "/openapi.json",
    "/swagger.json",
    "/api/openapi.json",
    "/api/swagger.json",
)

_HEX_SEGMENT = re.compile(r"^[0-9a-fA-F]{16,}$")
_LIVE_FIELD_COMPONENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_NUMERIC_SEGMENT = re.compile(r"^\d+$")
_PATH_PARAMETER = re.compile(r"^\{([^{}\/]+)\}$")
_MIN_RUNTIME_COMPONENT_LENGTH = 4
_DISCOVERY_MODULE_IDS = {
    PolicyModule.AUTHZ: "BOLA-001",
    PolicyModule.INPUT_VALIDATION: "INPUT-001",
    PolicyModule.DATA_EXPOSURE: "DATA-001",
}
_PROGRESS = {
    ScannerStage.PROFILE_LOADING: 5,
    ScannerStage.AUTHENTICATING: 20,
    ScannerStage.DISCOVERING: 45,
    ScannerStage.NORMALIZING: 65,
    ScannerStage.OBJECT_DISCOVERY: 85,
    ScannerStage.POLICY_VALIDATION: 70,
    ScannerStage.EXECUTING: 80,
    ScannerStage.VERIFYING: 90,
    ScannerStage.COMPLETED: 100,
}
_OPAQUE_ARTIFACT_REFERENCE = re.compile(r"artifact:[A-Za-z0-9][A-Za-z0-9._-]*")


class ContractLoadError(ValueError):
    """A fixed contract parsing failure that contains no source data."""


class ContractArtifactFetchError(RuntimeError):
    """A fixed artifact read failure that contains no reference data."""


class DiscoveryJobError(RuntimeError):
    """A fixed Discovery job failure that contains no target runtime data."""


class ExecutionJobError(RuntimeError):
    """A fixed Execution job failure that contains no target runtime data."""


ContractModel = TypeVar("ContractModel", bound=BaseModel)
JobRequest = DiscoveryJobRequest | ExecutionJobRequest


def load_contract_source(
    source: ContractSource,
    model_type: type[ContractModel],
    backend_client: BackendClient,
) -> ContractModel:
    """Load and strictly validate an inline or artifact-backed contract."""

    if source.inline is not None:
        payload: object = source.inline
    else:
        try:
            content = backend_client.fetch_artifact(cast(str, source.artifact_ref))
        except Exception:
            raise ContractArtifactFetchError("contract artifact fetch failed") from None
        try:
            payload = json.loads(content)
        except (json.JSONDecodeError, UnicodeDecodeError, TypeError):
            raise ContractLoadError("contract source is invalid") from None
    try:
        return model_type.model_validate(payload)
    except (ValidationError, TypeError, ValueError):
        raise ContractLoadError("contract source is invalid") from None


@dataclass(frozen=True)
class DiscoveryOutcome:
    job_id: str
    scan_id: str
    graph: NormalizedApiGraph
    graph_artifact_ref: str
    available_object_types: tuple[str, ...]
    requests_used: int


@dataclass(frozen=True)
class ExecutionOutcome:
    job_id: str
    scan_id: str
    decision: PlanApprovalDecision
    scan_result: ScanResult | None
    result_artifact_ref: str | None


@dataclass
class _ScanState:
    requests_used: int = 0
    runtime: RuntimeContext | None = field(default=None, repr=False)
    profile_fingerprint: str | None = field(default=None, repr=False)

    def retain_requests_used(self, value: int) -> None:
        self.requests_used = max(self.requests_used, value)


class _TrackedRequestBudget(RequestBudget):
    """Current-job enforcement that only retains its monotonic count."""

    def __init__(
        self,
        *,
        on_change: Callable[[int], None],
        **kwargs: object,
    ) -> None:
        self._on_change = on_change
        super().__init__(**kwargs)

    def restore(self, value: int) -> None:
        super().restore(value)
        self._on_change(self.requests_used)

    def reserve(self) -> None:
        super().reserve()
        self._on_change(self.requests_used)

    def _close_lease(self, lease: BudgetLease) -> None:
        super()._close_lease(lease)
        self._on_change(self.requests_used)


class Scanner:
    """Coordinates safe scanner jobs without backend or LLM implementation."""

    def __init__(
        self,
        backend_client: BackendClient,
        *,
        transport: httpx.BaseTransport | None = None,
        katana_runner: KatanaRunner | None = None,
        artifact_builder: ArtifactBuilder | None = None,
        audit_sink: AuditSink | None = None,
    ) -> None:
        resolved_audit_sink = (
            audit_sink if audit_sink is not None else InMemoryAuditSink()
        )
        self._backend = backend_client
        self._transport = transport
        self._katana_runner = katana_runner or KatanaRunner(
            audit_sink=resolved_audit_sink
        )
        self._artifact_builder = artifact_builder or ArtifactBuilder(Redactor())
        self._audit_sink = resolved_audit_sink
        self._scan_states: dict[str, _ScanState] = {}

    def __repr__(self) -> str:
        return "Scanner()"

    @property
    def audit_events(self) -> tuple[AuditEvent, ...]:
        if isinstance(self._audit_sink, InMemoryAuditSink):
            return tuple(self._audit_sink.events)
        return ()

    def run_discovery(
        self,
        request: DiscoveryJobRequest,
    ) -> DiscoveryOutcome:
        cancellation = CancellationGuard(self._backend)
        self._check_cancellation(request, cancellation)
        self._progress(request, ScannerStage.PROFILE_LOADING, {})

        profile = self._load_profile(request)
        self._check_cancellation(request, cancellation)

        state, budget = self._state_for(request, profile, cancellation)
        policy = PolicyEnforcer(profile)
        client = SafeHttpClient(
            policy=policy,
            budget=budget,
            transport=self._transport,
            redactor=Redactor(),
            audit_sink=self._audit_sink,
        )
        session_manager = SessionManager(client)

        self._progress(request, ScannerStage.AUTHENTICATING, {"actors": 2})
        try:
            runtime = session_manager.authenticate(profile)
        except CancellationRequested:
            self._cancelled(request)
            raise
        except Exception:
            self._check_cancellation(request, cancellation)
            self._fail(
                request,
                code="DISCOVERY_AUTHENTICATION_FAILED",
                stage=ScannerStage.AUTHENTICATING,
                retryable=False,
                message="discovery authentication failed",
            )
        state.runtime = runtime
        self._progress(request, ScannerStage.DISCOVERING, {"actors": 2})

        module_id = self._discovery_module_id(profile)
        openapi_document, openapi_succeeded = self._probe_openapi(
            request,
            profile,
            client,
            policy,
            module_id,
            cancellation,
        )
        katana_records, katana_succeeded, katana_failed = self._run_katana(
            request,
            profile,
            runtime,
            budget,
            policy,
            module_id,
            cancellation,
        )
        if katana_failed:
            self._warning(
                request,
                code="DISCOVERY_KATANA_FAILED",
                details={},
            )

        enabled_results = []
        if "openapi" in profile.discovery.sources:
            enabled_results.append(openapi_succeeded)
        if "crawl" in profile.discovery.sources:
            enabled_results.append(katana_succeeded)
        if not enabled_results or not any(enabled_results):
            self._fail(
                request,
                code="DISCOVERY_SOURCES_FAILED",
                stage=ScannerStage.DISCOVERING,
                retryable=True,
                message="discovery sources failed",
            )

        self._check_cancellation(request, cancellation)
        self._progress(
            request,
            ScannerStage.NORMALIZING,
            {"requests_used": budget.requests_used},
        )
        graph = normalize_openapi(request.scan_id, openapi_document, runtime)
        graph = self._filter_graph(graph, profile, policy, module_id)
        graph = merge_katana_records(graph, katana_records)
        graph = self._normalize_operation_paths(graph)
        graph = self._filter_graph(graph, profile, policy, module_id)

        self._check_cancellation(request, cancellation)
        self._progress(
            request,
            ScannerStage.OBJECT_DISCOVERY,
            {
                "operations": len(graph.operations),
                "requests_used": budget.requests_used,
            },
        )
        graph = self._collect_objects_and_outputs(
            request,
            profile,
            graph,
            runtime,
            policy,
            module_id,
            session_manager,
            client,
            cancellation,
        )
        graph = self._sanitize_authoritative_structure(graph, runtime)
        self._check_cancellation(request, cancellation)
        available_object_types = tuple(
            sorted(
                {
                    object_type
                    for actor_objects in runtime.object_ids.values()
                    for object_type in actor_objects
                }
            )
        )

        self._check_cancellation(request, cancellation)
        try:
            envelope = self._artifact_builder.build(
                scan_id=request.scan_id,
                artifact_type="normalized_api_graph",
                schema_version="1.1",
                payload=graph.model_dump(mode="json"),
            )
        except Exception:
            self._fail(
                request,
                code="DISCOVERY_GRAPH_PUBLISH_FAILED",
                stage=ScannerStage.NORMALIZING,
                retryable=True,
                message="discovery graph publish failed",
            )
        self._check_cancellation(request, cancellation)
        try:
            graph_artifact_ref = self._backend.publish_artifact(envelope)
        except Exception:
            self._fail(
                request,
                code="DISCOVERY_GRAPH_PUBLISH_FAILED",
                stage=ScannerStage.NORMALIZING,
                retryable=True,
                message="discovery graph publish failed",
            )

        statistics = {
            "actors": len(runtime.sessions),
            "operations": len(graph.operations),
            "object_types": len(available_object_types),
            "requests_used": budget.requests_used,
        }
        self._check_cancellation(request, cancellation)
        self._progress(request, ScannerStage.COMPLETED, statistics)
        return DiscoveryOutcome(
            job_id=request.job_id,
            scan_id=request.scan_id,
            graph=graph,
            graph_artifact_ref=graph_artifact_ref,
            available_object_types=available_object_types,
            requests_used=budget.requests_used,
        )

    def run_execution(
        self,
        request: ExecutionJobRequest,
    ) -> ExecutionOutcome:
        cancellation = CancellationGuard(self._backend)
        self._check_cancellation(request, cancellation)
        self._progress(request, ScannerStage.PROFILE_LOADING, {})
        self._check_cancellation(request, cancellation)

        profile = self._load_execution_contract(
            request,
            request.target_profile,
            TargetProfile,
            artifact_error_code="EXECUTION_PROFILE_FETCH_FAILED",
            invalid_error_code="EXECUTION_PROFILE_INVALID",
        )
        graph = self._load_execution_contract(
            request,
            request.normalized_api_graph,
            NormalizedApiGraph,
            artifact_error_code="EXECUTION_GRAPH_FETCH_FAILED",
            invalid_error_code="EXECUTION_GRAPH_INVALID",
        )
        analysis = self._load_execution_contract(
            request,
            request.relationship_analysis,
            RelationshipAnalysis,
            artifact_error_code="EXECUTION_ANALYSIS_FETCH_FAILED",
            invalid_error_code="EXECUTION_ANALYSIS_INVALID",
        )
        plan = self._load_execution_contract(
            request,
            request.scan_plan,
            ScanPlan,
            artifact_error_code="EXECUTION_PLAN_FETCH_FAILED",
            invalid_error_code="EXECUTION_PLAN_INVALID",
        )
        if {
            request.scan_id,
            profile.scan_id,
            graph.scan_id,
            analysis.scan_id,
            plan.scan_id,
        } != {request.scan_id}:
            self._execution_fail(
                request,
                code="EXECUTION_CONTRACT_INVALID",
                stage=ScannerStage.PROFILE_LOADING,
                retryable=False,
                message="execution contract is invalid",
            )
        self._check_cancellation(request, cancellation)

        state, budget = self._execution_state_for(
            request,
            profile,
            cancellation,
        )
        policy = PolicyEnforcer(profile)
        client = SafeHttpClient(
            policy=policy,
            budget=budget,
            transport=self._transport,
            redactor=Redactor(),
            audit_sink=self._audit_sink,
        )
        rehydrating = state.runtime is None
        session_manager = SessionManager(client)
        if rehydrating:
            self._progress(request, ScannerStage.AUTHENTICATING, {"actors": 2})
            self._check_cancellation(request, cancellation)
            try:
                state.runtime = session_manager.authenticate(profile)
            except CancellationRequested:
                self._cancelled(request)
                raise
            except Exception:
                self._check_cancellation(request, cancellation)
                self._execution_fail(
                    request,
                    code="EXECUTION_AUTHENTICATION_FAILED",
                    stage=ScannerStage.AUTHENTICATING,
                    retryable=False,
                    message="execution authentication failed",
                )
        runtime = state.runtime
        if runtime.scan_id != request.scan_id:
            self._execution_fail(
                request,
                code="EXECUTION_RUNTIME_INVALID",
                stage=ScannerStage.AUTHENTICATING,
                retryable=False,
                message="execution runtime is invalid",
            )
        if rehydrating:
            self._collect_objects_and_outputs(
                request,
                profile,
                graph,
                runtime,
                policy,
                self._discovery_module_id(profile),
                session_manager,
                client,
                cancellation,
            )
        identifier_sensitive_values = runtime.sensitive_values()
        if any(
            not _runtime_external_text_is_safe(
                value,
                identifier_sensitive_values,
            )
            for value in (
                request.scan_id,
                profile.scan_id,
                graph.scan_id,
                analysis.scan_id,
                plan.scan_id,
                plan.plan_id,
            )
        ):
            self._execution_fail(
                request,
                code="EXECUTION_CONTRACT_INVALID",
                stage=ScannerStage.POLICY_VALIDATION,
                retryable=False,
                message="execution contract is invalid",
            )

        self._check_cancellation(request, cancellation)
        self._progress(
            request,
            ScannerStage.POLICY_VALIDATION,
            {"requests_used": budget.requests_used},
        )
        self._check_cancellation(request, cancellation)
        executor = Executor(
            self._backend,
            client=client,
            artifact_builder=self._artifact_builder,
            audit_sink=self._audit_sink,
        )
        decision = executor.evaluate_plan(
            job_id=request.job_id,
            profile=profile,
            graph=graph,
            analysis=analysis,
            plan=plan,
            runtime_requests_used=budget.requests_used,
        )
        self._check_cancellation(request, cancellation)
        if decision.status is ApprovalStatus.REJECTED:
            self._progress(
                request,
                ScannerStage.COMPLETED,
                {"findings": 0, "requests_used": budget.requests_used},
            )
            return ExecutionOutcome(
                job_id=request.job_id,
                scan_id=request.scan_id,
                decision=decision,
                scan_result=None,
                result_artifact_ref=None,
            )

        self._progress(
            request,
            ScannerStage.EXECUTING,
            {"requests_used": budget.requests_used},
        )
        self._check_cancellation(request, cancellation)
        result = executor.execute(
            job_id=request.job_id,
            profile=profile,
            graph=graph,
            analysis=analysis,
            plan=plan,
            runtime=runtime,
            decision=decision,
        )
        self._check_cancellation(request, cancellation)
        self._progress(
            request,
            ScannerStage.VERIFYING,
            {
                "findings": len(result.findings),
                "requests_used": budget.requests_used,
            },
        )
        self._check_cancellation(request, cancellation)
        try:
            envelope = self._artifact_builder.build(
                scan_id=request.scan_id,
                artifact_type="scan_result",
                schema_version="1.2",
                payload=result.model_dump(mode="json"),
            )
            result_artifact_ref = self._backend.publish_artifact(envelope)
            if (
                not isinstance(result_artifact_ref, str)
                or _OPAQUE_ARTIFACT_REFERENCE.fullmatch(result_artifact_ref) is None
                or not _runtime_external_text_is_safe(
                    result_artifact_ref,
                    runtime.sensitive_values(),
                )
            ):
                raise ValueError("result artifact reference is invalid")
        except Exception:
            self._execution_fail(
                request,
                code="EXECUTION_RESULT_PUBLISH_FAILED",
                stage=ScannerStage.VERIFYING,
                retryable=True,
                message="execution result publish failed",
            )
        self._check_cancellation(request, cancellation)
        self._progress(
            request,
            ScannerStage.COMPLETED,
            {
                "findings": len(result.findings),
                "requests_used": budget.requests_used,
            },
        )
        return ExecutionOutcome(
            job_id=request.job_id,
            scan_id=request.scan_id,
            decision=decision,
            scan_result=result,
            result_artifact_ref=result_artifact_ref,
        )

    def _load_execution_contract(
        self,
        request: ExecutionJobRequest,
        source: ContractSource,
        model_type: type[ContractModel],
        *,
        artifact_error_code: str,
        invalid_error_code: str,
    ) -> ContractModel:
        try:
            return load_contract_source(source, model_type, self._backend)
        except ContractArtifactFetchError:
            self._execution_fail(
                request,
                code=artifact_error_code,
                stage=ScannerStage.PROFILE_LOADING,
                retryable=True,
                message="execution contract fetch failed",
            )
        except ContractLoadError:
            self._execution_fail(
                request,
                code=invalid_error_code,
                stage=ScannerStage.PROFILE_LOADING,
                retryable=False,
                message="execution contract is invalid",
            )

    def _execution_state_for(
        self,
        request: ExecutionJobRequest,
        profile: TargetProfile,
        cancellation: CancellationGuard,
    ) -> tuple[_ScanState, RequestBudget]:
        state = self._scan_states.get(request.scan_id)
        if state is None:
            state = _ScanState()
            self._scan_states[request.scan_id] = state
        profile_fingerprint = _target_profile_fingerprint(profile)
        if state.profile_fingerprint is None:
            state.profile_fingerprint = profile_fingerprint
        elif state.profile_fingerprint != profile_fingerprint:
            self._execution_fail(
                request,
                code="EXECUTION_RUNTIME_INVALID",
                stage=ScannerStage.PROFILE_LOADING,
                retryable=False,
                message="execution runtime is invalid",
            )
        try:
            restored = self._backend.get_requests_used(request.job_id)
            if (
                isinstance(restored, bool)
                or not isinstance(restored, int)
                or restored < 0
            ):
                raise ValueError("invalid restored request count")
            restored = max(state.requests_used, restored)
            if restored > profile.safety_policy.max_requests:
                raise ValueError("invalid restored request count")
            budget = _TrackedRequestBudget(
                max_requests=profile.safety_policy.max_requests,
                requests_per_second=profile.safety_policy.requests_per_second,
                cancellation_guard=cancellation,
                job_id=request.job_id,
                on_change=state.retain_requests_used,
            )
            budget.restore(restored)
        except Exception:
            self._execution_fail(
                request,
                code="EXECUTION_REQUEST_COUNT_INVALID",
                stage=ScannerStage.PROFILE_LOADING,
                retryable=False,
                message="execution request count is invalid",
            )
        return state, budget

    def _load_profile(self, request: DiscoveryJobRequest) -> TargetProfile:
        try:
            profile = load_contract_source(
                request.target_profile,
                TargetProfile,
                self._backend,
            )
        except ContractArtifactFetchError:
            self._fail(
                request,
                code="DISCOVERY_PROFILE_FETCH_FAILED",
                stage=ScannerStage.PROFILE_LOADING,
                retryable=True,
                message="discovery profile fetch failed",
            )
        except ContractLoadError:
            self._fail(
                request,
                code="DISCOVERY_PROFILE_INVALID",
                stage=ScannerStage.PROFILE_LOADING,
                retryable=False,
                message="discovery profile is invalid",
            )
        if profile.scan_id != request.scan_id:
            self._fail(
                request,
                code="DISCOVERY_PROFILE_INVALID",
                stage=ScannerStage.PROFILE_LOADING,
                retryable=False,
                message="discovery profile is invalid",
            )
        return profile

    def _state_for(
        self,
        request: DiscoveryJobRequest,
        profile: TargetProfile,
        cancellation: CancellationGuard,
    ) -> tuple[_ScanState, RequestBudget]:
        state = self._scan_states.get(request.scan_id)
        if state is None:
            state = _ScanState()
            self._scan_states[request.scan_id] = state
        profile_fingerprint = _target_profile_fingerprint(profile)
        try:
            restored = self._backend.get_requests_used(request.job_id)
            if (
                isinstance(restored, bool)
                or not isinstance(restored, int)
                or restored < 0
            ):
                raise ValueError("invalid restored request count")
            restored = max(state.requests_used, restored)
            if restored > profile.safety_policy.max_requests:
                raise ValueError("invalid restored request count")
            budget = _TrackedRequestBudget(
                max_requests=profile.safety_policy.max_requests,
                requests_per_second=profile.safety_policy.requests_per_second,
                cancellation_guard=cancellation,
                job_id=request.job_id,
                on_change=state.retain_requests_used,
            )
            budget.restore(restored)
        except Exception:
            self._fail(
                request,
                code="DISCOVERY_REQUEST_COUNT_INVALID",
                stage=ScannerStage.PROFILE_LOADING,
                retryable=False,
                message="discovery request count is invalid",
            )
        if state.profile_fingerprint is None:
            state.profile_fingerprint = profile_fingerprint
        elif state.profile_fingerprint != profile_fingerprint:
            self._fail(
                request,
                code="DISCOVERY_PROFILE_INVALID",
                stage=ScannerStage.PROFILE_LOADING,
                retryable=False,
                message="discovery profile is invalid",
            )
        return state, budget

    def _probe_openapi(
        self,
        request: DiscoveryJobRequest,
        profile: TargetProfile,
        client: SafeHttpClient,
        policy: PolicyEnforcer,
        module_id: str | None,
        cancellation: CancellationGuard,
    ) -> tuple[dict[str, object], bool]:
        combined_paths: dict[str, object] = {}
        succeeded = False
        if "openapi" not in profile.discovery.sources or module_id is None:
            return {"openapi": "3.1.0", "paths": combined_paths}, False

        for path in OPENAPI_PATH_CANDIDATES:
            self._check_cancellation(request, cancellation)
            url = self._target_url(profile, path)
            try:
                policy.authorize(
                    "GET",
                    url,
                    module_id=module_id,
                    is_login=False,
                    is_state_change=False,
                )
            except PolicyViolation:
                continue
            try:
                snapshot = client.request(
                    "GET",
                    url,
                    module_id=module_id,
                )
            except CancellationRequested:
                self._cancelled(request)
                raise
            except (BudgetExceeded, PolicyViolation, ScannerRequestError):
                continue
            if not snapshot.is_success or not isinstance(snapshot.json_body, Mapping):
                continue
            paths = snapshot.json_body.get("paths")
            if not isinstance(paths, Mapping):
                continue
            succeeded = True
            for raw_path, path_item in paths.items():
                if isinstance(raw_path, str) and raw_path not in combined_paths:
                    combined_paths[raw_path] = path_item
        return {"openapi": "3.1.0", "paths": combined_paths}, succeeded

    def _run_katana(
        self,
        request: DiscoveryJobRequest,
        profile: TargetProfile,
        runtime: RuntimeContext,
        budget: RequestBudget,
        policy: PolicyEnforcer,
        module_id: str | None,
        cancellation: CancellationGuard,
    ) -> tuple[tuple[KatanaRecord, ...], bool, bool]:
        if "crawl" not in profile.discovery.sources or module_id is None:
            return (), False, False

        remaining = max(0, profile.safety_policy.max_requests - budget.requests_used)
        crawl_pool = remaining // 2
        actors = ("user_a", "user_b")
        records: list[KatanaRecord] = []
        successes = 0
        failures = 0
        for index, actor_id in enumerate(actors):
            self._check_cancellation(request, cancellation)
            actors_left = len(actors) - index
            allocation = crawl_pool // actors_left
            crawl_pool -= allocation
            if allocation <= 0:
                failures += 1
                continue
            try:
                result = self._katana_runner.run(
                    profile,
                    session=runtime.sessions[actor_id],
                    allocated_requests=allocation,
                    budget=budget,
                    cancellation_guard=cancellation,
                    job_id=request.job_id,
                )
            except CancellationRequested:
                self._cancelled(request)
                raise
            except Exception:
                failures += 1
                continue
            successes += 1
            records.extend(
                record
                for record in result.records
                if self._katana_record_allowed(record, policy, module_id)
            )
        return tuple(records), successes > 0, failures > 0

    def _collect_objects_and_outputs(
        self,
        request: JobRequest,
        profile: TargetProfile,
        graph: NormalizedApiGraph,
        runtime: RuntimeContext,
        policy: PolicyEnforcer,
        module_id: str | None,
        session_manager: SessionManager,
        client: SafeHttpClient,
        cancellation: CancellationGuard,
    ) -> NormalizedApiGraph:
        if module_id is None:
            return graph
        observed_outputs: dict[
            str,
            dict[str, dict[tuple[str, str], OutputField]],
        ] = {}
        for actor_id in ("user_a", "user_b"):
            session = runtime.sessions[actor_id]
            for operation in graph.operations:
                self._check_cancellation(request, cancellation)
                if not self._is_list_operation(operation, runtime):
                    continue
                url = self._operation_url(profile, operation)
                if url is None:
                    continue
                try:
                    policy.authorize(
                        "GET",
                        url,
                        module_id=module_id,
                        is_login=False,
                        is_state_change=False,
                    )
                    snapshot = client.request(
                        "GET",
                        url,
                        module_id=module_id,
                        headers=session.authorization_headers(),
                    )
                except CancellationRequested:
                    self._cancelled(request)
                    raise
                except (BudgetExceeded, PolicyViolation, ScannerRequestError):
                    continue
                if not snapshot.is_success or snapshot.runtime_json_body is None:
                    continue
                session_manager.collect_response(
                    runtime,
                    actor_id=cast(LiteralActor, actor_id),
                    operation_id=operation.operation_id,
                    body=snapshot.json_body,
                )
                inferred = self._infer_runtime_output_fields(snapshot)
                observed_outputs.setdefault(operation.operation_id, {})[actor_id] = {
                    (field.field_path, field.type): field for field in inferred
                }
        operations: list[Operation] = []
        untrusted_runtime_components = self._untrusted_runtime_components(runtime)
        for operation in graph.operations:
            actor_outputs = observed_outputs.get(operation.operation_id, {})
            merged_outputs = {
                (output.field_path, output.type): output
                for output in operation.outputs
            }
            for outputs_by_key in actor_outputs.values():
                merged_outputs.update(
                    {
                        key: output
                        for key, output in outputs_by_key.items()
                        if self._is_safe_live_output(
                            output,
                            untrusted_runtime_components,
                        )
                    }
                )
            operations.append(
                operation.model_copy(
                    update={
                        "outputs": sorted(
                            merged_outputs.values(),
                            key=lambda field: field.field_path,
                        )
                    }
                )
            )
        return NormalizedApiGraph(
            scan_id=graph.scan_id,
            operations=operations,
        )

    @staticmethod
    def _infer_runtime_output_fields(
        snapshot: ResponseSnapshot,
    ) -> list[OutputField]:
        runtime_body = snapshot.runtime_json_body
        if runtime_body is None:
            return []
        try:
            return infer_output_fields(runtime_body.reveal())
        except Exception:
            return []

    @classmethod
    def _normalize_operation_paths(
        cls,
        graph: NormalizedApiGraph,
        runtime_components: set[str] | frozenset[str] = frozenset(),
    ) -> NormalizedApiGraph:
        normalized: dict[tuple[str, str], Operation] = {}
        for operation in graph.operations:
            path_template, generated_parameters = cls._generalize_path_template(
                operation.path_template,
                runtime_components,
            )
            inputs = {
                (input_field.location, input_field.field_path): input_field
                for input_field in operation.inputs
            }
            inputs.update(
                {
                    ("path", parameter): InputField(
                        location="path",
                        field_path=parameter,
                        type="string",
                    )
                    for parameter in generated_parameters
                }
            )
            candidate = operation.model_copy(
                update={
                    "operation_id": f"{operation.method}:{path_template}",
                    "path_template": path_template,
                    "inputs": sorted(
                        inputs.values(),
                        key=lambda field: (field.location, field.field_path),
                    ),
                }
            )
            key = (candidate.method, candidate.path_template)
            existing = normalized.get(key)
            if existing is None:
                normalized[key] = candidate
                continue
            merged_inputs = {
                (field.location, field.field_path): field
                for field in [*existing.inputs, *candidate.inputs]
            }
            merged_outputs = {
                (field.field_path, field.type): field
                for field in [*existing.outputs, *candidate.outputs]
            }
            normalized[key] = existing.model_copy(
                update={
                    "inputs": sorted(
                        merged_inputs.values(),
                        key=lambda field: (field.location, field.field_path),
                    ),
                    "outputs": sorted(
                        merged_outputs.values(),
                        key=lambda field: field.field_path,
                    ),
                }
            )
        return NormalizedApiGraph(
            scan_id=graph.scan_id,
            operations=sorted(
                normalized.values(),
                key=lambda operation: (
                    operation.path_template,
                    operation.method,
                ),
            ),
        )

    @classmethod
    def _generalize_path_template(
        cls,
        path_template: str,
        runtime_components: set[str] | frozenset[str] = frozenset(),
    ) -> tuple[str, tuple[str, ...]]:
        used_names = {
            match.group(1)
            for segment in path_template.split("/")
            if (match := _PATH_PARAMETER.fullmatch(segment)) is not None
        }
        generated: list[str] = []
        segments: list[str] = []
        next_index = 1
        for segment in path_template.split("/"):
            parameter_match = _PATH_PARAMETER.fullmatch(segment)
            component = (
                parameter_match.group(1)
                if parameter_match is not None
                else segment
            )
            if (
                not cls._is_value_path_segment(segment)
                and component not in runtime_components
            ):
                segments.append(segment)
                continue
            while True:
                name = "id" if next_index == 1 else f"id_{next_index}"
                next_index += 1
                if name not in used_names:
                    break
            used_names.add(name)
            generated.append(name)
            segments.append(f"{{{name}}}")
        return "/".join(segments), tuple(generated)

    @staticmethod
    def _is_value_path_segment(segment: str) -> bool:
        if (
            _NUMERIC_SEGMENT.fullmatch(segment) is not None
            or _HEX_SEGMENT.fullmatch(segment) is not None
        ):
            return True
        if len(segment) != 36:
            return False
        try:
            parsed = UUID(segment)
        except ValueError:
            return False
        return str(parsed) == segment.casefold()

    @classmethod
    def _sanitize_authoritative_structure(
        cls,
        graph: NormalizedApiGraph,
        runtime: RuntimeContext,
    ) -> NormalizedApiGraph:
        runtime_components = cls._untrusted_runtime_components(runtime)
        operations = [
            operation.model_copy(
                update={
                    "inputs": [
                        field
                        for field in operation.inputs
                        if not cls._field_path_contains_component(
                            field.field_path,
                            runtime_components,
                        )
                    ],
                    "outputs": [
                        field
                        for field in operation.outputs
                        if not cls._field_path_contains_component(
                            field.field_path,
                            runtime_components,
                        )
                    ],
                }
            )
            for operation in graph.operations
        ]
        sanitized = NormalizedApiGraph(
            scan_id=graph.scan_id,
            operations=operations,
        )
        return cls._normalize_operation_paths(
            sanitized,
            runtime_components,
        )

    @staticmethod
    def _field_path_contains_component(
        field_path: str,
        runtime_components: set[str] | frozenset[str],
    ) -> bool:
        for raw_component in field_path.split("."):
            component = raw_component
            while component.endswith("[]"):
                component = component[:-2]
            if component in runtime_components:
                return True
        return False

    @classmethod
    def _is_safe_live_output(
        cls,
        output: OutputField,
        untrusted_runtime_components: set[str],
    ) -> bool:
        for raw_component in output.field_path.split("."):
            component = raw_component
            while component.endswith("[]"):
                component = component[:-2]
            if (
                _LIVE_FIELD_COMPONENT.fullmatch(component) is None
                or cls._is_value_path_segment(component)
                or component in untrusted_runtime_components
            ):
                return False
        return True

    @staticmethod
    def _untrusted_runtime_components(runtime: RuntimeContext) -> set[str]:
        return {
            value
            for value in runtime.sensitive_values()
            if len(value) >= _MIN_RUNTIME_COMPONENT_LENGTH
        }

    @staticmethod
    def _is_list_operation(
        operation: Operation,
        runtime: RuntimeContext,
    ) -> bool:
        return (
            operation.method == "GET"
            and "{" not in operation.path_template
            and not any(field.location == "path" for field in operation.inputs)
            and not runtime.required_inputs.get(operation.operation_id)
        )

    @classmethod
    def _filter_graph(
        cls,
        graph: NormalizedApiGraph,
        profile: TargetProfile,
        policy: PolicyEnforcer,
        module_id: str | None,
    ) -> NormalizedApiGraph:
        if module_id is None:
            return NormalizedApiGraph(scan_id=graph.scan_id, operations=[])
        operations: list[Operation] = []
        for operation in graph.operations:
            if operation.method != "GET":
                continue
            path = operation.path_template
            if not cls._safe_graph_path(path):
                continue
            try:
                policy.authorize(
                    "GET",
                    cls._target_url(profile, path),
                    module_id=module_id,
                    is_login=False,
                    is_state_change=False,
                )
            except PolicyViolation:
                continue
            operations.append(operation)
        return NormalizedApiGraph(scan_id=graph.scan_id, operations=operations)

    @classmethod
    def _katana_record_allowed(
        cls,
        record: KatanaRecord,
        policy: PolicyEnforcer,
        module_id: str,
    ) -> bool:
        if record.method.upper() != "GET":
            return False
        parsed = urlsplit(record.url)
        if not cls._safe_graph_path(parsed.path):
            return False
        try:
            policy.authorize(
                "GET",
                record.url,
                module_id=module_id,
                is_login=False,
                is_state_change=False,
            )
        except PolicyViolation:
            return False
        return True

    @staticmethod
    def _safe_graph_path(path: str) -> bool:
        return (
            path.startswith("/")
            and not path.startswith("//")
            and "%" not in path
            and "?" not in path
            and "#" not in path
            and ".." not in path.split("/")
        )

    @staticmethod
    def _operation_url(
        profile: TargetProfile,
        operation: Operation,
    ) -> str | None:
        if not Scanner._safe_graph_path(operation.path_template):
            return None
        return Scanner._target_url(profile, operation.path_template)

    @staticmethod
    def _target_url(profile: TargetProfile, path: str) -> str:
        return f"{profile.target.base_url.rstrip('/')}/{path.lstrip('/')}"

    @staticmethod
    def _discovery_module_id(profile: TargetProfile) -> str | None:
        for policy in profile.safety_policy.approved_modules:
            module_id = _DISCOVERY_MODULE_IDS.get(policy)
            if module_id is not None:
                return module_id
        return None

    def _progress(
        self,
        request: JobRequest,
        stage: ScannerStage,
        statistics: Mapping[str, int],
    ) -> None:
        self._backend.report_progress(
            request.job_id,
            stage,
            _PROGRESS[stage],
            statistics,
        )

    def _cancelled(self, request: JobRequest) -> None:
        self._backend.report_progress(
            request.job_id,
            ScannerStage.CANCELED,
            100,
            {},
        )

    def _check_cancellation(
        self,
        request: JobRequest,
        cancellation: CancellationGuard,
    ) -> None:
        try:
            cancellation.raise_if_cancelled(request.job_id)
        except CancellationRequested:
            self._cancelled(request)
            raise

    def _warning(
        self,
        request: DiscoveryJobRequest,
        *,
        code: str,
        details: Mapping[str, object],
    ) -> None:
        self._audit_sink.emit(
            AuditEvent(
                code=code,
                level="WARNING",
                job_id=request.job_id,
                scan_id=request.scan_id,
                operation_id=None,
                module_id=None,
                details=details,
            )
        )

    def _fail(
        self,
        request: DiscoveryJobRequest,
        *,
        code: str,
        stage: ScannerStage,
        retryable: bool,
        message: str,
    ) -> None:
        self._backend.report_error(
            request.job_id,
            ScannerErrorReport(
                code=code,
                stage=stage,
                retryable=retryable,
            ),
        )
        raise DiscoveryJobError(message) from None

    def _execution_fail(
        self,
        request: ExecutionJobRequest,
        *,
        code: str,
        stage: ScannerStage,
        retryable: bool,
        message: str,
    ) -> None:
        self._backend.report_error(
            request.job_id,
            ScannerErrorReport(
                code=code,
                stage=stage,
                retryable=retryable,
            ),
        )
        raise ExecutionJobError(message) from None


LiteralActor = Literal["user_a", "user_b"]


def _runtime_external_text_is_safe(
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
            if len(item) >= _MIN_RUNTIME_COMPONENT_LENGTH
        },
    )
    return isinstance(cleaned, str) and cleaned == value


def _target_profile_fingerprint(profile: TargetProfile) -> str:
    canonical = json.dumps(
        profile.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()
