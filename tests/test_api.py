"""HTTP job entrypoint and Background execution tests."""

from __future__ import annotations

import asyncio
import subprocess
import sys
import threading
import warnings
from concurrent.futures import ThreadPoolExecutor
from typing import Callable

import pytest
from fastapi import FastAPI

warnings.filterwarnings(
    "ignore",
    message="Using `httpx` with `starlette.testclient` is deprecated.*",
)

from starlette.testclient import TestClient

import scanner.api as scanner_api
from scanner.api import JobRegistry, create_app
from scanner.contracts import DiscoveryJobRequest, ExecutionJobRequest
from scanner.integration.backend_client import (
    FakeBackendClient,
    JobKind,
    ScannerErrorReport,
    ScannerStage,
)
from scanner.policy import CancellationRequested
from scanner.scanner import DiscoveryJobError, ExecutionJobError, Scanner


DISCOVERY_PAYLOAD = {
    "job_id": "backend-generated_JOB.01",
    "scan_id": "scan-001",
    "target_profile": {
        "inline": {
            "schema_version": "1.1",
            "scan_id": "scan-001",
        }
    },
}
EXECUTION_PAYLOAD = {
    "job_id": "backend-generated_JOB.02",
    "scan_id": "scan-001",
    "target_profile": {"artifact_ref": "artifacts/profile-001"},
    "normalized_api_graph": {"artifact_ref": "artifacts/graph-001"},
    "relationship_analysis": {"artifact_ref": "artifacts/analysis-001"},
    "scan_plan": {"artifact_ref": "artifacts/plan-001"},
}


class RecordingScanner:
    def __init__(
        self,
        *,
        discovery: Callable[[DiscoveryJobRequest], None] | None = None,
        execution: Callable[[ExecutionJobRequest], None] | None = None,
    ) -> None:
        self._discovery = discovery
        self._execution = execution
        self._lock = threading.Lock()
        self._condition = threading.Condition(self._lock)
        self.discovery_requests: list[DiscoveryJobRequest] = []
        self.execution_requests: list[ExecutionJobRequest] = []
        self.discovery_completed = 0
        self.execution_completed = 0

    def run_discovery(self, request: DiscoveryJobRequest) -> None:
        with self._condition:
            self.discovery_requests.append(request)
            self._condition.notify_all()
        try:
            if self._discovery is not None:
                self._discovery(request)
        finally:
            with self._condition:
                self.discovery_completed += 1
                self._condition.notify_all()

    def run_execution(self, request: ExecutionJobRequest) -> None:
        with self._condition:
            self.execution_requests.append(request)
            self._condition.notify_all()
        try:
            if self._execution is not None:
                self._execution(request)
        finally:
            with self._condition:
                self.execution_completed += 1
                self._condition.notify_all()

    def wait_for(
        self,
        *,
        discovery_calls: int = 0,
        execution_calls: int = 0,
        discovery_completed: int = 0,
        execution_completed: int = 0,
        timeout: float = 2,
    ) -> bool:
        with self._condition:
            return self._condition.wait_for(
                lambda: (
                    len(self.discovery_requests) >= discovery_calls
                    and len(self.execution_requests) >= execution_calls
                    and self.discovery_completed >= discovery_completed
                    and self.execution_completed >= execution_completed
                ),
                timeout=timeout,
            )


def _app(
    scanner: RecordingScanner,
    *,
    backend: object | None = None,
    registry: JobRegistry | None = None,
    max_workers: int = 4,
) -> FastAPI:
    return create_app(
        scanner=scanner,  # type: ignore[arg-type]
        backend=backend or FakeBackendClient(),  # type: ignore[arg-type]
        registry=registry,
        max_workers=max_workers,
    )


def _post_once(
    app: FastAPI,
    path: str,
    payload: dict[str, object],
) -> tuple[int, dict[str, object]]:
    with TestClient(app) as client:
        response = client.post(path, json=payload)
    return response.status_code, response.json()


def test_discovery_endpoint_accepts_exact_contract_and_preserves_job_id() -> None:
    scanner = RecordingScanner()

    status_code, response = _post_once(
        _app(scanner),
        "/jobs/discovery",
        DISCOVERY_PAYLOAD,
    )

    assert status_code == 202
    assert response == {
        "job_id": "backend-generated_JOB.01",
        "accepted": True,
    }
    assert scanner.wait_for(discovery_completed=1)
    assert [
        request.model_dump(exclude_none=True)
        for request in scanner.discovery_requests
    ] == [DISCOVERY_PAYLOAD]
    assert scanner.execution_requests == []


def test_execution_endpoint_accepts_exact_contract_and_preserves_job_id() -> None:
    scanner = RecordingScanner()

    status_code, response = _post_once(
        _app(scanner),
        "/jobs/execution",
        EXECUTION_PAYLOAD,
    )

    assert status_code == 202
    assert response == {
        "job_id": "backend-generated_JOB.02",
        "accepted": True,
    }
    assert scanner.wait_for(execution_completed=1)
    assert [
        request.model_dump(exclude_none=True)
        for request in scanner.execution_requests
    ] == [EXECUTION_PAYLOAD]
    assert scanner.discovery_requests == []


@pytest.mark.parametrize(
    "target_profile",
    [
        {},
        {
            "inline": {"schema_version": "1.1"},
            "artifact_ref": "artifacts/profile-001",
        },
    ],
)
def test_invalid_contract_source_returns_422_without_registering_or_running(
    target_profile: dict[str, object],
) -> None:
    scanner = RecordingScanner()
    registry = JobRegistry()
    payload = {**DISCOVERY_PAYLOAD, "target_profile": target_profile}
    app = _app(scanner, registry=registry)

    status_code, _ = _post_once(app, "/jobs/discovery", payload)
    retry_status, retry_response = _post_once(
        app,
        "/jobs/discovery",
        DISCOVERY_PAYLOAD,
    )

    assert status_code == 422
    assert retry_status == 202
    assert retry_response == {
        "job_id": "backend-generated_JOB.01",
        "accepted": True,
    }
    assert scanner.wait_for(discovery_completed=1)
    assert len(scanner.discovery_requests) == 1


@pytest.mark.parametrize(
    ("path", "base_payload", "field", "invalid_value"),
    [
        ("/jobs/discovery", DISCOVERY_PAYLOAD, "job_id", "bad/job"),
        ("/jobs/discovery", DISCOVERY_PAYLOAD, "scan_id", "bad?scan"),
        ("/jobs/execution", EXECUTION_PAYLOAD, "job_id", "bad job"),
        ("/jobs/execution", EXECUTION_PAYLOAD, "scan_id", "../scan"),
    ],
)
def test_invalid_job_routing_id_returns_422_without_registering_or_running(
    path: str,
    base_payload: dict[str, object],
    field: str,
    invalid_value: str,
) -> None:
    scanner = RecordingScanner()
    registry = JobRegistry()
    payload = {**base_payload, field: invalid_value}

    status_code, _ = _post_once(
        _app(scanner, registry=registry),
        path,
        payload,
    )

    assert status_code == 422
    assert registry.register(str(payload["job_id"])) is True
    assert scanner.discovery_requests == []
    assert scanner.execution_requests == []


def test_importing_scanner_package_does_not_construct_api_app() -> None:
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "import scanner, sys; "
                "print('scanner.api' in sys.modules)"
            ),
        ],
        check=True,
        capture_output=True,
        text=True,
    )

    assert result.stdout.strip() == "False"


def test_app_lifespan_closes_owned_default_backend(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    instances: list[object] = []

    class OwnedBackend(FakeBackendClient):
        def __init__(self, _: object) -> None:
            super().__init__()
            self.close_calls = 0
            instances.append(self)

        def close(self) -> None:
            self.close_calls += 1

    monkeypatch.setattr(scanner_api, "HttpBackendClient", OwnedBackend)
    app = create_app(scanner=RecordingScanner())

    with TestClient(app):
        assert len(instances) == 1
        assert instances[0].close_calls == 0  # type: ignore[attr-defined]

    assert instances[0].close_calls == 1  # type: ignore[attr-defined]


def test_app_lifespan_does_not_close_injected_backend() -> None:
    class InjectedBackend(FakeBackendClient):
        def __init__(self) -> None:
            super().__init__()
            self.close_calls = 0

        def close(self) -> None:
            self.close_calls += 1

    backend = InjectedBackend()
    app = create_app(scanner=RecordingScanner(), backend=backend)

    with TestClient(app):
        pass

    assert backend.close_calls == 0


def test_app_lifespan_shuts_down_owned_worker_pool(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executors: list[object] = []

    class TrackingExecutor(ThreadPoolExecutor):
        def __init__(self, *args: object, **kwargs: object) -> None:
            super().__init__(*args, **kwargs)
            self.shutdown_calls = 0
            executors.append(self)

        def shutdown(self, *args: object, **kwargs: object) -> None:
            self.shutdown_calls += 1
            super().shutdown(*args, **kwargs)

    monkeypatch.setattr(scanner_api, "ThreadPoolExecutor", TrackingExecutor)
    app = _app(RecordingScanner())

    with TestClient(app):
        assert len(executors) == 1
        assert executors[0].shutdown_calls == 0  # type: ignore[attr-defined]

    assert executors[0].shutdown_calls == 1  # type: ignore[attr-defined]


def test_scanner_runs_in_background_thread_without_an_event_loop() -> None:
    observations: list[bool] = []

    def inspect_thread(_: DiscoveryJobRequest) -> None:
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            observations.append(False)
        else:
            observations.append(True)

    scanner = RecordingScanner(discovery=inspect_thread)

    status_code, _ = _post_once(
        _app(scanner),
        "/jobs/discovery",
        DISCOVERY_PAYLOAD,
    )

    assert status_code == 202
    assert scanner.wait_for(discovery_completed=1)
    assert observations == [False]


def test_duplicate_job_id_is_accepted_without_a_second_execution() -> None:
    scanner = RecordingScanner()
    app = _app(scanner)

    first = _post_once(app, "/jobs/discovery", DISCOVERY_PAYLOAD)
    second = _post_once(app, "/jobs/discovery", DISCOVERY_PAYLOAD)

    assert first == second == (
        202,
        {"job_id": "backend-generated_JOB.01", "accepted": True},
    )
    assert scanner.wait_for(discovery_completed=1)
    assert len(scanner.discovery_requests) == 1


def test_job_id_registry_is_shared_across_job_kinds() -> None:
    scanner = RecordingScanner()
    app = _app(scanner)
    execution_payload = {
        **EXECUTION_PAYLOAD,
        "job_id": DISCOVERY_PAYLOAD["job_id"],
    }

    discovery = _post_once(app, "/jobs/discovery", DISCOVERY_PAYLOAD)
    execution = _post_once(app, "/jobs/execution", execution_payload)

    assert discovery[0] == execution[0] == 202
    assert scanner.wait_for(discovery_completed=1)
    assert len(scanner.discovery_requests) == 1
    assert scanner.execution_requests == []


def test_concurrent_duplicate_registration_schedules_exactly_one_execution() -> None:
    started = threading.Event()
    release = threading.Event()

    def block(_: DiscoveryJobRequest) -> None:
        started.set()
        assert release.wait(timeout=2)

    scanner = RecordingScanner(discovery=block)
    app = _app(scanner)

    with TestClient(app) as client:
        def post() -> tuple[int, dict[str, object]]:
            response = client.post("/jobs/discovery", json=DISCOVERY_PAYLOAD)
            return response.status_code, response.json()

        with ThreadPoolExecutor(max_workers=2) as executor:
            first = executor.submit(post)
            assert started.wait(timeout=1)
            second = executor.submit(post)
            try:
                second_result = second.result(timeout=1)
            finally:
                release.set()
            first_result = first.result(timeout=1)

    assert first_result == second_result == (
        202,
        {"job_id": "backend-generated_JOB.01", "accepted": True},
    )
    assert len(scanner.discovery_requests) == 1


def test_different_job_ids_each_execute() -> None:
    scanner = RecordingScanner()
    app = _app(scanner)
    second_payload = {**DISCOVERY_PAYLOAD, "job_id": "backend-job-other"}

    first = _post_once(app, "/jobs/discovery", DISCOVERY_PAYLOAD)
    second = _post_once(app, "/jobs/discovery", second_payload)

    assert first[0] == second[0] == 202
    assert scanner.wait_for(discovery_completed=2)
    assert [request.job_id for request in scanner.discovery_requests] == [
        "backend-generated_JOB.01",
        "backend-job-other",
    ]


class ConcurrencyScanner(RecordingScanner):
    def __init__(self, *, rendezvous: threading.Barrier | None = None) -> None:
        super().__init__()
        self._rendezvous = rendezvous
        self._active_lock = threading.Lock()
        self.active = 0
        self.max_active = 0
        self.entered = 0
        self.first_entered = threading.Event()
        self.second_entered = threading.Event()
        self.release = threading.Event()
        self.rendezvous_passes = 0
        self.rendezvous_complete = threading.Event()

    def _run(self) -> None:
        with self._active_lock:
            self.active += 1
            self.entered += 1
            self.max_active = max(self.max_active, self.active)
            if self.entered == 1:
                self.first_entered.set()
            if self.entered == 2:
                self.second_entered.set()
        try:
            if self._rendezvous is None:
                assert self.release.wait(timeout=2)
            else:
                try:
                    self._rendezvous.wait(timeout=1)
                except threading.BrokenBarrierError:
                    return
                with self._active_lock:
                    self.rendezvous_passes += 1
                    if self.rendezvous_passes == 2:
                        self.rendezvous_complete.set()
        finally:
            with self._active_lock:
                self.active -= 1

    def run_discovery(self, request: DiscoveryJobRequest) -> None:
        super().run_discovery(request)
        self._run()

    def run_execution(self, request: ExecutionJobRequest) -> None:
        super().run_execution(request)
        self._run()


def test_same_scan_discovery_and_execution_do_not_overlap() -> None:
    scanner = ConcurrencyScanner()
    app = _app(scanner)
    start = threading.Barrier(2)

    def submit(path: str, payload: dict[str, object]) -> tuple[int, dict[str, object]]:
        start.wait(timeout=1)
        return _post_once(app, path, payload)

    with ThreadPoolExecutor(max_workers=2) as executor:
        discovery = executor.submit(
            submit,
            "/jobs/discovery",
            DISCOVERY_PAYLOAD,
        )
        execution = executor.submit(
            submit,
            "/jobs/execution",
            EXECUTION_PAYLOAD,
        )
        assert scanner.first_entered.wait(timeout=1)
        assert not scanner.second_entered.wait(timeout=0.5)
        scanner.release.set()
        discovery_result = discovery.result(timeout=2)
        execution_result = execution.result(timeout=2)
        assert scanner.second_entered.wait(timeout=1)

    assert discovery_result[0] == execution_result[0] == 202
    assert scanner.entered == 2
    assert scanner.max_active == 1


def test_different_scan_ids_execute_concurrently() -> None:
    scanner = ConcurrencyScanner(rendezvous=threading.Barrier(2))
    app = _app(scanner)
    start = threading.Barrier(2)
    other_scan_payload = {
        **EXECUTION_PAYLOAD,
        "job_id": "backend-job-other-scan",
        "scan_id": "scan-002",
    }

    def submit(path: str, payload: dict[str, object]) -> tuple[int, dict[str, object]]:
        start.wait(timeout=1)
        return _post_once(app, path, payload)

    with ThreadPoolExecutor(max_workers=2) as executor:
        discovery = executor.submit(
            submit,
            "/jobs/discovery",
            DISCOVERY_PAYLOAD,
        )
        execution = executor.submit(
            submit,
            "/jobs/execution",
            other_scan_payload,
        )
        discovery_result = discovery.result(timeout=2)
        execution_result = execution.result(timeout=2)
        assert scanner.second_entered.wait(timeout=1)
        assert scanner.rendezvous_complete.wait(timeout=1)

    assert discovery_result[0] == execution_result[0] == 202
    assert scanner.rendezvous_passes == 2
    assert scanner.max_active == 2


def test_same_scan_queue_cannot_saturate_workers_and_starve_another_scan() -> None:
    hot_started = threading.Event()
    other_scan_started = threading.Event()
    release_hot_scan = threading.Event()
    all_hot_jobs_finished = threading.Event()
    hot_job_count = 9
    finished_hot_jobs = 0
    count_lock = threading.Lock()

    def run(request: DiscoveryJobRequest) -> None:
        nonlocal finished_hot_jobs
        if request.scan_id == "scan-hot":
            hot_started.set()
            try:
                assert release_hot_scan.wait(timeout=3)
            finally:
                with count_lock:
                    finished_hot_jobs += 1
                    if finished_hot_jobs == hot_job_count:
                        all_hot_jobs_finished.set()
        else:
            other_scan_started.set()

    scanner = RecordingScanner(discovery=run)
    app = _app(scanner, max_workers=2)
    hot_payloads = [
        {
            **DISCOVERY_PAYLOAD,
            "job_id": f"hot-job-{index}",
            "scan_id": "scan-hot",
        }
        for index in range(hot_job_count)
    ]
    other_payload = {
        **DISCOVERY_PAYLOAD,
        "job_id": "other-scan-job",
        "scan_id": "scan-other",
    }

    with TestClient(app) as client:
        try:
            first = client.post("/jobs/discovery", json=hot_payloads[0])
            assert first.status_code == 202
            assert hot_started.wait(timeout=1)
            for payload in hot_payloads[1:]:
                assert (
                    client.post("/jobs/discovery", json=payload).status_code
                    == 202
                )

            other = client.post("/jobs/discovery", json=other_payload)

            assert other.status_code == 202
            assert other_scan_started.wait(timeout=1)
        finally:
            release_hot_scan.set()

    assert all_hot_jobs_finished.wait(timeout=2)
    assert len(scanner.discovery_requests) == hot_job_count + 1


@pytest.mark.parametrize(
    ("path", "payload", "job_kind", "error_type"),
    [
        (
            "/jobs/discovery",
            DISCOVERY_PAYLOAD,
            JobKind.DISCOVERY,
            DiscoveryJobError,
        ),
        (
            "/jobs/execution",
            EXECUTION_PAYLOAD,
            JobKind.EXECUTION,
            ExecutionJobError,
        ),
    ],
)
def test_known_scanner_failure_is_not_reported_twice(
    path: str,
    payload: dict[str, object],
    job_kind: JobKind,
    error_type: type[Exception],
) -> None:
    backend = FakeBackendClient()

    def fail(request: DiscoveryJobRequest | ExecutionJobRequest) -> None:
        backend.report_error(
            request.job_id,
            ScannerErrorReport(
                code="ALREADY_REPORTED",
                stage=ScannerStage.PROFILE_LOADING,
                retryable=False,
            ),
            scan_id=request.scan_id,
            job_kind=job_kind,
        )
        raise error_type("fixed scanner failure")

    scanner = RecordingScanner(
        discovery=fail if job_kind is JobKind.DISCOVERY else None,  # type: ignore[arg-type]
        execution=fail if job_kind is JobKind.EXECUTION else None,  # type: ignore[arg-type]
    )

    status_code, _ = _post_once(
        _app(scanner, backend=backend),
        path,
        payload,
    )

    assert status_code == 202
    assert scanner.wait_for(
        discovery_completed=1 if job_kind is JobKind.DISCOVERY else 0,
        execution_completed=1 if job_kind is JobKind.EXECUTION else 0,
    )
    assert len(backend.error_events) == 1
    assert backend.error_events[0].report.code == "ALREADY_REPORTED"


@pytest.mark.parametrize(
    ("path", "payload"),
    [
        ("/jobs/discovery", DISCOVERY_PAYLOAD),
        ("/jobs/execution", EXECUTION_PAYLOAD),
    ],
)
def test_known_scanner_failure_callback_error_is_attempted_only_once(
    path: str,
    payload: dict[str, object],
) -> None:
    class CallbackResponseLostBackend(FakeBackendClient):
        def __init__(self) -> None:
            super().__init__()
            self.attempts: list[ScannerErrorReport] = []
            self.first_attempt = threading.Event()
            self.second_attempt = threading.Event()

        def report_error(
            self,
            job_id: str,
            report: ScannerErrorReport,
            *,
            scan_id: str | None = None,
            job_kind: JobKind | None = None,
        ) -> None:
            self.attempts.append(report)
            if len(self.attempts) == 1:
                self.first_attempt.set()
            else:
                self.second_attempt.set()
            raise RuntimeError("callback response was lost")

    backend = CallbackResponseLostBackend()
    scanner = Scanner(backend)
    app = create_app(scanner=scanner, backend=backend, max_workers=1)

    status_code, _ = _post_once(app, path, payload)

    assert status_code == 202
    assert backend.first_attempt.wait(timeout=1)
    assert not backend.second_attempt.wait(timeout=0.5)
    assert len(backend.attempts) == 1
    assert backend.attempts[0].code != "SCANNER_UNEXPECTED_ERROR"


def test_cancellation_does_not_emit_a_failed_callback() -> None:
    backend = FakeBackendClient()

    def cancel(_: DiscoveryJobRequest) -> None:
        raise CancellationRequested("fixed cancellation")

    scanner = RecordingScanner(discovery=cancel)

    status_code, _ = _post_once(
        _app(scanner, backend=backend),
        "/jobs/discovery",
        DISCOVERY_PAYLOAD,
    )

    assert status_code == 202
    assert scanner.wait_for(discovery_completed=1)
    assert backend.error_events == []


def test_unexpected_failure_emits_one_fixed_secret_free_callback_and_stays_seen() -> None:
    class NotifyingBackend(FakeBackendClient):
        def __init__(self) -> None:
            super().__init__()
            self.reported = threading.Event()

        def report_error(
            self,
            job_id: str,
            report: ScannerErrorReport,
            *,
            scan_id: str | None = None,
            job_kind: JobKind | None = None,
        ) -> None:
            super().report_error(
                job_id,
                report,
                scan_id=scan_id,
                job_kind=job_kind,
            )
            self.reported.set()

    backend = NotifyingBackend()

    def fail(_: ExecutionJobRequest) -> None:
        raise RuntimeError("unexpected secret=raw-runtime-token")

    scanner = RecordingScanner(execution=fail)
    app = _app(scanner, backend=backend)

    first = _post_once(app, "/jobs/execution", EXECUTION_PAYLOAD)
    retry = _post_once(app, "/jobs/execution", EXECUTION_PAYLOAD)

    assert scanner.wait_for(execution_completed=1)
    assert backend.reported.wait(timeout=1)
    assert first == retry == (
        202,
        {"job_id": "backend-generated_JOB.02", "accepted": True},
    )
    assert len(scanner.execution_requests) == 1
    assert len(backend.error_events) == 1
    event = backend.error_events[0]
    assert event.job_id == "backend-generated_JOB.02"
    assert event.scan_id == "scan-001"
    assert event.job_kind is JobKind.EXECUTION
    assert event.report == ScannerErrorReport(
        code="SCANNER_UNEXPECTED_ERROR",
        stage=ScannerStage.PROFILE_LOADING,
        retryable=False,
    )
    assert "raw-runtime-token" not in repr(event)


def test_unexpected_failure_reporting_error_is_swallowed_and_job_stays_seen() -> None:
    class FailingBackend:
        def __init__(self) -> None:
            self.attempts = 0
            self.attempted = threading.Event()

        def report_error(self, *_: object, **__: object) -> None:
            self.attempts += 1
            self.attempted.set()
            raise RuntimeError("callback unavailable")

    backend = FailingBackend()

    def fail(_: DiscoveryJobRequest) -> None:
        raise RuntimeError("unexpected scanner failure")

    scanner = RecordingScanner(discovery=fail)
    app = _app(scanner, backend=backend)

    first = _post_once(app, "/jobs/discovery", DISCOVERY_PAYLOAD)
    retry = _post_once(app, "/jobs/discovery", DISCOVERY_PAYLOAD)

    assert backend.attempted.wait(timeout=1)
    assert first[0] == retry[0] == 202
    assert len(scanner.discovery_requests) == 1
    assert backend.attempts == 1
