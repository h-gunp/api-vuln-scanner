"""FastAPI entrypoints for idempotent Scanner Background jobs."""

from __future__ import annotations

import threading
from collections.abc import Callable

from fastapi import BackgroundTasks, FastAPI, status

from scanner.contracts import DiscoveryJobRequest, ExecutionJobRequest
from scanner.integration.backend_client import (
    BackendClient,
    BackendSettings,
    HttpBackendClient,
    JobKind,
    ScannerErrorReport,
    ScannerStage,
)
from scanner.policy import CancellationRequested
from scanner.scanner import DiscoveryJobError, ExecutionJobError, Scanner


_UNEXPECTED_ERROR_CODE = "SCANNER_UNEXPECTED_ERROR"


class JobRegistry:
    """Process-lifetime job deduplication and per-scan serialization state."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._job_ids: set[str] = set()
        self._scan_locks: dict[str, threading.Lock] = {}

    def register(self, job_id: str) -> bool:
        """Atomically retain a job ID and report whether it was new."""

        with self._lock:
            if job_id in self._job_ids:
                return False
            self._job_ids.add(job_id)
            return True

    def scan_lock(self, scan_id: str) -> threading.Lock:
        """Return the stable process-lifetime lock for a scan."""

        with self._lock:
            lock = self._scan_locks.get(scan_id)
            if lock is None:
                lock = threading.Lock()
                self._scan_locks[scan_id] = lock
            return lock


class _BackgroundRunner:
    def __init__(
        self,
        scanner: Scanner,
        backend: BackendClient,
        registry: JobRegistry,
    ) -> None:
        self._scanner = scanner
        self._backend = backend
        self._registry = registry

    def run_discovery(self, request: DiscoveryJobRequest) -> None:
        self._run(
            request=request,
            job_kind=JobKind.DISCOVERY,
            operation=lambda: self._scanner.run_discovery(request),
        )

    def run_execution(self, request: ExecutionJobRequest) -> None:
        self._run(
            request=request,
            job_kind=JobKind.EXECUTION,
            operation=lambda: self._scanner.run_execution(request),
        )

    def _run(
        self,
        *,
        request: DiscoveryJobRequest | ExecutionJobRequest,
        job_kind: JobKind,
        operation: Callable[[], object],
    ) -> None:
        with self._registry.scan_lock(request.scan_id):
            try:
                operation()
            except (DiscoveryJobError, ExecutionJobError):
                return
            except CancellationRequested:
                return
            except Exception:
                self._report_unexpected_failure(request, job_kind)

    def _report_unexpected_failure(
        self,
        request: DiscoveryJobRequest | ExecutionJobRequest,
        job_kind: JobKind,
    ) -> None:
        try:
            self._backend.report_error(
                request.job_id,
                ScannerErrorReport(
                    code=_UNEXPECTED_ERROR_CODE,
                    stage=ScannerStage.PROFILE_LOADING,
                    retryable=False,
                ),
                scan_id=request.scan_id,
                job_kind=job_kind,
            )
        except Exception:
            return


def create_app(
    *,
    scanner: Scanner | None = None,
    backend: BackendClient | None = None,
    registry: JobRegistry | None = None,
) -> FastAPI:
    """Create one injected or environment-backed scanner worker app."""

    resolved_backend = backend
    if resolved_backend is None:
        resolved_backend = HttpBackendClient(BackendSettings.from_env())
    resolved_scanner = scanner if scanner is not None else Scanner(resolved_backend)
    resolved_registry = registry if registry is not None else JobRegistry()
    runner = _BackgroundRunner(
        resolved_scanner,
        resolved_backend,
        resolved_registry,
    )

    worker_app = FastAPI()

    @worker_app.post(
        "/jobs/discovery",
        status_code=status.HTTP_202_ACCEPTED,
    )
    async def submit_discovery(
        request: DiscoveryJobRequest,
        background_tasks: BackgroundTasks,
    ) -> dict[str, object]:
        if resolved_registry.register(request.job_id):
            background_tasks.add_task(runner.run_discovery, request)
        return {"job_id": request.job_id, "accepted": True}

    @worker_app.post(
        "/jobs/execution",
        status_code=status.HTTP_202_ACCEPTED,
    )
    async def submit_execution(
        request: ExecutionJobRequest,
        background_tasks: BackgroundTasks,
    ) -> dict[str, object]:
        if resolved_registry.register(request.job_id):
            background_tasks.add_task(runner.run_execution, request)
        return {"job_id": request.job_id, "accepted": True}

    return worker_app


app = create_app()


__all__ = ["JobRegistry", "app", "create_app"]
