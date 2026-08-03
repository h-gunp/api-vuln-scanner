"""FastAPI entrypoints for idempotent Scanner Background jobs."""

from __future__ import annotations

import os
import threading
from collections import deque
from collections.abc import AsyncIterator, Callable
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
from functools import partial

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
from scanner.scanner import (
    OPENAPI_PATH_CANDIDATES,
    DiscoveryJobError,
    ExecutionJobError,
    Scanner,
    validate_openapi_path_candidates,
)


_UNEXPECTED_ERROR_CODE = "SCANNER_UNEXPECTED_ERROR"
_DEFAULT_MAX_WORKERS = 4

def _openapi_path_candidates_from_env() -> tuple[str, ...]:
    raw_extra_paths = os.getenv("SCANNER_EXTRA_OPENAPI_PATHS", "")
    extra_paths = tuple(
        path.strip()
        for path in raw_extra_paths.split(",")
        if path.strip()
    )

    return validate_openapi_path_candidates(
        (*OPENAPI_PATH_CANDIDATES, *extra_paths)
    )


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
    ) -> None:
        self._scanner = scanner
        self._backend = backend

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


class _KeyedJobScheduler:
    """Bounded worker pool that submits at most one active job per scan."""

    def __init__(self, max_workers: int) -> None:
        if (
            isinstance(max_workers, bool)
            or not isinstance(max_workers, int)
            or max_workers <= 0
        ):
            raise ValueError("max_workers must be a positive integer")
        self._lock = threading.Lock()
        self._idle = threading.Condition(self._lock)
        self._max_workers = max_workers
        self._executor = ThreadPoolExecutor(
            max_workers=max_workers,
            thread_name_prefix="scanner-job",
        )
        self._accepting = True
        self._queues: dict[str, deque[Callable[[], None]]] = {}
        self._active_scans: set[str] = set()

    def start(self) -> None:
        with self._lock:
            if self._executor is None:
                self._executor = ThreadPoolExecutor(
                    max_workers=self._max_workers,
                    thread_name_prefix="scanner-job",
                )
            self._accepting = True

    def submit(self, scan_id: str, operation: Callable[[], None]) -> None:
        with self._lock:
            if not self._accepting:
                raise RuntimeError("job scheduler is stopped")
            queue = self._queues.setdefault(scan_id, deque())
            queue.append(operation)
            if scan_id in self._active_scans:
                return
            self._active_scans.add(scan_id)
            next_operation = queue.popleft()
        self._dispatch(scan_id, next_operation)

    def _dispatch(
        self,
        scan_id: str,
        operation: Callable[[], None],
    ) -> None:
        with self._lock:
            executor = self._executor
        if executor is None:
            raise RuntimeError("job scheduler is stopped")
        try:
            executor.submit(self._run, scan_id, operation)
        except RuntimeError:
            with self._lock:
                self._queues[scan_id].appendleft(operation)
                self._active_scans.discard(scan_id)
                self._idle.notify_all()

    def _run(
        self,
        scan_id: str,
        operation: Callable[[], None],
    ) -> None:
        try:
            operation()
        finally:
            self._advance(scan_id)

    def _advance(self, scan_id: str) -> None:
        with self._lock:
            queue = self._queues[scan_id]
            if not queue:
                self._active_scans.remove(scan_id)
                self._idle.notify_all()
                return
            next_operation = queue.popleft()
        self._dispatch(scan_id, next_operation)

    def shutdown(self) -> None:
        with self._idle:
            self._accepting = False
            self._idle.wait_for(lambda: not self._active_scans)
            executor = self._executor
            self._executor = None
        if executor is not None:
            executor.shutdown(wait=True)


def create_app(
    *,
    scanner: Scanner | None = None,
    backend: BackendClient | None = None,
    registry: JobRegistry | None = None,
    max_workers: int = _DEFAULT_MAX_WORKERS,
) -> FastAPI:
    """Create one injected or environment-backed scanner worker app."""

    owns_backend = backend is None
    resolved_backend = backend
    if resolved_backend is None:
        resolved_backend = HttpBackendClient(BackendSettings.from_env())
    resolved_scanner = (
        scanner
        if scanner is not None
        else Scanner(
            resolved_backend,
            openapi_path_candidates=_openapi_path_candidates_from_env(),
        )
    )
    resolved_registry = registry if registry is not None else JobRegistry()
    scheduler = _KeyedJobScheduler(max_workers)
    runner = _BackgroundRunner(
        resolved_scanner,
        resolved_backend,
    )

    lifecycle_lock = threading.Lock()
    lifecycle_users = 0

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        nonlocal lifecycle_users
        with lifecycle_lock:
            if lifecycle_users == 0:
                scheduler.start()
            lifecycle_users += 1
        try:
            yield
        finally:
            with lifecycle_lock:
                lifecycle_users -= 1
                is_last_user = lifecycle_users == 0
            if is_last_user:
                scheduler.shutdown()
                if owns_backend:
                    resolved_backend.close()  # type: ignore[attr-defined]

    worker_app = FastAPI(lifespan=lifespan)

    @worker_app.post(
        "/jobs/discovery",
        status_code=status.HTTP_202_ACCEPTED,
    )
    async def submit_discovery(
        request: DiscoveryJobRequest,
        background_tasks: BackgroundTasks,
    ) -> dict[str, object]:
        if resolved_registry.register(request.job_id):
            background_tasks.add_task(
                scheduler.submit,
                request.scan_id,
                partial(runner.run_discovery, request),
            )
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
            background_tasks.add_task(
                scheduler.submit,
                request.scan_id,
                partial(runner.run_execution, request),
            )
        return {"job_id": request.job_id, "accepted": True}

    return worker_app


app = create_app()


__all__ = ["JobRegistry", "app", "create_app"]
