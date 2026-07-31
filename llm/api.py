"""FastAPI entrypoints for idempotent asynchronous LLM jobs."""

from __future__ import annotations

import asyncio
import threading
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from typing import Awaitable

from fastapi import BackgroundTasks, FastAPI, status

from llm.contracts import (
    AiReportJobRequest,
    RelationshipAnalysisJobRequest,
    ScanPlanJobRequest,
)
from llm.integration.backend_client import (
    BackendCallbackClient,
    BackendSettings,
    HttpBackendCallbackClient,
    LLMJobStage,
)
from llm.service import LLMService


class JobRegistry:
    """프로세스 수명 동안 동일 job_id의 중복 실행을 차단한다."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._job_ids: set[str] = set()

    def register(self, job_id: str) -> bool:
        with self._lock:
            if job_id in self._job_ids:
                return False
            self._job_ids.add(job_id)
            return True


class _BackgroundRunner:
    def __init__(
        self,
        service: LLMService,
        backend: BackendCallbackClient,
    ) -> None:
        self._service = service
        self._backend = backend

    async def run_relationship_analysis(
        self,
        request: RelationshipAnalysisJobRequest,
    ) -> None:
        await self._run(
            scan_id=request.target_profile.scan_id,
            stage=LLMJobStage.RELATIONSHIP_ANALYSIS,
            operation=lambda: self._service.analyze_relationships(
                request.target_profile,
                request.normalized_api_graph,
            ),
            publish=lambda artifact: self._backend.publish_relationship_analysis(
                request.target_profile.scan_id,
                artifact,
            ),
        )

    async def run_scan_plan(self, request: ScanPlanJobRequest) -> None:
        await self._run(
            scan_id=request.target_profile.scan_id,
            stage=LLMJobStage.PLAN_GENERATION,
            operation=lambda: self._service.create_scan_plan(
                request.target_profile,
                request.normalized_api_graph,
                request.relationship_analysis,
                requests_already_used=request.requests_already_used,
            ),
            publish=lambda artifact: self._backend.publish_scan_plan(
                request.target_profile.scan_id,
                artifact,
            ),
        )

    async def run_ai_report(self, request: AiReportJobRequest) -> None:
        await self._run(
            scan_id=request.scan_result.scan_id,
            stage=LLMJobStage.REPORT_GENERATION,
            operation=lambda: self._service.create_ai_report(
                request.scan_result
            ),
            publish=lambda artifact: self._backend.publish_ai_report(
                request.scan_result.scan_id,
                artifact,
            ),
        )

    async def _run(
        self,
        *,
        scan_id: str,
        stage: LLMJobStage,
        operation: Callable[[], object],
        publish: Callable[[object], Awaitable[None]],
    ) -> None:
        try:
            artifact = await asyncio.to_thread(operation)
            await publish(artifact)
        except Exception:
            try:
                await self._backend.report_failure(scan_id, stage)
            except Exception:
                return


def create_app(
    *,
    service: LLMService | None = None,
    backend: BackendCallbackClient | None = None,
    registry: JobRegistry | None = None,
) -> FastAPI:
    resolved_service = service or LLMService()
    owns_backend = backend is None
    resolved_backend = backend or HttpBackendCallbackClient(
        BackendSettings.from_env()
    )
    resolved_registry = registry or JobRegistry()
    runner = _BackgroundRunner(resolved_service, resolved_backend)

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        try:
            yield
        finally:
            if owns_backend:
                await resolved_backend.aclose()  # type: ignore[attr-defined]

    worker_app = FastAPI(lifespan=lifespan)

    @worker_app.post(
        "/jobs/relationship-analysis",
        status_code=status.HTTP_202_ACCEPTED,
    )
    async def submit_relationship_analysis(
        request: RelationshipAnalysisJobRequest,
        background_tasks: BackgroundTasks,
    ) -> dict[str, object]:
        is_new = resolved_registry.register(request.job_id)
        if is_new:
            background_tasks.add_task(
                runner.run_relationship_analysis,
                request,
            )
        return {
            "job_id": request.job_id,
            "accepted": True,
            "duplicate": not is_new,
        }

    @worker_app.post(
        "/jobs/scan-plan",
        status_code=status.HTTP_202_ACCEPTED,
    )
    async def submit_scan_plan(
        request: ScanPlanJobRequest,
        background_tasks: BackgroundTasks,
    ) -> dict[str, object]:
        is_new = resolved_registry.register(request.job_id)
        if is_new:
            background_tasks.add_task(runner.run_scan_plan, request)
        return {
            "job_id": request.job_id,
            "accepted": True,
            "duplicate": not is_new,
        }

    @worker_app.post(
        "/jobs/ai-report",
        status_code=status.HTTP_202_ACCEPTED,
    )
    async def submit_ai_report(
        request: AiReportJobRequest,
        background_tasks: BackgroundTasks,
    ) -> dict[str, object]:
        is_new = resolved_registry.register(request.job_id)
        if is_new:
            background_tasks.add_task(runner.run_ai_report, request)
        return {
            "job_id": request.job_id,
            "accepted": True,
            "duplicate": not is_new,
        }

    return worker_app


app = create_app()
