import uuid
from typing import Any

import httpx

from app.core.error_codes import ErrorCode
from app.core.exceptions import AppError
from app.integrations.common import ExternalSubmission
from app.integrations.llm.base import LLMClient
from app.schemas.contracts.normalized_api_graph import NormalizedAPIGraph
from app.schemas.contracts.relationship_analysis import RelationshipAnalysis
from app.schemas.contracts.scan_result import ScanResult
from app.schemas.contracts.target_profile import TargetProfile


class HTTPLLMClient(LLMClient):
    def __init__(
        self,
        base_url: str,
        *,
        service_token: str | None = None,
        timeout_seconds: float = 10.0,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.service_token = service_token
        self.timeout_seconds = timeout_seconds
        self.transport = transport

    async def request_relationship_analysis(
        self,
        profile: TargetProfile,
        graph: NormalizedAPIGraph,
    ) -> ExternalSubmission:
        return await self._submit(
            "/jobs/relationship-analysis",
            {
                "target_profile": profile.model_dump(mode="json"),
                "normalized_api_graph": graph.model_dump(mode="json"),
            },
        )

    async def request_scan_plan(
        self,
        profile: TargetProfile,
        graph: NormalizedAPIGraph,
        analysis: RelationshipAnalysis,
        requests_already_used: int,
    ) -> ExternalSubmission:
        return await self._submit(
            "/jobs/scan-plan",
            {
                "target_profile": profile.model_dump(mode="json"),
                "normalized_api_graph": graph.model_dump(mode="json"),
                "relationship_analysis": analysis.model_dump(mode="json"),
                "requests_already_used": requests_already_used,
            },
        )

    async def request_report(self, result: ScanResult) -> ExternalSubmission:
        return await self._submit(
            "/jobs/ai-report",
            {"scan_result": result.model_dump(mode="json")},
        )

    async def _submit(
        self,
        path: str,
        payload: dict[str, Any],
    ) -> ExternalSubmission:
        job_id = str(uuid.uuid4())
        headers = (
            {"Authorization": f"Bearer {self.service_token}"}
            if self.service_token
            else {}
        )
        try:
            async with httpx.AsyncClient(
                base_url=self.base_url,
                timeout=self.timeout_seconds,
                headers=headers,
                transport=self.transport,
            ) as client:
                response = await client.post(path, json={"job_id": job_id, **payload})
        except httpx.TimeoutException as exc:
            raise AppError(
                ErrorCode.LLM_REQUEST_FAILED,
                "LLM 요청 시간이 초과되었습니다.",
                status_code=504,
            ) from exc
        except httpx.RequestError as exc:
            raise AppError(
                ErrorCode.LLM_REQUEST_FAILED,
                "LLM에 연결할 수 없습니다.",
                status_code=502,
            ) from exc

        if response.status_code != 202:
            raise AppError(
                ErrorCode.LLM_REQUEST_FAILED,
                "LLM이 작업 요청을 거부했습니다.",
                status_code=502,
                details={"upstream_status": response.status_code},
            )
        try:
            body = response.json()
        except ValueError as exc:
            self._malformed(exc)
        if (
            not isinstance(body, dict)
            or body.get("job_id") != job_id
            or body.get("accepted") is not True
        ):
            self._malformed()
        return ExternalSubmission(external_job_id=job_id)

    @staticmethod
    def _malformed(exc: Exception | None = None) -> None:
        error = AppError(
            ErrorCode.LLM_REQUEST_FAILED,
            "LLM 응답 형식이 올바르지 않습니다.",
            status_code=502,
        )
        if exc is not None:
            raise error from exc
        raise error
