"""고정 Backend URL만 사용하는 LLM 결과 callback client."""

from __future__ import annotations

import math
import os
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Mapping, Protocol
from urllib.parse import urlsplit

import httpx

from llm.contracts import AiReport
from scanner.contracts import RelationshipAnalysis, ScanPlan


_CONFIGURATION_ERROR = "backend callback configuration is invalid"
_REQUEST_FAILED_ERROR = "backend callback failed"
_FAILURE_MESSAGE = "llm job failed"


class LLMBackendError(RuntimeError):
    """민감정보나 backend 응답 본문을 노출하지 않는 연동 오류."""


class LLMJobStage(StrEnum):
    RELATIONSHIP_ANALYSIS = "RELATIONSHIP_ANALYSIS"
    PLAN_GENERATION = "PLAN_GENERATION"
    REPORT_GENERATION = "REPORT_GENERATION"


_FAILURE_CODES: dict[LLMJobStage, str] = {
    LLMJobStage.RELATIONSHIP_ANALYSIS: "LLM_RELATIONSHIP_ANALYSIS_FAILED",
    LLMJobStage.PLAN_GENERATION: "LLM_SCAN_PLAN_FAILED",
    LLMJobStage.REPORT_GENERATION: "LLM_AI_REPORT_FAILED",
}


@dataclass(frozen=True)
class BackendSettings:
    base_url: str = "http://backend:8000"
    internal_auth_enabled: bool = False
    internal_service_token: str | None = field(default=None, repr=False)
    timeout_seconds: float = 10.0

    def __post_init__(self) -> None:
        try:
            timeout = float(self.timeout_seconds)
            parsed = urlsplit(self.base_url)
            parsed.port
        except (TypeError, ValueError):
            raise LLMBackendError(_CONFIGURATION_ERROR) from None

        if (
            not math.isfinite(timeout)
            or timeout <= 0
            or not isinstance(self.internal_auth_enabled, bool)
            or parsed.scheme not in {"http", "https"}
            or not parsed.netloc
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            raise LLMBackendError(_CONFIGURATION_ERROR)

        token = self.internal_service_token
        if token is not None and (not isinstance(token, str) or not token.strip()):
            token = None
        if self.internal_auth_enabled and token is None:
            raise LLMBackendError(_CONFIGURATION_ERROR)

        object.__setattr__(self, "base_url", self.base_url.rstrip("/"))
        object.__setattr__(self, "internal_service_token", token)
        object.__setattr__(self, "timeout_seconds", timeout)

    @classmethod
    def from_env(
        cls,
        environ: Mapping[str, str] | None = None,
    ) -> BackendSettings:
        values = os.environ if environ is None else environ
        try:
            auth_enabled = _parse_bool(
                values.get("INTERNAL_AUTH_ENABLED", "false")
            )
            timeout = float(values.get("BACKEND_TIMEOUT_SECONDS", "10"))
        except (TypeError, ValueError):
            raise LLMBackendError(_CONFIGURATION_ERROR) from None

        return cls(
            base_url=values.get("BACKEND_BASE_URL", "http://backend:8000"),
            internal_auth_enabled=auth_enabled,
            internal_service_token=values.get("INTERNAL_SERVICE_TOKEN") or None,
            timeout_seconds=timeout,
        )


def _parse_bool(value: str) -> bool:
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ValueError


class BackendCallbackClient(Protocol):
    async def publish_relationship_analysis(
        self,
        scan_id: str,
        artifact: RelationshipAnalysis,
    ) -> None: ...

    async def publish_scan_plan(
        self,
        scan_id: str,
        artifact: ScanPlan,
    ) -> None: ...

    async def publish_ai_report(
        self,
        scan_id: str,
        artifact: AiReport,
    ) -> None: ...

    async def report_failure(
        self,
        scan_id: str,
        stage: LLMJobStage,
    ) -> None: ...


class HttpBackendCallbackClient:
    """Backend의 내부 callback 경로에만 POST하는 비동기 adapter."""

    def __init__(
        self,
        settings: BackendSettings,
        *,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self._settings = settings
        self._owns_client = client is None
        self._headers = (
            {
                "Authorization": (
                    f"Bearer {settings.internal_service_token}"
                )
            }
            if settings.internal_auth_enabled
            else {}
        )
        self._client = client or httpx.AsyncClient(
            base_url=settings.base_url,
            timeout=settings.timeout_seconds,
            trust_env=False,
        )

    async def publish_relationship_analysis(
        self,
        scan_id: str,
        artifact: RelationshipAnalysis,
    ) -> None:
        await self._post(
            f"/internal/scans/{scan_id}/relationship-analysis",
            artifact.model_dump(mode="json"),
        )

    async def publish_scan_plan(
        self,
        scan_id: str,
        artifact: ScanPlan,
    ) -> None:
        await self._post(
            f"/internal/scans/{scan_id}/scan-plan",
            artifact.model_dump(mode="json"),
        )

    async def publish_ai_report(
        self,
        scan_id: str,
        artifact: AiReport,
    ) -> None:
        await self._post(
            f"/internal/scans/{scan_id}/ai-report",
            artifact.model_dump(mode="json"),
        )

    async def report_failure(
        self,
        scan_id: str,
        stage: LLMJobStage,
    ) -> None:
        await self._post(
            f"/internal/scans/{scan_id}/failed",
            {
                "source": "LLM",
                "stage": stage.value,
                "error": {
                    "code": _FAILURE_CODES[stage],
                    "message": _FAILURE_MESSAGE,
                },
            },
        )

    async def _post(self, path: str, payload: dict[str, object]) -> None:
        try:
            response = await self._client.post(
                f"{self._settings.base_url}{path}",
                json=payload,
                headers=self._headers,
            )
            response.raise_for_status()
        except (httpx.HTTPError, ValueError):
            raise LLMBackendError(_REQUEST_FAILED_ERROR) from None

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()
