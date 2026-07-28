"""Backend port, stateless HTTP adapter, and deterministic in-memory fake."""

from __future__ import annotations

import json
import math
import os
import re
import threading
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Mapping, Protocol
from urllib.parse import urljoin, urlsplit

import httpx

from scanner.artifacts import ArtifactEnvelope
from scanner.contracts import PlanApprovalDecision


_OPAQUE_COMPONENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")
_CONFIGURATION_ERROR = "backend client configuration is invalid"
_CONTEXT_REQUIRED_ERROR = "backend callback context is required"
_CONTEXT_INVALID_ERROR = "backend callback context is invalid"
_PAYLOAD_INVALID_ERROR = "backend callback payload is invalid"
_REQUEST_FAILED_ERROR = "backend request failed"
_ARTIFACT_RESPONSE_ERROR = "backend artifact response is invalid"
_ARTIFACT_LOCATION_ERROR = "backend artifact location is invalid"
_FAILURE_MESSAGE = "scanner job failed"


class BackendIntegrationError(RuntimeError):
    """A fixed, non-sensitive backend integration failure."""


class JobKind(StrEnum):
    DISCOVERY = "DISCOVERY"
    EXECUTION = "EXECUTION"


class ScannerStage(StrEnum):
    PROFILE_LOADING = "PROFILE_LOADING"
    AUTHENTICATING = "AUTHENTICATING"
    DISCOVERING = "DISCOVERING"
    NORMALIZING = "NORMALIZING"
    OBJECT_DISCOVERY = "OBJECT_DISCOVERY"
    POLICY_VALIDATION = "POLICY_VALIDATION"
    EXECUTING = "EXECUTING"
    VERIFYING = "VERIFYING"
    COMPLETED = "COMPLETED"
    CANCELED = "CANCELED"


_STAGE_MAPPINGS: dict[JobKind, dict[ScannerStage, str]] = {
    JobKind.DISCOVERY: {
        ScannerStage.PROFILE_LOADING: "API_DISCOVERY",
        ScannerStage.AUTHENTICATING: "API_DISCOVERY",
        ScannerStage.DISCOVERING: "API_DISCOVERY",
        ScannerStage.OBJECT_DISCOVERY: "API_DISCOVERY",
        ScannerStage.NORMALIZING: "API_NORMALIZATION",
        ScannerStage.COMPLETED: "API_NORMALIZATION",
    },
    JobKind.EXECUTION: {
        ScannerStage.PROFILE_LOADING: "PLAN_VALIDATION",
        ScannerStage.AUTHENTICATING: "PLAN_VALIDATION",
        ScannerStage.POLICY_VALIDATION: "PLAN_VALIDATION",
        ScannerStage.EXECUTING: "MODULE_EXECUTION",
        ScannerStage.VERIFYING: "RESULT_VALIDATION",
        ScannerStage.COMPLETED: "RESULT_VALIDATION",
    },
}

_ARTIFACT_ROUTES: dict[str, tuple[JobKind, str]] = {
    "normalized_api_graph": (
        JobKind.DISCOVERY,
        "normalized-api-graph",
    ),
    "scan_result": (JobKind.EXECUTION, "scan-result"),
    "evidence": (JobKind.EXECUTION, "evidence"),
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
            raise BackendIntegrationError(_CONFIGURATION_ERROR) from None
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
            raise BackendIntegrationError(_CONFIGURATION_ERROR)
        token = self.internal_service_token
        if token is not None and (not isinstance(token, str) or not token.strip()):
            token = None
        if self.internal_auth_enabled and token is None:
            raise BackendIntegrationError(_CONFIGURATION_ERROR)
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
            raise BackendIntegrationError(_CONFIGURATION_ERROR) from None
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


def _map_stage(job_kind: JobKind, stage: ScannerStage) -> str:
    try:
        return _STAGE_MAPPINGS[job_kind][stage]
    except (KeyError, TypeError):
        raise BackendIntegrationError(_CONTEXT_INVALID_ERROR) from None


def _optional_job_kind(job_kind: JobKind | None) -> JobKind | None:
    if job_kind is None:
        return None
    try:
        return JobKind(job_kind)
    except (TypeError, ValueError):
        raise BackendIntegrationError(_CONTEXT_INVALID_ERROR) from None


def _required_context(
    *,
    job_id: str | None,
    scan_id: str | None,
    job_kind: JobKind | None,
) -> tuple[str, str, JobKind]:
    if job_id is None or scan_id is None or job_kind is None:
        raise BackendIntegrationError(_CONTEXT_REQUIRED_ERROR)
    normalized_kind = _optional_job_kind(job_kind)
    if (
        not isinstance(job_id, str)
        or not job_id
        or not isinstance(scan_id, str)
        or _OPAQUE_COMPONENT.fullmatch(scan_id) is None
        or normalized_kind is None
    ):
        raise BackendIntegrationError(_CONTEXT_INVALID_ERROR)
    return job_id, scan_id, normalized_kind


def _progress_payload(
    *,
    job_kind: JobKind,
    stage: ScannerStage,
    progress: int,
    statistics: Mapping[str, int],
) -> dict[str, object]:
    if (
        isinstance(progress, bool)
        or not isinstance(progress, int)
        or progress < 0
        or not isinstance(statistics, Mapping)
    ):
        raise BackendIntegrationError(_PAYLOAD_INVALID_ERROR)
    return {
        "stage": _map_stage(job_kind, stage),
        "progress": min(progress, 99),
        "message": None,
        "metrics": dict(statistics),
    }


def _approval_payload(
    job_id: str,
    decision: PlanApprovalDecision,
) -> dict[str, object]:
    return {
        "job_id": job_id,
        "plan_id": decision.plan_id,
        "status": decision.status.value,
        "reason_codes": list(decision.reason_codes),
    }


def _error_payload(
    report: ScannerErrorReport,
    *,
    job_kind: JobKind,
) -> dict[str, object]:
    return {
        "source": "SCANNER",
        "stage": _map_stage(job_kind, report.stage),
        "error": {
            "code": report.code,
            "message": _FAILURE_MESSAGE,
            "details": {"retryable": report.retryable},
        },
    }


@dataclass(frozen=True)
class ScannerErrorReport:
    code: str
    stage: ScannerStage
    retryable: bool


@dataclass(frozen=True)
class ProgressEvent:
    job_id: str
    stage: ScannerStage
    progress: int
    statistics: Mapping[str, int]
    scan_id: str | None = None
    job_kind: JobKind | None = None
    backend_stage: str | None = None
    payload: Mapping[str, object] | None = None


@dataclass(frozen=True)
class ApprovalEvent:
    job_id: str
    decision: PlanApprovalDecision
    scan_id: str | None = None
    job_kind: JobKind | None = None
    payload: Mapping[str, object] | None = None


@dataclass(frozen=True)
class ErrorEvent:
    job_id: str
    report: ScannerErrorReport
    scan_id: str | None = None
    job_kind: JobKind | None = None
    backend_stage: str | None = None
    payload: Mapping[str, object] | None = None


@dataclass(frozen=True)
class ArtifactEvent:
    job_id: str | None
    scan_id: str
    job_kind: JobKind | None
    artifact_type: str
    payload: object
    artifact_ref: str


class BackendClient(Protocol):
    def fetch_artifact(
        self,
        ref: str,
        *,
        job_id: str | None = None,
        scan_id: str | None = None,
        job_kind: JobKind | None = None,
    ) -> bytes: ...

    def get_requests_used(
        self,
        job_id: str,
        *,
        scan_id: str | None = None,
        job_kind: JobKind | None = None,
    ) -> int: ...

    def report_progress(
        self,
        job_id: str,
        stage: ScannerStage,
        progress: int,
        statistics: Mapping[str, int],
        *,
        scan_id: str | None = None,
        job_kind: JobKind | None = None,
    ) -> None: ...

    def report_approval(
        self,
        job_id: str,
        decision: PlanApprovalDecision,
        *,
        scan_id: str | None = None,
        job_kind: JobKind | None = None,
    ) -> None: ...

    def publish_artifact(
        self,
        envelope: ArtifactEnvelope,
        *,
        job_id: str | None = None,
        scan_id: str | None = None,
        job_kind: JobKind | None = None,
    ) -> str: ...

    def report_error(
        self,
        job_id: str,
        report: ScannerErrorReport,
        *,
        scan_id: str | None = None,
        job_kind: JobKind | None = None,
    ) -> None: ...

    def is_cancelled(
        self,
        job_id: str,
        *,
        scan_id: str | None = None,
        job_kind: JobKind | None = None,
    ) -> bool: ...


class FakeBackendClient:
    """Local fake with no network, persistence, or backend-service behavior."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._artifacts: dict[str, bytes] = {}
        self._artifact_refs: dict[tuple[str, str, str], str] = {}
        self._requests_used: dict[str, int] = {}
        self._cancelled_jobs: set[str] = set()
        self.progress_events: list[ProgressEvent] = []
        self.approval_decisions: list[PlanApprovalDecision] = []
        self.error_reports: list[ScannerErrorReport] = []
        self.approval_events: list[ApprovalEvent] = []
        self.error_events: list[ErrorEvent] = []
        self.artifact_events: list[ArtifactEvent] = []

    def set_artifact(self, ref: str, content: bytes) -> None:
        with self._lock:
            self._artifacts[ref] = content

    def fetch_artifact(
        self,
        ref: str,
        *,
        job_id: str | None = None,
        scan_id: str | None = None,
        job_kind: JobKind | None = None,
    ) -> bytes:
        with self._lock:
            return self._artifacts[ref]

    def set_requests_used(self, job_id: str, requests_used: int) -> None:
        with self._lock:
            self._requests_used[job_id] = requests_used

    def get_requests_used(
        self,
        job_id: str,
        *,
        scan_id: str | None = None,
        job_kind: JobKind | None = None,
    ) -> int:
        with self._lock:
            return self._requests_used.get(job_id, 0)

    def report_progress(
        self,
        job_id: str,
        stage: ScannerStage,
        progress: int,
        statistics: Mapping[str, int],
        *,
        scan_id: str | None = None,
        job_kind: JobKind | None = None,
    ) -> None:
        normalized_kind = _optional_job_kind(job_kind)
        payload = (
            _progress_payload(
                job_kind=normalized_kind,
                stage=stage,
                progress=progress,
                statistics=statistics,
            )
            if normalized_kind is not None
            else None
        )
        with self._lock:
            self.progress_events.append(
                ProgressEvent(
                    job_id,
                    stage,
                    progress,
                    dict(statistics),
                    scan_id=scan_id,
                    job_kind=normalized_kind,
                    backend_stage=(
                        str(payload["stage"]) if payload is not None else None
                    ),
                    payload=payload,
                )
            )

    def report_approval(
        self,
        job_id: str,
        decision: PlanApprovalDecision,
        *,
        scan_id: str | None = None,
        job_kind: JobKind | None = None,
    ) -> None:
        normalized_kind = _optional_job_kind(job_kind)
        with self._lock:
            self.approval_decisions.append(decision)
            self.approval_events.append(
                ApprovalEvent(
                    job_id,
                    decision,
                    scan_id=scan_id,
                    job_kind=normalized_kind,
                    payload=_approval_payload(job_id, decision),
                )
            )

    def publish_artifact(
        self,
        envelope: ArtifactEnvelope,
        *,
        job_id: str | None = None,
        scan_id: str | None = None,
        job_kind: JobKind | None = None,
    ) -> str:
        try:
            payload: object = json.loads(envelope.content)
        except (UnicodeDecodeError, json.JSONDecodeError):
            payload = None
        normalized_kind = _optional_job_kind(job_kind)
        key = (envelope.scan_id, envelope.artifact_type, envelope.sha256)
        with self._lock:
            if key not in self._artifact_refs:
                ref = f"artifact:{len(self._artifact_refs) + 1}"
                self._artifact_refs[key] = ref
                self._artifacts[ref] = envelope.content
            artifact_ref = self._artifact_refs[key]
            self.artifact_events.append(
                ArtifactEvent(
                    job_id=job_id,
                    scan_id=scan_id or envelope.scan_id,
                    job_kind=normalized_kind,
                    artifact_type=envelope.artifact_type,
                    payload=payload,
                    artifact_ref=artifact_ref,
                )
            )
        return artifact_ref

    def report_error(
        self,
        job_id: str,
        report: ScannerErrorReport,
        *,
        scan_id: str | None = None,
        job_kind: JobKind | None = None,
    ) -> None:
        normalized_kind = _optional_job_kind(job_kind)
        payload = (
            _error_payload(report, job_kind=normalized_kind)
            if normalized_kind is not None
            else None
        )
        with self._lock:
            self.error_reports.append(report)
            self.error_events.append(
                ErrorEvent(
                    job_id,
                    report,
                    scan_id=scan_id,
                    job_kind=normalized_kind,
                    backend_stage=(
                        str(payload["stage"]) if payload is not None else None
                    ),
                    payload=payload,
                )
            )

    def cancel(self, job_id: str) -> None:
        with self._lock:
            self._cancelled_jobs.add(job_id)

    def is_cancelled(
        self,
        job_id: str,
        *,
        scan_id: str | None = None,
        job_kind: JobKind | None = None,
    ) -> bool:
        with self._lock:
            return job_id in self._cancelled_jobs


class HttpBackendClient:
    """Stateless synchronous adapter for Scanner-to-backend callbacks."""

    def __init__(
        self,
        settings: BackendSettings,
        *,
        client: httpx.Client | None = None,
    ) -> None:
        self._settings = settings
        self._client = client or httpx.Client()
        self._owns_client = client is None

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def __enter__(self) -> HttpBackendClient:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def fetch_artifact(
        self,
        ref: str,
        *,
        job_id: str | None = None,
        scan_id: str | None = None,
        job_kind: JobKind | None = None,
    ) -> bytes:
        _required_context(
            job_id=job_id,
            scan_id=scan_id,
            job_kind=job_kind,
        )
        url = self._artifact_url(ref)
        response = self._send("GET", url)
        return response.content

    def get_requests_used(
        self,
        job_id: str,
        *,
        scan_id: str | None = None,
        job_kind: JobKind | None = None,
    ) -> int:
        _required_context(
            job_id=job_id,
            scan_id=scan_id,
            job_kind=job_kind,
        )
        return 0

    def report_progress(
        self,
        job_id: str,
        stage: ScannerStage,
        progress: int,
        statistics: Mapping[str, int],
        *,
        scan_id: str | None = None,
        job_kind: JobKind | None = None,
    ) -> None:
        _, resolved_scan_id, resolved_kind = _required_context(
            job_id=job_id,
            scan_id=scan_id,
            job_kind=job_kind,
        )
        route = (
            "progress"
            if resolved_kind is JobKind.DISCOVERY
            else "execution-progress"
        )
        payload = _progress_payload(
            job_kind=resolved_kind,
            stage=stage,
            progress=progress,
            statistics=statistics,
        )
        self._post(
            f"/internal/scans/{resolved_scan_id}/{route}",
            payload,
        )

    def report_approval(
        self,
        job_id: str,
        decision: PlanApprovalDecision,
        *,
        scan_id: str | None = None,
        job_kind: JobKind | None = None,
    ) -> None:
        _, resolved_scan_id, resolved_kind = _required_context(
            job_id=job_id,
            scan_id=scan_id,
            job_kind=job_kind,
        )
        if (
            resolved_kind is not JobKind.EXECUTION
            or decision.scan_id != resolved_scan_id
        ):
            raise BackendIntegrationError(_CONTEXT_INVALID_ERROR)
        self._post(
            f"/internal/scans/{resolved_scan_id}/plan-approval",
            _approval_payload(job_id, decision),
        )

    def publish_artifact(
        self,
        envelope: ArtifactEnvelope,
        *,
        job_id: str | None = None,
        scan_id: str | None = None,
        job_kind: JobKind | None = None,
    ) -> str:
        _, resolved_scan_id, resolved_kind = _required_context(
            job_id=job_id,
            scan_id=scan_id,
            job_kind=job_kind,
        )
        route = _ARTIFACT_ROUTES.get(envelope.artifact_type)
        if (
            route is None
            or route[0] is not resolved_kind
            or envelope.scan_id != resolved_scan_id
        ):
            raise BackendIntegrationError(_CONTEXT_INVALID_ERROR)
        try:
            payload = json.loads(envelope.content)
        except (TypeError, UnicodeDecodeError, json.JSONDecodeError):
            raise BackendIntegrationError(_PAYLOAD_INVALID_ERROR) from None
        response = self._post(
            f"/internal/scans/{resolved_scan_id}/{route[1]}",
            payload,
        )
        return self._artifact_reference(response)

    def report_error(
        self,
        job_id: str,
        report: ScannerErrorReport,
        *,
        scan_id: str | None = None,
        job_kind: JobKind | None = None,
    ) -> None:
        _, resolved_scan_id, resolved_kind = _required_context(
            job_id=job_id,
            scan_id=scan_id,
            job_kind=job_kind,
        )
        self._post(
            f"/internal/scans/{resolved_scan_id}/failed",
            _error_payload(report, job_kind=resolved_kind),
        )

    def is_cancelled(
        self,
        job_id: str,
        *,
        scan_id: str | None = None,
        job_kind: JobKind | None = None,
    ) -> bool:
        _required_context(
            job_id=job_id,
            scan_id=scan_id,
            job_kind=job_kind,
        )
        return False

    def _post(
        self,
        path: str,
        payload: object,
    ) -> httpx.Response:
        return self._send("POST", self._callback_url(path), payload=payload)

    def _send(
        self,
        method: str,
        url: str,
        *,
        payload: object | None = None,
    ) -> httpx.Response:
        headers: dict[str, str] = {}
        if self._settings.internal_auth_enabled:
            headers["Authorization"] = (
                f"Bearer {self._settings.internal_service_token}"
            )
        try:
            request = self._client.build_request(
                method,
                url,
                headers=headers,
                json=payload if method == "POST" else None,
                timeout=self._settings.timeout_seconds,
            )
            if (
                not self._settings.internal_auth_enabled
                and "Authorization" in request.headers
            ):
                del request.headers["Authorization"]
            response = self._client.send(request)
        except Exception:
            raise BackendIntegrationError(_REQUEST_FAILED_ERROR) from None
        if not 200 <= response.status_code < 300:
            raise BackendIntegrationError(_REQUEST_FAILED_ERROR)
        return response

    def _callback_url(self, path: str) -> str:
        return f"{self._settings.base_url}{path}"

    def _artifact_url(self, ref: str) -> str:
        if not isinstance(ref, str) or not ref or "\\" in ref:
            raise BackendIntegrationError(_ARTIFACT_LOCATION_ERROR)
        try:
            parsed_ref = urlsplit(ref)
            if parsed_ref.scheme or parsed_ref.netloc or parsed_ref.fragment:
                raise ValueError
            url = urljoin(f"{self._settings.base_url}/", ref)
            base = urlsplit(self._settings.base_url)
            resolved = urlsplit(url)
            if (
                resolved.scheme != base.scheme
                or resolved.hostname != base.hostname
                or resolved.port != base.port
            ):
                raise ValueError
        except (TypeError, ValueError):
            raise BackendIntegrationError(_ARTIFACT_LOCATION_ERROR) from None
        return url

    @staticmethod
    def _artifact_reference(response: httpx.Response) -> str:
        try:
            payload: Any = response.json()
            artifact_id = payload["details"]["artifact_id"]
        except (ValueError, TypeError, KeyError):
            raise BackendIntegrationError(_ARTIFACT_RESPONSE_ERROR) from None
        if (
            not isinstance(artifact_id, str)
            or _OPAQUE_COMPONENT.fullmatch(artifact_id) is None
        ):
            raise BackendIntegrationError(_ARTIFACT_RESPONSE_ERROR)
        return f"artifact:{artifact_id}"
