"""Backend port and in-memory fake used by the scanner worker."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Mapping, Protocol

from scanner.artifacts import ArtifactEnvelope
from scanner.contracts import PlanApprovalDecision


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


@dataclass(frozen=True)
class ApprovalEvent:
    job_id: str
    decision: PlanApprovalDecision


@dataclass(frozen=True)
class ErrorEvent:
    job_id: str
    report: ScannerErrorReport


class BackendClient(Protocol):
    def fetch_artifact(self, ref: str) -> bytes: ...

    def get_requests_used(self, job_id: str) -> int: ...

    def report_progress(
        self,
        job_id: str,
        stage: ScannerStage,
        progress: int,
        statistics: Mapping[str, int],
    ) -> None: ...

    def report_approval(self, job_id: str, decision: PlanApprovalDecision) -> None: ...

    def publish_artifact(self, envelope: ArtifactEnvelope) -> str: ...

    def report_error(self, job_id: str, report: ScannerErrorReport) -> None: ...

    def is_cancelled(self, job_id: str) -> bool: ...


class FakeBackendClient:
    """Local fake with no network, persistence, or backend-service behavior."""

    def __init__(self) -> None:
        self._artifacts: dict[str, bytes] = {}
        self._artifact_refs: dict[tuple[str, str, str], str] = {}
        self._requests_used: dict[str, int] = {}
        self._cancelled_jobs: set[str] = set()
        self.progress_events: list[ProgressEvent] = []
        self.approval_decisions: list[PlanApprovalDecision] = []
        self.error_reports: list[ScannerErrorReport] = []
        self.approval_events: list[ApprovalEvent] = []
        self.error_events: list[ErrorEvent] = []

    def set_artifact(self, ref: str, content: bytes) -> None:
        self._artifacts[ref] = content

    def fetch_artifact(self, ref: str) -> bytes:
        return self._artifacts[ref]

    def set_requests_used(self, job_id: str, requests_used: int) -> None:
        self._requests_used[job_id] = requests_used

    def get_requests_used(self, job_id: str) -> int:
        return self._requests_used.get(job_id, 0)

    def report_progress(
        self,
        job_id: str,
        stage: ScannerStage,
        progress: int,
        statistics: Mapping[str, int],
    ) -> None:
        self.progress_events.append(
            ProgressEvent(job_id, stage, progress, dict(statistics))
        )

    def report_approval(self, job_id: str, decision: PlanApprovalDecision) -> None:
        self.approval_decisions.append(decision)
        self.approval_events.append(ApprovalEvent(job_id, decision))

    def publish_artifact(self, envelope: ArtifactEnvelope) -> str:
        key = (envelope.scan_id, envelope.artifact_type, envelope.sha256)
        if key not in self._artifact_refs:
            ref = f"artifact:{len(self._artifact_refs) + 1}"
            self._artifact_refs[key] = ref
            self._artifacts[ref] = envelope.content
        return self._artifact_refs[key]

    def report_error(self, job_id: str, report: ScannerErrorReport) -> None:
        self.error_reports.append(report)
        self.error_events.append(ErrorEvent(job_id, report))

    def cancel(self, job_id: str) -> None:
        self._cancelled_jobs.add(job_id)

    def is_cancelled(self, job_id: str) -> bool:
        return job_id in self._cancelled_jobs
