from datetime import UTC, datetime

from app.core.enums import STAGE_PROGRESS, ScanStage, ScanStatus
from app.core.error_codes import ErrorCode
from app.core.exceptions import AppError
from app.models.scan import Scan

TERMINAL_STATUSES = {
    ScanStatus.COMPLETED,
    ScanStatus.FAILED,
    ScanStatus.CANCELLED,
    ScanStatus.TIMED_OUT,
}
STATUS_TRANSITIONS: dict[ScanStatus, set[ScanStatus]] = {
    ScanStatus.PENDING: {
        ScanStatus.PENDING,
        ScanStatus.RUNNING,
        ScanStatus.FAILED,
        ScanStatus.CANCELLED,
    },
    ScanStatus.RUNNING: {
        ScanStatus.RUNNING,
        ScanStatus.COMPLETED,
        ScanStatus.FAILED,
        ScanStatus.CANCELLED,
        ScanStatus.TIMED_OUT,
    },
    ScanStatus.COMPLETED: {ScanStatus.COMPLETED},
    ScanStatus.FAILED: {ScanStatus.FAILED},
    ScanStatus.CANCELLED: {ScanStatus.CANCELLED},
    ScanStatus.TIMED_OUT: {ScanStatus.TIMED_OUT},
}
STAGE_ORDER = {stage: index for index, stage in enumerate(ScanStage)}


class ProgressService:
    def transition(
        self,
        scan: Scan,
        *,
        status: ScanStatus | None = None,
        stage: ScanStage | None = None,
        progress: int | None = None,
    ) -> Scan:
        if scan.status in TERMINAL_STATUSES and status != scan.status:
            raise AppError(
                ErrorCode.SCAN_CANNOT_BE_CANCELLED,
                "종료된 스캔의 상태는 변경할 수 없습니다.",
                status_code=409,
            )
        if status is not None and status not in STATUS_TRANSITIONS[scan.status]:
            raise AppError(
                ErrorCode.INVALID_REQUEST,
                f"{scan.status.value}에서 {status.value}(으)로 상태를 변경할 수 없습니다.",
                status_code=409,
            )
        if progress is not None and not 0 <= progress <= 100:
            raise AppError(
                ErrorCode.INVALID_REQUEST,
                "진행률은 0부터 100 사이여야 합니다.",
                status_code=422,
            )
        next_status = status or scan.status
        next_stage = stage or scan.stage
        next_progress = progress if progress is not None else STAGE_PROGRESS[next_stage]
        if (
            scan.status == ScanStatus.RUNNING
            and STAGE_ORDER[next_stage] < STAGE_ORDER[scan.stage]
        ):
            raise AppError(
                ErrorCode.INVALID_REQUEST,
                "스캔 단계를 이전 단계로 되돌릴 수 없습니다.",
                status_code=409,
            )
        next_progress = max(scan.progress, next_progress)

        if next_status != ScanStatus.COMPLETED:
            next_progress = min(next_progress, 99)
        if next_status == ScanStatus.COMPLETED:
            if next_stage != ScanStage.COMPLETED:
                raise AppError(
                    ErrorCode.INVALID_REQUEST,
                    "완료 상태에는 COMPLETED 단계가 필요합니다.",
                    status_code=422,
                )
            next_progress = 100
            scan.completed_at = datetime.now(UTC)
        if next_status == ScanStatus.RUNNING and scan.started_at is None:
            scan.started_at = datetime.now(UTC)

        scan.status = next_status
        scan.stage = next_stage
        scan.progress = next_progress
        return scan
