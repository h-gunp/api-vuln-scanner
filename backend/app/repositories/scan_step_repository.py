import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import ScanStage
from app.models.scan_step import ScanStep


class ScanStepRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def latest(self, scan_id: uuid.UUID, stage: ScanStage) -> ScanStep | None:
        statement = (
            select(ScanStep)
            .where(ScanStep.scan_id == scan_id, ScanStep.stage == stage)
            .order_by(ScanStep.attempt.desc())
            .limit(1)
        )
        return await self.session.scalar(statement)

    async def add(self, step: ScanStep) -> ScanStep:
        self.session.add(step)
        await self.session.flush()
        return step

    async def flush(self) -> None:
        await self.session.flush()

