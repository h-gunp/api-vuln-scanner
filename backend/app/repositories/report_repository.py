import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.report import Report
from app.core.enums import ReportStatus


class ReportRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def add(self, report: Report) -> Report:
        self.session.add(report)
        await self.session.flush()
        return report

    async def get(self, report_id: str) -> Report | None:
        return await self.session.get(Report, report_id)

    async def latest_for_scan(self, scan_id: uuid.UUID) -> Report | None:
        statement = (
            select(Report)
            .where(Report.scan_id == scan_id)
            .order_by(Report.created_at.desc())
            .limit(1)
        )
        return await self.session.scalar(statement)

    async def latest_for_scan_and_status(
        self,
        scan_id: uuid.UUID,
        status: ReportStatus,
    ) -> Report | None:
        statement = (
            select(Report)
            .where(Report.scan_id == scan_id, Report.status == status)
            .order_by(Report.created_at.desc())
            .limit(1)
            .with_for_update()
        )
        return await self.session.scalar(statement)

    async def flush(self) -> None:
        await self.session.flush()

