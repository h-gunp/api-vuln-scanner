import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import JobType
from app.models.external_job import ExternalJob


class ExternalJobRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def add(self, job: ExternalJob) -> ExternalJob:
        self.session.add(job)
        await self.session.flush()
        return job

    async def get(self, job_id: uuid.UUID) -> ExternalJob | None:
        return await self.session.get(ExternalJob, job_id)

    async def latest_for_scan_and_type(
        self,
        scan_id: uuid.UUID,
        job_type: JobType,
    ) -> ExternalJob | None:
        statement = (
            select(ExternalJob)
            .where(ExternalJob.scan_id == scan_id, ExternalJob.job_type == job_type)
            .order_by(ExternalJob.requested_at.desc())
            .limit(1)
        )
        return await self.session.scalar(statement)

    async def by_external_id(
        self,
        scan_id: uuid.UUID,
        job_type: JobType,
        external_job_id: str,
    ) -> ExternalJob | None:
        return await self.session.scalar(
            select(ExternalJob)
            .where(
                ExternalJob.scan_id == scan_id,
                ExternalJob.job_type == job_type,
                ExternalJob.external_job_id == external_job_id,
            )
            .with_for_update()
        )

    async def flush(self) -> None:
        await self.session.flush()
