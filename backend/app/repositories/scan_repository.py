import uuid
from collections.abc import Sequence

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.scan import Scan


class ScanRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def add(self, scan: Scan) -> Scan:
        self.session.add(scan)
        await self.session.flush()
        return scan

    async def get(self, scan_id: uuid.UUID) -> Scan | None:
        return await self.session.get(Scan, scan_id)

    async def get_for_update(self, scan_id: uuid.UUID) -> Scan | None:
        statement = select(Scan).where(Scan.id == scan_id).with_for_update()
        return await self.session.scalar(statement)

    async def list_by_ids(self, scan_ids: Sequence[uuid.UUID]) -> list[Scan]:
        result = await self.session.scalars(select(Scan).where(Scan.id.in_(scan_ids)))
        return list(result)

    async def flush(self) -> None:
        await self.session.flush()

