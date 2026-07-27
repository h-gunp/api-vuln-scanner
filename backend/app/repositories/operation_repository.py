import uuid
from collections.abc import Iterable

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.operation import Operation
from app.schemas.contracts.normalized_api_graph import NormalizedOperation


class OperationRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def replace_for_scan(
        self,
        scan_id: uuid.UUID,
        operations: Iterable[NormalizedOperation],
    ) -> list[Operation]:
        await self.session.execute(delete(Operation).where(Operation.scan_id == scan_id))
        models = [
            Operation(
                scan_id=scan_id,
                operation_id=item.operation_id,
                method=item.method,
                path_template=item.path_template,
                inputs_json=[entry.model_dump(mode="json") for entry in item.inputs],
                outputs_json=[entry.model_dump(mode="json") for entry in item.outputs],
            )
            for item in operations
        ]
        self.session.add_all(models)
        await self.session.flush()
        return models

    async def list_for_scan(self, scan_id: uuid.UUID) -> list[Operation]:
        result = await self.session.scalars(
            select(Operation)
            .where(Operation.scan_id == scan_id)
            .order_by(Operation.method, Operation.path_template)
        )
        return list(result)

    async def get_by_operation_id(
        self,
        scan_id: uuid.UUID,
        operation_id: str,
    ) -> Operation | None:
        statement = select(Operation).where(
            Operation.scan_id == scan_id,
            Operation.operation_id == operation_id,
        )
        return await self.session.scalar(statement)

    async def existing_ids(self, scan_id: uuid.UUID) -> set[str]:
        result = await self.session.scalars(
            select(Operation.operation_id).where(Operation.scan_id == scan_id)
        )
        return set(result)

