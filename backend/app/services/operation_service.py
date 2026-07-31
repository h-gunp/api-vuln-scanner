import uuid

from app.core.error_codes import ErrorCode
from app.core.exceptions import AppError
from app.repositories.operation_repository import OperationRepository
from app.repositories.scan_repository import ScanRepository
from app.schemas.contracts.normalized_api_graph import NormalizedAPIGraph
from app.schemas.endpoint import EndpointItem, EndpointListResponse


class OperationService:
    def __init__(
        self,
        operation_repository: OperationRepository,
        scan_repository: ScanRepository,
    ) -> None:
        self.operation_repository = operation_repository
        self.scan_repository = scan_repository

    async def replace_from_graph(
        self,
        scan_id: uuid.UUID,
        graph: NormalizedAPIGraph,
    ) -> None:
        scan = await self.scan_repository.get_for_update(scan_id)
        if not scan:
            raise AppError(
                ErrorCode.SCAN_NOT_FOUND,
                "해당 스캔을 찾을 수 없습니다.",
                status_code=404,
            )
        operations = await self.operation_repository.replace_for_scan(scan_id, graph.operations)
        scan.api_count = len(operations)
        await self.scan_repository.flush()

    async def list_endpoints(self, scan_id: uuid.UUID) -> EndpointListResponse:
        if not await self.scan_repository.get(scan_id):
            raise AppError(
                ErrorCode.SCAN_NOT_FOUND,
                "해당 스캔을 찾을 수 없습니다.",
                status_code=404,
            )
        # TODO: Endpoint search, pagination, and sorting contract pending.
        operations = await self.operation_repository.list_for_scan(scan_id)
        return EndpointListResponse(
            items=[
                EndpointItem(
                    operation_id=operation.operation_id,
                    method=operation.method,
                    path=operation.path_template,
                )
                for operation in operations
            ]
        )

