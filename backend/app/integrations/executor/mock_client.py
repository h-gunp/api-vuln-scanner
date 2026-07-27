import uuid

from app.integrations.common import ExternalSubmission
from app.integrations.executor.base import ExecutorClient
from app.schemas.contracts.scan_plan import ScanPlan


class MockExecutorClient(ExecutorClient):
    async def execute_plan(self, plan: ScanPlan) -> ExternalSubmission:
        return ExternalSubmission(external_job_id=f"mock-executor-{plan.scan_id}-{uuid.uuid4()}")

