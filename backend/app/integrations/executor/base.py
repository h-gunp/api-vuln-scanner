from abc import ABC, abstractmethod

from app.integrations.common import ExternalSubmission
from app.schemas.contracts.scan_plan import ScanPlan


class ExecutorClient(ABC):
    @abstractmethod
    async def execute_plan(self, plan: ScanPlan) -> ExternalSubmission:
        raise NotImplementedError

