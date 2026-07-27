from abc import ABC, abstractmethod

from app.integrations.common import ExternalSubmission
from app.schemas.contracts.target_profile import TargetProfile


class ScannerClient(ABC):
    @abstractmethod
    async def submit_scan(self, profile: TargetProfile) -> ExternalSubmission:
        raise NotImplementedError

