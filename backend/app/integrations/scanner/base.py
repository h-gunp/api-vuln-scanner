from abc import ABC, abstractmethod

from app.integrations.common import ExternalSubmission
from app.schemas.contracts.normalized_api_graph import NormalizedAPIGraph
from app.schemas.contracts.relationship_analysis import RelationshipAnalysis
from app.schemas.contracts.scan_plan import ScanPlan
from app.schemas.contracts.target_profile import TargetProfile


class ScannerClient(ABC):
    @abstractmethod
    async def submit_discovery(self, profile: TargetProfile) -> ExternalSubmission:
        raise NotImplementedError

    @abstractmethod
    async def submit_execution(
        self,
        profile: TargetProfile,
        graph: NormalizedAPIGraph,
        analysis: RelationshipAnalysis,
        plan: ScanPlan,
    ) -> ExternalSubmission:
        raise NotImplementedError

