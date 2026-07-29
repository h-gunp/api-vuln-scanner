from abc import ABC, abstractmethod

from app.integrations.common import ExternalSubmission
from app.schemas.contracts.normalized_api_graph import NormalizedAPIGraph
from app.schemas.contracts.relationship_analysis import RelationshipAnalysis
from app.schemas.contracts.scan_result import ScanResult
from app.schemas.contracts.target_profile import TargetProfile


class LLMClient(ABC):
    @abstractmethod
    async def request_relationship_analysis(
        self,
        profile: TargetProfile,
        graph: NormalizedAPIGraph,
    ) -> ExternalSubmission:
        raise NotImplementedError

    @abstractmethod
    async def request_scan_plan(
        self,
        profile: TargetProfile,
        graph: NormalizedAPIGraph,
        analysis: RelationshipAnalysis,
        requests_already_used: int,
    ) -> ExternalSubmission:
        raise NotImplementedError

    @abstractmethod
    async def request_report(self, result: ScanResult) -> ExternalSubmission:
        raise NotImplementedError

