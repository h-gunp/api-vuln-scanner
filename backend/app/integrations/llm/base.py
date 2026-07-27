from abc import ABC, abstractmethod

from app.integrations.common import ExternalSubmission
from app.schemas.contracts.normalized_api_graph import NormalizedAPIGraph
from app.schemas.contracts.relationship_analysis import RelationshipAnalysis


class LLMClient(ABC):
    @abstractmethod
    async def request_relationship_analysis(
        self,
        graph: NormalizedAPIGraph,
    ) -> ExternalSubmission:
        raise NotImplementedError

    @abstractmethod
    async def request_scan_plan(
        self,
        analysis: RelationshipAnalysis,
    ) -> ExternalSubmission:
        raise NotImplementedError

    @abstractmethod
    async def request_report(self, scan_id: str) -> ExternalSubmission:
        raise NotImplementedError

