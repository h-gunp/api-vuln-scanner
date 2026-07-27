import uuid

from app.integrations.common import ExternalSubmission
from app.integrations.llm.base import LLMClient
from app.schemas.contracts.normalized_api_graph import NormalizedAPIGraph
from app.schemas.contracts.relationship_analysis import RelationshipAnalysis


class MockLLMClient(LLMClient):
    async def request_relationship_analysis(
        self,
        graph: NormalizedAPIGraph,
    ) -> ExternalSubmission:
        return ExternalSubmission(external_job_id=f"mock-llm-rel-{graph.scan_id}-{uuid.uuid4()}")

    async def request_scan_plan(
        self,
        analysis: RelationshipAnalysis,
    ) -> ExternalSubmission:
        return ExternalSubmission(
            external_job_id=f"mock-llm-plan-{analysis.scan_id}-{uuid.uuid4()}"
        )

    async def request_report(self, scan_id: str) -> ExternalSubmission:
        return ExternalSubmission(external_job_id=f"mock-llm-report-{scan_id}-{uuid.uuid4()}")

