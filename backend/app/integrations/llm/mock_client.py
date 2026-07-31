import uuid

from app.integrations.common import ExternalSubmission
from app.integrations.llm.base import LLMClient
from app.schemas.contracts.normalized_api_graph import NormalizedAPIGraph
from app.schemas.contracts.relationship_analysis import RelationshipAnalysis
from app.schemas.contracts.scan_result import ScanResult
from app.schemas.contracts.target_profile import TargetProfile


class MockLLMClient(LLMClient):
    async def request_relationship_analysis(
        self,
        profile: TargetProfile,
        graph: NormalizedAPIGraph,
    ) -> ExternalSubmission:
        return ExternalSubmission(external_job_id=f"mock-llm-rel-{graph.scan_id}-{uuid.uuid4()}")

    async def request_scan_plan(
        self,
        profile: TargetProfile,
        graph: NormalizedAPIGraph,
        analysis: RelationshipAnalysis,
        requests_already_used: int,
    ) -> ExternalSubmission:
        return ExternalSubmission(
            external_job_id=f"mock-llm-plan-{analysis.scan_id}-{uuid.uuid4()}"
        )

    async def request_report(self, result: ScanResult) -> ExternalSubmission:
        return ExternalSubmission(
            external_job_id=f"mock-llm-report-{result.scan_id}-{uuid.uuid4()}"
        )

