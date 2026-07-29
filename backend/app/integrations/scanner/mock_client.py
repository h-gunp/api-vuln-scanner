import uuid

from app.integrations.common import ExternalSubmission
from app.integrations.scanner.base import ScannerClient
from app.schemas.contracts.normalized_api_graph import NormalizedAPIGraph
from app.schemas.contracts.relationship_analysis import RelationshipAnalysis
from app.schemas.contracts.scan_plan import ScanPlan
from app.schemas.contracts.target_profile import TargetProfile


class MockScannerClient(ScannerClient):
    async def submit_discovery(self, profile: TargetProfile) -> ExternalSubmission:
        return ExternalSubmission(external_job_id=f"mock-scanner-{profile.scan_id}-{uuid.uuid4()}")

    async def submit_execution(
        self,
        profile: TargetProfile,
        graph: NormalizedAPIGraph,
        analysis: RelationshipAnalysis,
        plan: ScanPlan,
    ) -> ExternalSubmission:
        return ExternalSubmission(
            external_job_id=f"mock-execution-{profile.scan_id}-{uuid.uuid4()}"
        )

