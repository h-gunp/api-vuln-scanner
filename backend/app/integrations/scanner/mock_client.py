import uuid

from app.integrations.common import ExternalSubmission
from app.integrations.scanner.base import ScannerClient
from app.schemas.contracts.target_profile import TargetProfile


class MockScannerClient(ScannerClient):
    async def submit_scan(self, profile: TargetProfile) -> ExternalSubmission:
        return ExternalSubmission(external_job_id=f"mock-scanner-{profile.scan_id}-{uuid.uuid4()}")

