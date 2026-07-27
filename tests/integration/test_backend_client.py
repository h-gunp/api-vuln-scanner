import hashlib

from scanner.artifacts import ArtifactEnvelope
from scanner.contracts import ApprovalStatus, PlanApprovalDecision
from scanner.integration.backend_client import (
    FakeBackendClient,
    ScannerErrorReport,
    ScannerStage,
)


def test_fake_backend_stores_progress_approval_artifacts_and_cancel_state():
    backend = FakeBackendClient()
    approved_decision = PlanApprovalDecision(
        scan_id="scan-001",
        plan_id="plan-001",
        status=ApprovalStatus.APPROVED,
        reason_codes=(),
    )
    content = b'{"schema_version":"1.1","scan_id":"scan-001","operations":[]}'
    artifact_envelope = ArtifactEnvelope(
        scan_id="scan-001",
        artifact_type="normalized_api_graph",
        schema_version="1.1",
        content=content,
        sha256=hashlib.sha256(content).hexdigest(),
        size=len(content),
    )

    backend.set_artifact("profile:1", b'{"schema_version":"1.1"}')
    assert backend.fetch_artifact("profile:1") == b'{"schema_version":"1.1"}'

    backend.set_requests_used("job-1", 7)
    backend.report_progress("job-1", ScannerStage.AUTHENTICATING, 20, {"actors": 1})
    backend.report_approval("job-1", approved_decision)
    ref = backend.publish_artifact(artifact_envelope)
    backend.report_error(
        "job-1",
        ScannerErrorReport(
            code="AUTH_UNAVAILABLE",
            stage=ScannerStage.AUTHENTICATING,
            retryable=True,
        ),
    )
    backend.cancel("job-1")

    assert ref.startswith("artifact:")
    assert backend.is_cancelled("job-1") is True
    assert backend.get_requests_used("job-1") == 7
    assert backend.progress_events[-1].progress == 20
    assert backend.progress_events[-1].statistics == {"actors": 1}
    assert backend.approval_decisions[-1].status == ApprovalStatus.APPROVED
    assert backend.error_reports[-1].code == "AUTH_UNAVAILABLE"
    assert backend.approval_events[-1].job_id == "job-1"
    assert backend.approval_events[-1].decision == approved_decision
    assert backend.error_events[-1].job_id == "job-1"
    assert backend.error_events[-1].report.code == "AUTH_UNAVAILABLE"


def test_fake_backend_idempotently_reuses_artifact_ref_for_same_scan_type_and_checksum():
    backend = FakeBackendClient()
    content = b'{"schema_version":"1.1"}'
    envelope = ArtifactEnvelope(
        scan_id="scan-001",
        artifact_type="normalized_api_graph",
        schema_version="1.1",
        content=content,
        sha256=hashlib.sha256(content).hexdigest(),
        size=len(content),
    )

    first_ref = backend.publish_artifact(envelope)
    second_ref = backend.publish_artifact(envelope)

    assert second_ref == first_ref
    assert backend.fetch_artifact(first_ref) == content
