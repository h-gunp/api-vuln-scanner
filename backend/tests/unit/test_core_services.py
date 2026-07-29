import uuid
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from app.core.config import Settings
from app.core.enums import (
    ArtifactType,
    PlanStatus,
    ScanStage,
    ScanStatus,
    Severity,
)
from app.core.exceptions import AppError
from app.models.scan import Scan
from app.schemas.contracts.normalized_api_graph import NormalizedAPIGraph
from app.schemas.contracts.relationship_analysis import RelationshipAnalysis
from app.schemas.contracts.scan_plan import ScanPlan
from app.services.artifact_service import ArtifactService
from app.services.masking_service import MaskingService
from app.services.plan_validation_service import PlanValidationService
from app.services.progress_service import ProgressService
from app.services.report_service import ReportService
from app.services.target_health_service import TargetHealthService
from app.services.target_profile_service import TargetProfileService
from app.storage.local import LocalStorage
from app.utils.checksum import sha256_bytes
from app.utils.url_utils import is_blocked_ip, normalized_http_url


def test_scan_state_transition_and_completion_progress() -> None:
    scan = Scan(
        id=uuid.uuid4(),
        target_url="https://example.com",
        status=ScanStatus.PENDING,
        stage=ScanStage.TARGET_VALIDATION,
        progress=0,
    )
    service = ProgressService()

    service.transition(
        scan,
        status=ScanStatus.RUNNING,
        stage=ScanStage.API_DISCOVERY,
        progress=25,
    )
    assert scan.status == ScanStatus.RUNNING
    assert scan.progress == 25
    assert scan.started_at is not None

    service.transition(
        scan,
        status=ScanStatus.COMPLETED,
        stage=ScanStage.COMPLETED,
    )
    assert scan.progress == 100
    assert scan.completed_at is not None


def test_non_completed_scan_progress_is_capped_at_99() -> None:
    scan = Scan(
        target_url="https://example.com",
        status=ScanStatus.RUNNING,
        stage=ScanStage.REPORT_GENERATION,
        progress=90,
    )
    ProgressService().transition(scan, progress=100)
    assert scan.progress == 99


def test_target_profile_uses_environment_variable_names_only(tmp_path: Path) -> None:
    settings = Settings(
        database_url="postgresql+asyncpg://postgres:postgres@localhost/scanner",
        artifact_root=tmp_path,
    )
    profile = TargetProfileService(settings).build(
        uuid.uuid4(),
        "https://example.com/api",
    )

    assert profile.target.allowed_methods == ["GET"]
    assert profile.safety_policy.state_change_policy == "deny"
    assert profile.authentication.actors[0].password_env == "USER_A_PASSWORD"
    serialized = profile.model_dump_json()
    assert "actual-password" not in serialized


def test_url_validation_and_private_ip_detection() -> None:
    assert normalized_http_url("https://example.com/api") == "https://example.com/api"
    assert is_blocked_ip("127.0.0.1")
    assert is_blocked_ip("10.0.0.1")
    assert is_blocked_ip("169.254.169.254")
    assert not is_blocked_ip("8.8.8.8")
    with pytest.raises(ValueError):
        normalized_http_url("file:///etc/passwd")


@pytest.mark.asyncio
async def test_health_service_blocks_private_dns_destination(tmp_path: Path) -> None:
    settings = Settings(
        database_url="postgresql+asyncpg://postgres:postgres@localhost/scanner",
        artifact_root=tmp_path,
        allow_private_targets=False,
    )
    service = TargetHealthService(settings)
    service._resolve = AsyncMock(return_value=["127.0.0.1"])  # type: ignore[method-assign]

    with pytest.raises(AppError) as caught:
        await service.validate_destination("https://internal.example")
    assert caught.value.code.value == "SCAN_POLICY_VIOLATION"


def test_normalized_graph_validates_operation_id_and_uniqueness() -> None:
    graph = NormalizedAPIGraph.model_validate(
        {
            "schema_version": "1.1",
            "scan_id": str(uuid.uuid4()),
            "operations": [
                {
                    "operation_id": "GET:/users/{user_id}",
                    "method": "GET",
                    "path_template": "/users/{user_id}",
                    "inputs": [],
                    "outputs": [],
                }
            ],
        }
    )
    assert graph.operations[0].method == "GET"

    with pytest.raises(ValueError):
        NormalizedAPIGraph.model_validate(
            {
                "schema_version": "1.1",
                "scan_id": "scan",
                "operations": [
                    {
                        "operation_id": "GET:/users",
                        "method": "POST",
                        "path_template": "/users",
                    }
                ],
            }
        )


def test_plan_budget_and_policy_validation(tmp_path: Path) -> None:
    scan_id = uuid.uuid4()
    settings = Settings(
        database_url="postgresql+asyncpg://postgres:postgres@localhost/scanner",
        artifact_root=tmp_path,
    )
    profile = TargetProfileService(settings).build(scan_id, "https://example.com")
    analysis = RelationshipAnalysis.model_validate(
        {
            "schema_version": "1.2",
            "scan_id": str(scan_id),
            "model_name": "mock",
            "prompt_version": "rel-v2",
            "prompt_sha256": "a" * 64,
            "approved_module_ids": ["BOLA-001"],
            "relationships": [],
            "test_candidates": [
                {
                    "candidate_id": "candidate-1",
                    "module_id": "BOLA-001",
                    "target_operation_id": "GET:/users/{user_id}",
                    "required_object_types": ["user"],
                    "rationale": "id flow",
                    "priority": 1,
                    "executable": True,
                    "missing_requirements": [],
                    "binding_hints": [],
                }
            ],
        }
    )
    plan = ScanPlan.model_validate(
        {
            "schema_version": "1.2",
            "plan_id": str(uuid.uuid4()),
            "scan_id": str(scan_id),
            "model_name": "mock",
            "prompt_version": "plan-v2",
            "prompt_sha256": "b" * 64,
            "status": "PENDING_APPROVAL",
            "budget": {
                "requests_already_used": 1,
                "estimated_execution_requests": 1,
                "max_requests": 300,
                "within_budget": True,
            },
            "steps": [
                {
                    "order": 1,
                    "candidate_id": "candidate-1",
                    "module_id": "BOLA-001",
                    "target_operation_id": "GET:/users/{user_id}",
                    "target_endpoint": {
                        "method": "GET",
                        "path_template": "/users/{user_id}",
                    },
                        "input_bindings": [
                        {
                            "parameter": "user_id",
                            "location": "path",
                            "binding_type": "object_binding",
                            "object_type": "user",
                                "owner": "user_b",
                            },
                            {
                                "parameter": "page",
                                "location": "query",
                                "binding_type": "parameter_binding",
                                "object_type": None,
                                "owner": None,
                            },
                        ],
                }
            ],
        }
    )

    approved = PlanValidationService().validate(
        scan_id,
        plan,
        profile,
        analysis,
        {"GET:/users/{user_id}"},
    )
    assert approved is plan
    assert approved.status == PlanStatus.PENDING_APPROVAL
    assert plan.status == PlanStatus.PENDING_APPROVAL

    invalid = plan.model_copy(deep=True)
    invalid.budget.within_budget = False
    with pytest.raises(AppError):
        PlanValidationService().validate(
            scan_id,
            invalid,
            profile,
            analysis,
            {"GET:/users/{user_id}"},
        )


def test_severity_sort_order() -> None:
    order = [
        Severity.CRITICAL,
        Severity.HIGH,
        Severity.MEDIUM,
        Severity.LOW,
        Severity.INFO,
    ]
    from app.core.enums import SEVERITY_RANK

    assert sorted(order, key=SEVERITY_RANK.get, reverse=True) == order


def test_zero_finding_report_risk_is_contract_low() -> None:
    assert ReportService._overall_risk([]) == "low"


def test_recursive_masking_for_json_arrays_and_headers() -> None:
    value = {
        "Authorization": "Bearer secret",
        "nested": [
            {
                "Password": "plain",
                "email": "alice@example.com",
                "phone": "010-1234-5678",
                "account_number": "123-456-789012",
            }
        ],
    }
    masked = MaskingService().mask(value)
    assert masked["Authorization"] == "[MASKED]"
    assert masked["nested"][0]["Password"] == "[MASKED]"
    assert masked["nested"][0]["email"].endswith("@example.com")
    assert masked["nested"][0]["phone"] == "010-****-5678"
    assert masked["nested"][0]["account_number"].endswith("9012")


class FakeArtifactRepository:
    def __init__(self) -> None:
        self.items = []

    async def find_duplicate(self, scan_id, artifact_type, checksum):
        return next(
            (
                item
                for item in self.items
                if item.scan_id == scan_id
                and item.artifact_type == artifact_type
                and item.checksum_sha256 == checksum
            ),
            None,
        )

    async def latest_by_type(self, scan_id, artifact_type):
        return next(
            (
                item
                for item in reversed(self.items)
                if item.scan_id == scan_id and item.artifact_type == artifact_type
            ),
            None,
        )

    async def add(self, artifact):
        artifact.id = uuid.uuid4()
        self.items.append(artifact)
        return artifact


@pytest.mark.asyncio
async def test_evidence_artifacts_allow_multiple_immutable_content_paths(
    tmp_path: Path,
) -> None:
    repository = FakeArtifactRepository()
    service = ArtifactService(repository, LocalStorage(tmp_path))  # type: ignore[arg-type]
    scan_id = uuid.uuid4()

    first, first_created = await service.store_json(
        scan_id,
        ArtifactType.EVIDENCE,
        {"scan_id": str(scan_id), "observation": "first"},
        None,
    )
    second, second_created = await service.store_json(
        scan_id,
        ArtifactType.EVIDENCE,
        {"scan_id": str(scan_id), "observation": "second"},
        None,
    )

    assert first_created is True
    assert second_created is True
    assert first.id != second.id
    assert first.storage_path.startswith(f"scans/{scan_id}/results/evidence/")
    assert first.storage_path.endswith(f"{first.checksum_sha256}.json")
    assert second.storage_path.endswith(f"{second.checksum_sha256}.json")


@pytest.mark.asyncio
async def test_artifact_checksum_atomic_storage_and_duplicate_callback(
    tmp_path: Path,
) -> None:
    repository = FakeArtifactRepository()
    service = ArtifactService(repository, LocalStorage(tmp_path))  # type: ignore[arg-type]
    scan_id = uuid.uuid4()
    payload = {"schema_version": "1.1", "scan_id": str(scan_id), "한글": "보존"}

    first, first_created = await service.store_json(
        scan_id,
        ArtifactType.TARGET_PROFILE,
        payload,
        "1.1",
    )
    second, second_created = await service.store_json(
        scan_id,
        ArtifactType.TARGET_PROFILE,
        payload,
        "1.1",
    )

    assert first_created is True
    assert second_created is False
    assert first.id == second.id
    content = (tmp_path / first.storage_path).read_bytes()
    assert sha256_bytes(content) == first.checksum_sha256
    assert "한글" in content.decode("utf-8")

