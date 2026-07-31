import uuid
import json
from pathlib import Path
from typing import Any

from app.core.enums import ArtifactType
from app.core.error_codes import ErrorCode
from app.core.exceptions import AppError
from app.models.scan_artifact import ScanArtifact
from app.repositories.artifact_repository import ArtifactRepository
from app.storage.base import Storage
from app.utils.checksum import sha256_bytes
from app.utils.json_utils import json_bytes

ARTIFACT_PATHS: dict[ArtifactType, str] = {
    ArtifactType.TARGET_PROFILE: "input/target_profile.json",
    ArtifactType.NORMALIZED_API_GRAPH: "discovery/normalized_api_graph.json",
    ArtifactType.RELATIONSHIP_ANALYSIS: "planning/relationship_analysis.json",
    ArtifactType.SCAN_PLAN: "planning/scan_plan.json",
    ArtifactType.SCAN_RESULT: "results/scan_result.json",
    ArtifactType.AI_REPORT: "reports/ai_report.json",
    ArtifactType.PDF_REPORT: "reports/security-report-{scan_id}.pdf",
}


class ArtifactService:
    def __init__(self, repository: ArtifactRepository, storage: Storage) -> None:
        self.repository = repository
        self.storage = storage

    def relative_path(self, scan_id: uuid.UUID, artifact_type: ArtifactType) -> Path:
        filename = ARTIFACT_PATHS[artifact_type].format(scan_id=scan_id)
        return Path("scans") / str(scan_id) / filename

    async def store_json(
        self,
        scan_id: uuid.UUID,
        artifact_type: ArtifactType,
        value: dict[str, Any],
        schema_version: str | None,
    ) -> tuple[ScanArtifact, bool]:
        content = json_bytes(value)
        return await self._store(
            scan_id,
            artifact_type,
            content,
            schema_version=schema_version,
            content_type="application/json",
        )

    async def store_pdf(
        self,
        scan_id: uuid.UUID,
        content: bytes,
    ) -> tuple[ScanArtifact, bool]:
        return await self._store(
            scan_id,
            ArtifactType.PDF_REPORT,
            content,
            schema_version=None,
            content_type="application/pdf",
        )

    async def read_latest_json(
        self,
        scan_id: uuid.UUID,
        artifact_type: ArtifactType,
    ) -> dict[str, Any] | None:
        artifact = await self.repository.latest_by_type(scan_id, artifact_type)
        if not artifact:
            return None
        content = await self.storage.read(Path(artifact.storage_path))
        try:
            value = json.loads(content.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise AppError(
                ErrorCode.ARTIFACT_STORAGE_FAILED,
                "저장된 JSON 산출물을 읽을 수 없습니다.",
                status_code=500,
            ) from exc
        if not isinstance(value, dict):
            raise AppError(
                ErrorCode.ARTIFACT_STORAGE_FAILED,
                "저장된 JSON 산출물의 형식이 올바르지 않습니다.",
                status_code=500,
            )
        return value

    async def _store(
        self,
        scan_id: uuid.UUID,
        artifact_type: ArtifactType,
        content: bytes,
        *,
        schema_version: str | None,
        content_type: str,
    ) -> tuple[ScanArtifact, bool]:
        checksum = sha256_bytes(content)
        duplicate = await self.repository.find_duplicate(scan_id, artifact_type, checksum)
        if duplicate:
            return duplicate, False
        previous = await self.repository.latest_by_type(scan_id, artifact_type)
        if previous and artifact_type != ArtifactType.EVIDENCE:
            # Raw artifacts are immutable. A correction/versioning contract is not yet defined.
            raise AppError(
                ErrorCode.ARTIFACT_STORAGE_FAILED,
                "이미 저장된 산출물과 다른 내용의 callback은 허용되지 않습니다.",
                status_code=409,
                details={"artifact_type": artifact_type.value},
            )

        relative_path = (
            Path("scans")
            / str(scan_id)
            / "results"
            / "evidence"
            / f"{checksum}.json"
            if artifact_type == ArtifactType.EVIDENCE
            else self.relative_path(scan_id, artifact_type)
        )
        try:
            await self.storage.write_atomic(relative_path, content)
            artifact = ScanArtifact(
                scan_id=scan_id,
                artifact_type=artifact_type,
                schema_version=schema_version,
                storage_path=relative_path.as_posix(),
                checksum_sha256=checksum,
                file_size=len(content),
                content_type=content_type,
            )
            stored = await self.repository.add(artifact)
            return stored, stored is artifact
        except AppError:
            raise
        except Exception as exc:
            raise AppError(
                ErrorCode.ARTIFACT_STORAGE_FAILED,
                "산출물을 저장하지 못했습니다.",
                status_code=500,
            ) from exc
