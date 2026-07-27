import os
import uuid
from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.core.config import Settings, get_settings
from app.core.database import Base, get_db_session
from app.main import app

TEST_DATABASE_URL = os.getenv("TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(
    not TEST_DATABASE_URL,
    reason="Set TEST_DATABASE_URL to the isolated PostgreSQL test database.",
)


@pytest_asyncio.fixture
async def client(tmp_path: Path) -> AsyncIterator[httpx.AsyncClient]:
    assert TEST_DATABASE_URL is not None
    assert TEST_DATABASE_URL.startswith("postgresql+asyncpg://")
    assert "_test" in TEST_DATABASE_URL, "Integration tests require an isolated *_test database"
    engine = create_async_engine(TEST_DATABASE_URL)
    session_factory = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.drop_all)
        await connection.run_sync(Base.metadata.create_all)

    test_settings = Settings(
        app_env="test",
        database_url=TEST_DATABASE_URL,
        artifact_root=tmp_path / "artifacts",
        task_mode="disabled",
        use_mock_integrations=True,
    )

    async def override_session() -> AsyncIterator[AsyncSession]:
        async with session_factory() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise

    app.dependency_overrides[get_db_session] = override_session
    app.dependency_overrides[get_settings] = lambda: test_settings
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as api_client:
        yield api_client
    app.dependency_overrides.clear()
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.drop_all)
    await engine.dispose()


@pytest.mark.asyncio
async def test_complete_callback_driven_pipeline(client: httpx.AsyncClient) -> None:
    created = await client.post(
        "/api/scans",
        json={"target_url": "https://example.com", "scan_config": None},
    )
    assert created.status_code == 202, created.text
    scan_id = created.json()["scan_id"]
    assert created.json()["status"] == "PENDING"

    status_response = await client.get(f"/api/scans/{scan_id}")
    assert status_response.status_code == 200
    summary_response = await client.get(f"/api/scans/{scan_id}/summary")
    assert summary_response.status_code == 200

    graph = {
        "schema_version": "1.1",
        "scan_id": scan_id,
        "operations": [
            {
                "operation_id": "GET:/api/users/{user_id}",
                "method": "GET",
                "path_template": "/api/users/{user_id}",
                "inputs": [
                    {
                        "location": "path",
                        "field_path": "user_id",
                        "type": "string",
                    }
                ],
                "outputs": [{"field_path": "id", "type": "string"}],
            }
        ],
    }
    graph_response = await client.post(
        f"/internal/scans/{scan_id}/normalized-api-graph",
        json=graph,
    )
    assert graph_response.status_code == 200, graph_response.text
    duplicate = await client.post(
        f"/internal/scans/{scan_id}/normalized-api-graph",
        json=graph,
    )
    assert duplicate.json()["duplicate"] is True

    endpoints = await client.get(f"/api/scans/{scan_id}/endpoints")
    assert endpoints.json()["items"][0]["operation_id"] == "GET:/api/users/{user_id}"

    relationship = {
        "schema_version": "1.2",
        "scan_id": scan_id,
        "model_name": "mock-llm",
        "prompt_version": "rel-v2",
        "prompt_sha256": "a" * 64,
        "approved_module_ids": ["BOLA-001"],
        "relationships": [],
        "test_candidates": [
            {
                "candidate_id": "candidate-001",
                "module_id": "BOLA-001",
                "target_operation_id": "GET:/api/users/{user_id}",
                "required_object_types": ["user"],
                "rationale": "ID flow",
                "priority": 1,
                "executable": True,
                "missing_requirements": [],
                "binding_hints": [
                    {
                        "parameter": "user_id",
                        "location": "path",
                        "binding_type": "object_binding",
                        "object_type": "user",
                    }
                ],
            }
        ],
    }
    relationship_response = await client.post(
        f"/internal/scans/{scan_id}/relationship-analysis",
        json=relationship,
    )
    assert relationship_response.status_code == 200, relationship_response.text

    plan = {
        "schema_version": "1.2",
        "plan_id": str(uuid.uuid4()),
        "scan_id": scan_id,
        "model_name": "mock-llm",
        "prompt_version": "plan-v2",
        "prompt_sha256": "b" * 64,
        "status": "PENDING_APPROVAL",
        "budget": {
            "requests_already_used": 0,
            "estimated_execution_requests": 1,
            "max_requests": 300,
            "within_budget": True,
        },
        "steps": [
            {
                "order": 1,
                "candidate_id": "candidate-001",
                "module_id": "BOLA-001",
                "target_operation_id": "GET:/api/users/{user_id}",
                "target_endpoint": {
                    "method": "GET",
                    "path_template": "/api/users/{user_id}",
                },
                "input_bindings": [
                    {
                        "parameter": "user_id",
                        "location": "path",
                        "binding_type": "object_binding",
                        "object_type": "user",
                        "owner": "user_b",
                    }
                ],
            }
        ],
    }
    plan_response = await client.post(
        f"/internal/scans/{scan_id}/scan-plan",
        json=plan,
    )
    assert plan_response.status_code == 200, plan_response.text
    assert plan_response.json()["details"]["plan_status"] == "APPROVED"

    scan_result = {
        "schema_version": "1.2",
        "scan_id": scan_id,
        "findings": [
            {
                "finding_id": "finding-001",
                "operation_id": "GET:/api/users/{user_id}",
                "module_id": "BOLA-001",
                "severity": "HIGH",
                "verification": {
                    "rule_id": "BOLA-RULE-001",
                    "verified_conditions": ["CROSS_USER_ACCESS_SUCCEEDED"],
                },
                "affected_fields": [],
                "evidence_refs": [],
            }
        ],
    }
    result_response = await client.post(
        f"/internal/scans/{scan_id}/scan-result",
        json=scan_result,
    )
    assert result_response.status_code == 200, result_response.text
    report_id = result_response.json()["details"]["report_id"]

    findings = await client.get(
        f"/api/scans/{scan_id}/findings",
        params={"q": "users", "severity": "HIGH"},
    )
    assert findings.status_code == 200
    assert findings.json()["total_elements"] == 1
    detail = await client.get("/api/findings/finding-001")
    assert detail.status_code == 200
    assert detail.json()["analysis"] is None

    pending_report = await client.get(f"/api/scans/{scan_id}/ai-report")
    assert pending_report.status_code == 409
    assert pending_report.json()["error"]["code"] == "REPORT_NOT_READY"

    ai_report = {
        "schema_version": "1.2",
        "report_id": report_id,
        "scan_id": scan_id,
        "model_name": "mock-llm",
        "prompt_version": "report-v2",
        "prompt_sha256": "c" * 64,
        "overall_risk": "HIGH",
        "overall_risk_basis": "rule:max_verified_severity",
        "summary": "검증된 취약점 1건이 확인되었습니다.",
        "findings": [
            {
                "finding_id": "finding-001",
                "analysis_id": str(uuid.uuid4()),
                "root_cause": "객체 소유권 검증이 누락되었습니다.",
                "attack_flow": ["User A 로그인", "User B 객체 요청"],
                "impact": "다른 사용자의 정보가 노출될 수 있습니다.",
                "recommendation": "서버 측 소유권 검증을 적용합니다.",
                "severity": "HIGH",
                "evidence_refs": [],
            }
        ],
    }
    report_callback = await client.post(
        f"/internal/scans/{scan_id}/ai-report",
        json=ai_report,
    )
    assert report_callback.status_code == 200, report_callback.text

    report = await client.get(f"/api/scans/{scan_id}/ai-report")
    assert report.status_code == 200
    assert report.json()["overall_risk"] == "HIGH"
    enriched_detail = await client.get("/api/findings/finding-001")
    assert enriched_detail.json()["analysis"]["root_cause"].startswith("객체")

    download = await client.get(f"/api/reports/{report_id}/download")
    assert download.status_code == 200
    assert download.headers["content-type"] == "application/pdf"
    assert download.content.startswith(b"%PDF-1.4")

    completed = await client.get(f"/api/scans/{scan_id}")
    assert completed.json()["status"] == "COMPLETED"
    assert completed.json()["progress"] == 100
    completed_summary = await client.get(f"/api/scans/{scan_id}/summary")
    assert completed_summary.json()["overall_risk"] == "HIGH"


@pytest.mark.asyncio
async def test_common_not_found_error(client: httpx.AsyncClient) -> None:
    response = await client.get(f"/api/scans/{uuid.uuid4()}")
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "SCAN_NOT_FOUND"

