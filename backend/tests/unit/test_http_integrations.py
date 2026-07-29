import json

import httpx
import pytest

from app.core.error_codes import ErrorCode
from app.core.exceptions import AppError
from app.integrations.llm.http_client import HTTPLLMClient
from app.integrations.scanner.http_client import HTTPScannerClient
from app.schemas.contracts.ai_report import AIReport
from app.schemas.contracts.normalized_api_graph import NormalizedAPIGraph
from app.schemas.contracts.relationship_analysis import RelationshipAnalysis
from app.schemas.contracts.scan_plan import ScanPlan
from app.schemas.contracts.scan_result import ScanResult
from app.schemas.contracts.target_profile import TargetProfile


def profile() -> TargetProfile:
    return TargetProfile.model_validate(
        {
            "schema_version": "1.1",
            "scan_id": "scan-001",
            "target": {
                "base_url": "https://example.test",
                "allowed_paths": ["/*"],
                "allowed_methods": ["GET"],
            },
            "discovery": {"sources": ["openapi", "crawl"], "max_depth": 3},
            "authentication": {
                "login": {
                    "method": "POST",
                    "path": "/api/login",
                    "content_type": "application/json",
                    "username_field": "username",
                    "password_field": "password",
                    "session": {"type": "bearer", "token_field": "token"},
                },
                "actors": [
                    {
                        "actor_id": "user_a",
                        "username_env": "USER_A_USERNAME",
                        "password_env": "USER_A_PASSWORD",
                    },
                    {
                        "actor_id": "user_b",
                        "username_env": "USER_B_USERNAME",
                        "password_env": "USER_B_PASSWORD",
                    },
                ],
            },
            "safety_policy": {
                "max_requests": 300,
                "requests_per_second": 3,
                "state_change_policy": "deny",
                "approved_modules": [
                    "authz",
                    "input_validation",
                    "data_exposure",
                ],
            },
        }
    )


def graph() -> NormalizedAPIGraph:
    return NormalizedAPIGraph.model_validate(
        {
            "schema_version": "1.1",
            "scan_id": "scan-001",
            "operations": [
                {
                    "operation_id": "GET:/api/accounts",
                    "method": "GET",
                    "path_template": "/api/accounts",
                    "inputs": [],
                    "outputs": [],
                }
            ],
        }
    )


def relationship() -> RelationshipAnalysis:
    return RelationshipAnalysis.model_validate(
        {
            "schema_version": "1.2",
            "scan_id": "scan-001",
            "model_name": "model",
            "prompt_version": "rel-v2",
            "prompt_sha256": "a" * 64,
            "approved_module_ids": ["BOLA-001"],
            "relationships": [],
            "test_candidates": [],
        }
    )


def plan() -> ScanPlan:
    return ScanPlan.model_validate(
        {
            "schema_version": "1.2",
            "plan_id": "plan-001",
            "scan_id": "scan-001",
            "model_name": "model",
            "prompt_version": "plan-v2",
            "prompt_sha256": "b" * 64,
            "status": "PENDING_APPROVAL",
            "budget": {
                "requests_already_used": 0,
                "estimated_execution_requests": 0,
                "max_requests": 300,
                "within_budget": True,
            },
            "steps": [],
        }
    )


def result() -> ScanResult:
    return ScanResult.model_validate(
        {"schema_version": "1.2", "scan_id": "scan-001", "findings": []}
    )


@pytest.mark.asyncio
async def test_scanner_client_uses_inline_sources_auth_and_matching_job_id() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        body = json.loads(request.content)
        return httpx.Response(
            202,
            json={"job_id": body["job_id"], "accepted": True},
        )

    client = HTTPScannerClient(
        "http://scanner",
        service_token="internal-token",
        transport=httpx.MockTransport(handler),
    )
    await client.submit_discovery(profile())
    await client.submit_execution(profile(), graph(), relationship(), plan())

    assert [request.url.path for request in requests] == [
        "/jobs/discovery",
        "/jobs/execution",
    ]
    assert all(
        request.headers["authorization"] == "Bearer internal-token"
        for request in requests
    )
    execution = json.loads(requests[1].content)
    assert execution["scan_plan"] == {"inline": plan().model_dump(mode="json")}
    assert execution["target_profile"]["inline"]["scan_id"] == "scan-001"


@pytest.mark.asyncio
async def test_llm_client_sends_all_latest_endpoint_signatures_and_auth() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        body = json.loads(request.content)
        return httpx.Response(
            202,
            json={"job_id": body["job_id"], "accepted": True},
        )

    client = HTTPLLMClient(
        "http://llm",
        service_token="internal-token",
        transport=httpx.MockTransport(handler),
    )
    await client.request_relationship_analysis(profile(), graph())
    await client.request_scan_plan(profile(), graph(), relationship(), 12)
    await client.request_report(result())

    assert [request.url.path for request in requests] == [
        "/jobs/relationship-analysis",
        "/jobs/scan-plan",
        "/jobs/ai-report",
    ]
    bodies = [json.loads(request.content) for request in requests]
    assert bodies[0]["target_profile"]["scan_id"] == "scan-001"
    assert bodies[1]["requests_already_used"] == 12
    assert bodies[2]["scan_result"] == result().model_dump(mode="json")
    assert all(
        request.headers["authorization"] == "Bearer internal-token"
        for request in requests
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("handler", "expected_status"),
    [
        (
            lambda request: (_ for _ in ()).throw(
                httpx.ReadTimeout("timeout", request=request)
            ),
            504,
        ),
        (
            lambda request: (_ for _ in ()).throw(
                httpx.ConnectError("connect", request=request)
            ),
            502,
        ),
        (lambda request: httpx.Response(500, json={"error": "upstream"}), 502),
        (lambda request: httpx.Response(202, content=b"not-json"), 502),
        (
            lambda request: httpx.Response(
                202, json={"job_id": "wrong", "accepted": True}
            ),
            502,
        ),
    ],
)
async def test_scanner_client_maps_transport_and_response_failures(
    handler, expected_status: int
) -> None:
    client = HTTPScannerClient(
        "http://scanner",
        transport=httpx.MockTransport(handler),
    )
    with pytest.raises(AppError) as caught:
        await client.submit_discovery(profile())
    assert caught.value.code == ErrorCode.SCANNER_REQUEST_FAILED
    assert caught.value.status_code == expected_status


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "handler",
    [
        lambda request: (_ for _ in ()).throw(
            httpx.ReadTimeout("timeout", request=request)
        ),
        lambda request: (_ for _ in ()).throw(
            httpx.ConnectError("connect", request=request)
        ),
        lambda request: httpx.Response(503),
        lambda request: httpx.Response(202, json={"accepted": True}),
    ],
)
async def test_llm_client_maps_transport_and_response_failures(handler) -> None:
    client = HTTPLLMClient(
        "http://llm",
        transport=httpx.MockTransport(handler),
    )
    with pytest.raises(AppError) as caught:
        await client.request_report(result())
    assert caught.value.code == ErrorCode.LLM_REQUEST_FAILED


def test_ai_report_artifact_has_no_report_id_and_uses_lowercase_severity() -> None:
    report = AIReport.model_validate(
        {
            "schema_version": "1.2",
            "scan_id": "scan-001",
            "model_name": "model",
            "prompt_version": "report-v2",
            "prompt_sha256": "c" * 64,
            "overall_risk": "low",
            "overall_risk_basis": "rule:max_verified_severity",
            "summary": "No findings.",
            "findings": [],
        }
    )
    assert "report_id" not in report.model_dump(mode="json")
