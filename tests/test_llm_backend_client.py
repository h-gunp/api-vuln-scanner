import asyncio
import json
import unittest

import httpx

from llm.contracts import AiReport
from llm.integration.backend_client import (
    BackendSettings,
    HttpBackendCallbackClient,
    LLMJobStage,
)
from llm.prompts import REPORT_PROMPT_SHA256, REPORT_PROMPT_VERSION
from llm.service import LLMService
from tests.test_service import (
    FakeClient,
    PlanDraft,
    api_graph,
    relationship_draft,
    target_profile,
)


class HttpBackendCallbackClientTest(unittest.TestCase):
    def test_three_artifact_paths_failure_shape_and_bearer_auth(self):
        requests = []

        def handler(request: httpx.Request) -> httpx.Response:
            requests.append(
                (
                    request.url.path,
                    request.headers.get("authorization"),
                    json.loads(request.content),
                )
            )
            return httpx.Response(200, json={"accepted": True})

        async def scenario():
            transport = httpx.MockTransport(handler)
            async with httpx.AsyncClient(
                base_url="https://backend.internal",
                transport=transport,
            ) as http_client:
                client = HttpBackendCallbackClient(
                    BackendSettings(
                        base_url="https://backend.internal",
                        internal_auth_enabled=True,
                        internal_service_token="test-service-token",
                    ),
                    client=http_client,
                )
                analysis = LLMService(
                    client=FakeClient([relationship_draft()]),
                    sleep=lambda _: None,
                ).analyze_relationships(target_profile(), api_graph())
                candidate_ids = [
                    item.candidate_id for item in analysis.test_candidates
                ]
                plan = LLMService(
                    client=FakeClient(
                        [PlanDraft(ordered_candidate_ids=candidate_ids)]
                    ),
                    sleep=lambda _: None,
                ).create_scan_plan(
                    target_profile(),
                    api_graph(),
                    analysis,
                    requests_already_used=12,
                )
                report = AiReport(
                    schema_version="1.2",
                    scan_id="scan-001",
                    model_name="gpt-4o-mini-2024-07-18",
                    prompt_version=REPORT_PROMPT_VERSION,
                    prompt_sha256=REPORT_PROMPT_SHA256,
                    overall_risk="low",
                    overall_risk_basis="rule:max_verified_severity",
                    summary="검증 규칙으로 확정된 취약점이 없습니다.",
                    findings=[],
                )

                await client.publish_relationship_analysis(
                    "scan-001", analysis
                )
                await client.publish_scan_plan("scan-001", plan)
                await client.publish_ai_report("scan-001", report)
                await client.report_failure(
                    "scan-001",
                    LLMJobStage.PLAN_GENERATION,
                )

        asyncio.run(scenario())

        self.assertEqual(
            [
                "/internal/scans/scan-001/relationship-analysis",
                "/internal/scans/scan-001/scan-plan",
                "/internal/scans/scan-001/ai-report",
                "/internal/scans/scan-001/failed",
            ],
            [request[0] for request in requests],
        )
        self.assertEqual(
            {"Bearer test-service-token"},
            {request[1] for request in requests},
        )
        failure = requests[-1][2]
        self.assertEqual(
            {
                "source": "LLM",
                "stage": "PLAN_GENERATION",
                "error": {
                    "code": "LLM_SCAN_PLAN_FAILED",
                    "message": "llm job failed",
                },
            },
            failure,
        )
        self.assertNotIn("job_id", failure)


if __name__ == "__main__":
    unittest.main()
