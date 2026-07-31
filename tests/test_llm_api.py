import unittest

from fastapi.testclient import TestClient

from llm.api import JobRegistry, create_app
from llm.contracts import AiReport
from llm.prompts import REPORT_PROMPT_SHA256, REPORT_PROMPT_VERSION
from llm.service import LLMService
from tests.test_service import (
    FakeClient,
    PlanDraft,
    api_graph,
    relationship_draft,
    target_profile,
)


class FakeBackend:
    def __init__(self):
        self.relationship_analyses = []
        self.scan_plans = []
        self.ai_reports = []
        self.failures = []

    async def publish_relationship_analysis(self, scan_id, artifact):
        self.relationship_analyses.append((scan_id, artifact))

    async def publish_scan_plan(self, scan_id, artifact):
        self.scan_plans.append((scan_id, artifact))

    async def publish_ai_report(self, scan_id, artifact):
        self.ai_reports.append((scan_id, artifact))

    async def report_failure(self, scan_id, stage):
        self.failures.append((scan_id, stage))


class FakeService:
    def __init__(self, analysis, plan, report):
        self.analysis = analysis
        self.plan = plan
        self.report = report
        self.calls = []
        self.fail_relationship = False

    def analyze_relationships(self, target, graph):
        self.calls.append("relationship")
        if self.fail_relationship:
            raise RuntimeError("sensitive upstream detail")
        return self.analysis

    def create_scan_plan(
        self,
        target,
        graph,
        analysis,
        *,
        requests_already_used,
    ):
        self.calls.append("plan")
        return self.plan

    def create_ai_report(self, scan_result):
        self.calls.append("report")
        return self.report


def build_artifacts():
    analysis = LLMService(
        client=FakeClient([relationship_draft()]),
        sleep=lambda _: None,
    ).analyze_relationships(target_profile(), api_graph())
    candidate_ids = [
        candidate.candidate_id for candidate in analysis.test_candidates
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
    return analysis, plan, report


class LLMJobApiTest(unittest.TestCase):
    def setUp(self):
        analysis, plan, report = build_artifacts()
        self.service = FakeService(analysis, plan, report)
        self.backend = FakeBackend()
        self.client = TestClient(
            create_app(
                service=self.service,
                backend=self.backend,
                registry=JobRegistry(),
            )
        )

    def tearDown(self):
        self.client.close()

    def test_three_job_endpoints_return_202_and_publish_callbacks(self):
        relationship_response = self.client.post(
            "/jobs/relationship-analysis",
            json={
                "job_id": "job-rel-001",
                "target_profile": target_profile(),
                "normalized_api_graph": api_graph(),
            },
        )
        plan_response = self.client.post(
            "/jobs/scan-plan",
            json={
                "job_id": "job-plan-001",
                "target_profile": target_profile(),
                "normalized_api_graph": api_graph(),
                "relationship_analysis": self.service.analysis.model_dump(
                    mode="json"
                ),
                "requests_already_used": 12,
            },
        )
        report_response = self.client.post(
            "/jobs/ai-report",
            json={
                "job_id": "job-report-001",
                "scan_result": {
                    "schema_version": "1.2",
                    "scan_id": "scan-001",
                    "findings": [],
                },
            },
        )

        self.assertEqual(202, relationship_response.status_code)
        self.assertEqual(202, plan_response.status_code)
        self.assertEqual(202, report_response.status_code)
        self.assertEqual(1, len(self.backend.relationship_analyses))
        self.assertEqual(1, len(self.backend.scan_plans))
        self.assertEqual(1, len(self.backend.ai_reports))

    def test_same_job_id_is_executed_only_once(self):
        body = {
            "job_id": "job-rel-idempotent",
            "target_profile": target_profile(),
            "normalized_api_graph": api_graph(),
        }

        first = self.client.post("/jobs/relationship-analysis", json=body)
        second = self.client.post("/jobs/relationship-analysis", json=body)

        self.assertEqual(202, first.status_code)
        self.assertFalse(first.json()["duplicate"])
        self.assertEqual(202, second.status_code)
        self.assertTrue(second.json()["duplicate"])
        self.assertEqual(["relationship"], self.service.calls)
        self.assertEqual(1, len(self.backend.relationship_analyses))

    def test_failure_uses_fixed_stage_callback(self):
        self.service.fail_relationship = True

        response = self.client.post(
            "/jobs/relationship-analysis",
            json={
                "job_id": "job-rel-failure",
                "target_profile": target_profile(),
                "normalized_api_graph": api_graph(),
            },
        )

        self.assertEqual(202, response.status_code)
        self.assertEqual(
            [("scan-001", "RELATIONSHIP_ANALYSIS")],
            self.backend.failures,
        )


if __name__ == "__main__":
    unittest.main()
