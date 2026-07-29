import hashlib
import unittest
from types import SimpleNamespace

from llm.contracts import (
    PlanDraft,
    RelationshipDraft,
    RelationshipDraftItem,
    ReportDraft,
    ReportFindingDraft,
)
from llm.errors import LLMError
from llm.prompts import (
    PLAN_PROMPT,
    PLAN_PROMPT_SHA256,
    RELATIONSHIP_PROMPT,
    RELATIONSHIP_PROMPT_SHA256,
    REPORT_PROMPT,
    REPORT_PROMPT_SHA256,
)
from llm.service import LLMService
from scanner.contracts import (
    RelationshipAnalysis as ScannerRelationshipAnalysis,
)
from scanner.contracts import ScanPlan as ScannerScanPlan


def target_profile() -> dict:
    return {
        "schema_version": "1.1",
        "scan_id": "scan-001",
        "target": {
            "base_url": "http://vuln-bank.local",
            "allowed_paths": ["/api/**"],
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


def api_graph() -> dict:
    return {
        "schema_version": "1.1",
        "scan_id": "scan-001",
        "operations": [
            {
                "operation_id": "GET:/api/accounts",
                "method": "GET",
                "path_template": "/api/accounts",
                "inputs": [],
                "outputs": [
                    {"field_path": "items[].account_id", "type": "string"}
                ],
            },
            {
                "operation_id": "GET:/api/accounts/{account_id}",
                "method": "GET",
                "path_template": "/api/accounts/{account_id}",
                "inputs": [
                    {
                        "location": "path",
                        "field_path": "account_id",
                        "type": "string",
                    }
                ],
                "outputs": [
                    {"field_path": "account_id", "type": "string"},
                    {"field_path": "balance", "type": "number"},
                ],
            },
        ],
    }


def relationship_draft(source_field: str = "items[].account_id") -> RelationshipDraft:
    return RelationshipDraft(
        relationships=[
            RelationshipDraftItem(
                source_operation_id="GET:/api/accounts",
                target_operation_id="GET:/api/accounts/{account_id}",
                source_field=source_field,
                target_parameter="account_id",
                target_parameter_location="path",
                relationship_type="id_flow",
                confidence=0.96,
            )
        ]
    )


class FakeResponses:
    def __init__(self, outputs: list):
        self.outputs = list(outputs)
        self.calls = []

    def parse(self, **kwargs):
        self.calls.append(kwargs)
        return SimpleNamespace(output_parsed=self.outputs.pop(0))


class FakeClient:
    def __init__(self, outputs: list):
        self.responses = FakeResponses(outputs)


class LLMServiceTest(unittest.TestCase):
    def test_relationships_use_fixed_versions_and_skip_authn(self):
        client = FakeClient([relationship_draft()])
        service = LLMService(client=client, sleep=lambda _: None)

        analysis = service.analyze_relationships(target_profile(), api_graph())

        self.assertEqual("1.2", analysis.schema_version)
        self.assertEqual(
            ["BOLA-001", "INPUT-001", "DATA-001"],
            analysis.approved_module_ids,
        )
        self.assertNotIn(
            "AUTHN-001",
            [candidate.module_id for candidate in analysis.test_candidates],
        )
        self.assertEqual("rel-001", analysis.relationships[0].relationship_id)
        self.assertEqual(
            "RelationshipDraft",
            client.responses.calls[0]["text_format"].__name__,
        )
        payload = analysis.model_dump(mode="json")
        ScannerRelationshipAnalysis.model_validate(payload)
        self.assertEqual(
            {
                "schema_version",
                "scan_id",
                "model_name",
                "prompt_version",
                "prompt_sha256",
                "approved_module_ids",
                "relationships",
                "test_candidates",
            },
            set(payload),
        )

    def test_hallucinated_reference_is_retried(self):
        client = FakeClient(
            [relationship_draft("not_in_graph"), relationship_draft()]
        )
        service = LLMService(client=client, sleep=lambda _: None)

        analysis = service.analyze_relationships(target_profile(), api_graph())

        self.assertEqual(2, len(client.responses.calls))
        self.assertEqual(3, len(client.responses.calls[1]["input"]))
        self.assertEqual(1, len(analysis.relationships))

    def test_plan_copies_contract_fields_and_calculates_budget(self):
        analysis_service = LLMService(
            client=FakeClient([relationship_draft()]), sleep=lambda _: None
        )
        analysis = analysis_service.analyze_relationships(
            target_profile(), api_graph()
        )
        ordered = [
            candidate.candidate_id for candidate in analysis.test_candidates
        ]
        plan_service = LLMService(
            client=FakeClient([PlanDraft(ordered_candidate_ids=ordered)]),
            sleep=lambda _: None,
        )

        plan = plan_service.create_scan_plan(
            target_profile(),
            api_graph(),
            analysis,
            requests_already_used=12,
        )

        self.assertEqual("PENDING_APPROVAL", plan.status)
        self.assertEqual(6, plan.budget.estimated_execution_requests)
        self.assertTrue(plan.budget.within_budget)
        self.assertEqual("user_b", plan.steps[0].input_bindings[0].owner)
        input_step = next(
            step for step in plan.steps if step.module_id == "INPUT-001"
        )
        self.assertEqual("user_a", input_step.input_bindings[0].owner)
        data_detail = next(
            step
            for step in plan.steps
            if step.module_id == "DATA-001" and step.input_bindings
        )
        self.assertEqual("user_a", data_detail.input_bindings[0].owner)
        self.assertEqual(
            {
                "schema_version",
                "plan_id",
                "scan_id",
                "model_name",
                "prompt_version",
                "prompt_sha256",
                "status",
                "budget",
                "steps",
            },
            set(plan.model_dump(mode="json")),
        )
        ScannerScanPlan.model_validate(plan.model_dump(mode="json"))

    def test_parameter_binding_keeps_object_type_and_owner_null(self):
        graph = api_graph()
        graph["operations"][0]["inputs"] = [
            {
                "location": "query",
                "field_path": "limit",
                "type": "integer",
            }
        ]
        analysis = LLMService(
            client=FakeClient([relationship_draft()]), sleep=lambda _: None
        ).analyze_relationships(target_profile(), graph)
        ordered = [
            candidate.candidate_id for candidate in analysis.test_candidates
        ]
        plan = LLMService(
            client=FakeClient([PlanDraft(ordered_candidate_ids=ordered)]),
            sleep=lambda _: None,
        ).create_scan_plan(
            target_profile(),
            graph,
            analysis,
            requests_already_used=0,
        )

        parameter_binding = next(
            binding
            for step in plan.steps
            for binding in step.input_bindings
            if binding.parameter == "limit"
            and binding.binding_type == "parameter_binding"
        )
        self.assertIsNone(parameter_binding.object_type)
        self.assertIsNone(parameter_binding.owner)
        ScannerScanPlan.model_validate(plan.model_dump(mode="json"))

    def test_report_adds_severity_and_preserves_evidence_refs(self):
        scan_result = {
            "schema_version": "1.2",
            "scan_id": "scan-001",
            "findings": [
                {
                    "finding_id": "finding-001",
                    "operation_id": "GET:/api/accounts/{account_id}",
                    "vulnerability_type": "BOLA",
                    "verification": {
                        "rule_id": "BOLA-RULE-001",
                        "verified_conditions": ["FOREIGN_OBJECT_RETURNED"],
                    },
                    "affected_fields": [
                        {
                            "location": "response",
                            "field_path": "balance",
                            "data_class": "financial",
                        }
                    ],
                    "evidence_refs": ["evidence:redacted:001"],
                }
            ],
        }
        draft = ReportDraft(
            findings=[
                ReportFindingDraft(
                    finding_id="finding-001",
                    root_cause="객체 소유권 검증이 응답 전에 적용되지 않았습니다.",
                    attack_flow=["다른 사용자 소유 객체 참조", "응답 필드 확인"],
                    impact="다른 사용자의 금융 정보에 접근할 수 있습니다.",
                    recommendation="조회 시 인증 주체와 객체 소유자를 비교합니다.",
                    severity="high",
                )
            ]
        )
        service = LLMService(client=FakeClient([draft]), sleep=lambda _: None)

        report = service.create_ai_report(scan_result)

        self.assertEqual("high", report.overall_risk)
        self.assertEqual(
            ["evidence:redacted:001"], report.findings[0].evidence_refs
        )
        self.assertEqual("high", report.findings[0].severity)
        self.assertEqual(
            {
                "schema_version",
                "scan_id",
                "model_name",
                "prompt_version",
                "prompt_sha256",
                "overall_risk",
                "overall_risk_basis",
                "summary",
                "findings",
            },
            set(report.model_dump(mode="json")),
        )

    def test_plan_rejects_unknown_binding_reference(self):
        analysis_service = LLMService(
            client=FakeClient([relationship_draft()]), sleep=lambda _: None
        )
        analysis = analysis_service.analyze_relationships(
            target_profile(), api_graph()
        ).model_dump(mode="json")
        analysis["test_candidates"][0]["binding_hints"][0][
            "parameter"
        ] = "missing_id"
        service = LLMService(client=FakeClient([]), sleep=lambda _: None)

        with self.assertRaisesRegex(
            LLMError, "LLM_HALLUCINATED_REFERENCE"
        ):
            service.create_scan_plan(
                target_profile(),
                api_graph(),
                analysis,
                requests_already_used=0,
            )

    def test_empty_findings_do_not_call_llm(self):
        client = FakeClient([])
        service = LLMService(client=client, sleep=lambda _: None)

        report = service.create_ai_report(
            {"schema_version": "1.2", "scan_id": "scan-001", "findings": []}
        )

        self.assertEqual([], report.findings)
        self.assertEqual("low", report.overall_risk)
        self.assertEqual([], client.responses.calls)

    def test_empty_findings_work_without_openai_sdk_or_api_key(self):
        report = LLMService().create_ai_report(
            {"schema_version": "1.2", "scan_id": "scan-001", "findings": []}
        )
        self.assertEqual([], report.findings)

    def test_invalid_contract_is_rejected_before_llm_call(self):
        profile = target_profile()
        profile["unexpected"] = True
        client = FakeClient([])
        service = LLMService(client=client, sleep=lambda _: None)

        with self.assertRaisesRegex(LLMError, "LLM_INVALID_INPUT"):
            service.analyze_relationships(profile, api_graph())

        self.assertEqual([], client.responses.calls)

    def test_prompt_hashes_match_prompt_bytes(self):
        pairs = [
            (RELATIONSHIP_PROMPT, RELATIONSHIP_PROMPT_SHA256),
            (PLAN_PROMPT, PLAN_PROMPT_SHA256),
            (REPORT_PROMPT, REPORT_PROMPT_SHA256),
        ]
        for prompt, expected in pairs:
            self.assertEqual(
                expected, hashlib.sha256(prompt.encode("utf-8")).hexdigest()
            )
            self.assertIn("<security-boundary>", prompt)
            self.assertTrue(any("\uac00" <= char <= "\ud7a3" for char in prompt))
        self.assertNotIn("auth_dependency", RELATIONSHIP_PROMPT)


if __name__ == "__main__":
    unittest.main()
