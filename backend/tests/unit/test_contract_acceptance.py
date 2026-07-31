import json
import re
from pathlib import Path

import pytest
from pydantic import ValidationError

from app.schemas.contracts.ai_report import AIReport
from app.schemas.contracts.evidence import EvidenceArtifact
from app.schemas.contracts.normalized_api_graph import NormalizedAPIGraph
from app.schemas.contracts.relationship_analysis import RelationshipAnalysis
from app.schemas.contracts.scan_plan import ScanPlan
from app.schemas.contracts.scan_result import ScanResult
from app.schemas.contracts.target_profile import TargetProfile

CONTRACT_DOCUMENT = (
    Path(__file__).resolve().parents[3] / "docs" / "최종 JSON 데이터 계약.md"
)
MODEL_BY_NAME = {
    "target_profile": TargetProfile,
    "normalized_api_graph": NormalizedAPIGraph,
    "relationship_analysis": RelationshipAnalysis,
    "scan_plan": ScanPlan,
    "scan_result": ScanResult,
    "ai_report": AIReport,
}
PLACEHOLDERS = {
    "<scan_id>": "scan-contract-001",
    "<base_url>": "https://scanner.example.test",
    "<path_pattern>": "/api/*",
    "<USER_A_USERNAME_ENV>": "USER_A_USERNAME",
    "<USER_A_PASSWORD_ENV>": "USER_A_PASSWORD",
    "<USER_B_USERNAME_ENV>": "USER_B_USERNAME",
    "<USER_B_PASSWORD_ENV>": "USER_B_PASSWORD",
    "<HTTP_METHOD>": "GET",
    "<path_template>": "/api/accounts/{account_id}",
    "<path|query|header|body>": "path",
    "<input_field_path>": "account_id",
    "<string|integer|number|boolean|object|array|unknown>": "string",
    "<response_json_path>": "items[].account_id",
    "<finding_id>": "finding-contract-001",
    "<operation_id>": "GET:/api/accounts/{account_id}",
    "<vulnerability_type>": "BOLA",
    "<rule_id>": "VERIFY-BOLA-001",
    "<rule_condition_code>": "BOLA_FOREIGN_OBJECT_RETURNED",
    "<request|response>": "response",
    "<field_path>": "balance",
    "<identity|account|financial|authentication|transaction|other>": "financial",
    "<redacted_evidence_artifact_reference>": "artifact:evidence-contract-001",
}


def _example(name: str) -> dict[str, object]:
    document = CONTRACT_DOCUMENT.read_text(encoding="utf-8")
    heading = re.search(
        rf"^## `{re.escape(name)}\.json`[ \t]*$",
        document,
        re.MULTILINE,
    )
    assert heading is not None
    section = document[heading.end() :]
    next_heading = re.search(r"^## ", section, re.MULTILINE)
    if next_heading:
        section = section[: next_heading.start()]
    fence = re.search(
        r"^```json[ \t]*\r?\n(?P<payload>.*?)^```[ \t]*$",
        section,
        re.MULTILINE | re.DOTALL,
    )
    assert fence is not None
    payload = json.loads(fence.group("payload"))

    def replace(value):
        if isinstance(value, dict):
            return {key: replace(item) for key, item in value.items()}
        if isinstance(value, list):
            return [replace(item) for item in value]
        if not isinstance(value, str):
            return value
        return re.sub(r"<[^>]+>", lambda match: PLACEHOLDERS[match.group(0)], value)

    return replace(payload)


@pytest.mark.parametrize("name", MODEL_BY_NAME)
def test_all_six_final_document_examples_validate(name: str) -> None:
    MODEL_BY_NAME[name].model_validate(_example(name))


@pytest.mark.parametrize("name", MODEL_BY_NAME)
def test_artifact_contracts_forbid_unknown_fields(name: str) -> None:
    payload = _example(name)
    payload["unexpected"] = True
    with pytest.raises(ValidationError):
        MODEL_BY_NAME[name].model_validate(payload)


def test_nullable_call_order_and_parameter_binding_match_llm_output() -> None:
    relationship = _example("relationship_analysis")
    relationship["relationships"] = [
        {
            "relationship_id": "rel-call-order",
            "source_operation_id": "GET:/api/accounts",
            "target_operation_id": "GET:/api/accounts/{account_id}",
            "source_field": None,
            "target_parameter": None,
            "target_parameter_location": None,
            "relationship_type": "call_order",
            "confidence": 0.9,
        }
    ]
    RelationshipAnalysis.model_validate(relationship)

    plan = _example("scan_plan")
    plan["steps"][0]["input_bindings"] = [
        {
            "parameter": "page",
            "location": "query",
            "binding_type": "parameter_binding",
            "object_type": None,
            "owner": None,
        }
    ]
    parsed = ScanPlan.model_validate(plan)
    assert parsed.steps[0].input_bindings[0].owner is None


def _evidence() -> dict[str, object]:
    return {
        "scan_id": "scan-001",
        "operation_id": "GET:/api/accounts/{account_id}",
        "module_id": "BOLA-001",
        "rule_id": "VERIFY-BOLA-001",
        "verified_conditions": ["BOLA_FOREIGN_OBJECT_RETURNED"],
        "affected_fields": [
            {
                "location": "response",
                "field_path": "account.balance",
                "data_class": "financial",
            }
        ],
        "baseline": {
            "actor_id": "user_a",
            "status_code": 200,
            "observed_field_paths": ["account.balance"],
        },
        "variant": {
            "actor_id": "user_b",
            "status_code": 200,
            "response_structure_sha256": "a" * 64,
        },
    }


@pytest.mark.parametrize(
    "forbidden_field",
    ["token", "cookie", "password", "object_id", "raw_response"],
)
def test_evidence_allowlist_rejects_secrets_ids_and_raw_responses(
    forbidden_field: str,
) -> None:
    payload = _evidence()
    payload[forbidden_field] = "must-never-be-stored"
    with pytest.raises(ValidationError):
        EvidenceArtifact.model_validate(payload)
