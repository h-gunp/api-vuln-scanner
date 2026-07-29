"""Conformance tests for the immutable final JSON-contract examples."""

from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import re

from pydantic import ValidationError
import pytest

from scanner.contracts import (
    NormalizedApiGraph,
    RelationshipAnalysis,
    ScanPlan,
    ScanResult,
    TargetProfile,
)


CONTRACT_DOCUMENT = (
    Path(__file__).resolve().parents[1] / "docs" / "최종 JSON 데이터 계약.md"
)
EXAMPLE_NAMES = (
    "target_profile",
    "normalized_api_graph",
    "relationship_analysis",
    "scan_plan",
    "scan_result",
)
PLACEHOLDER_VALUES = {
    "<scan_id>": "scan-contract-001",
    "<base_url>": "https://scanner.example.test",
    "<path_pattern>": "/api/*",
    "<USER_A_USERNAME_ENV>": "SCANNER_USER_A_USERNAME",
    "<USER_A_PASSWORD_ENV>": "SCANNER_USER_A_PASSWORD",
    "<USER_B_USERNAME_ENV>": "SCANNER_USER_B_USERNAME",
    "<USER_B_PASSWORD_ENV>": "SCANNER_USER_B_PASSWORD",
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
    "<redacted_evidence_artifact_reference>": "artifacts/evidence-contract-001",
}
MODEL_BY_EXAMPLE = {
    "target_profile": TargetProfile,
    "normalized_api_graph": NormalizedApiGraph,
    "relationship_analysis": RelationshipAnalysis,
    "scan_plan": ScanPlan,
    "scan_result": ScanResult,
}


def _load_contract_examples() -> dict[str, dict[str, object]]:
    try:
        document = CONTRACT_DOCUMENT.read_text(encoding="utf-8")
    except FileNotFoundError as error:
        raise AssertionError(
            f"canonical JSON contract document is missing: {CONTRACT_DOCUMENT}"
        ) from error

    return {
        example_name: _replace_placeholders(
            _extract_fenced_json_example(document, example_name)
        )
        for example_name in EXAMPLE_NAMES
    }


def _extract_fenced_json_example(document: str, example_name: str) -> dict[str, object]:
    heading = re.compile(
        rf"^## `{re.escape(example_name)}\.json`[ \t]*$", re.MULTILINE
    )
    heading_match = heading.search(document)
    if heading_match is None:
        raise AssertionError(f"missing named heading for {example_name}.json")

    section = document[heading_match.end() :]
    next_heading = re.search(r"^## ", section, re.MULTILINE)
    if next_heading is not None:
        section = section[: next_heading.start()]

    fence = re.search(
        r"^```json[ \t]*\r?\n(?P<payload>.*?)^```[ \t]*$",
        section,
        re.MULTILINE | re.DOTALL,
    )
    if fence is None:
        raise AssertionError(f"missing JSON fence under {example_name}.json")

    try:
        payload = json.loads(fence.group("payload"))
    except json.JSONDecodeError as error:
        raise AssertionError(
            f"invalid JSON in {example_name}.json example: {error.msg}"
        ) from error
    if not isinstance(payload, dict):
        raise AssertionError(f"{example_name}.json example must contain a JSON object")
    return payload


def _replace_placeholders(value: object) -> object:
    if isinstance(value, dict):
        return {key: _replace_placeholders(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_replace_placeholders(item) for item in value]
    if not isinstance(value, str):
        return value

    def replacement(match: re.Match[str]) -> str:
        placeholder = match.group(0)
        if placeholder not in PLACEHOLDER_VALUES:
            raise AssertionError(
                f"no concrete fixture value is defined for {placeholder}"
            )
        return PLACEHOLDER_VALUES[placeholder]

    return re.sub(r"<[^>]+>", replacement, value)


@pytest.mark.parametrize("example_name", EXAMPLE_NAMES)
def test_final_json_contract_examples_validate_against_scanner_models(
    example_name: str,
) -> None:
    examples = _load_contract_examples()

    MODEL_BY_EXAMPLE[example_name].model_validate(examples[example_name])


def test_relationship_analysis_keeps_authn_approved_but_rejects_authn_candidate() -> None:
    analysis_payload = _load_contract_examples()["relationship_analysis"]
    assert analysis_payload["approved_module_ids"] == [
        "BOLA-001",
        "AUTHN-001",
        "INPUT-001",
        "DATA-001",
    ]

    analysis = RelationshipAnalysis.model_validate(analysis_payload)
    assert analysis.approved_module_ids[1] == "AUTHN-001"

    invalid_payload = deepcopy(analysis_payload)
    invalid_payload["test_candidates"][0]["module_id"] = "AUTHN-001"  # type: ignore[index]
    with pytest.raises(ValidationError):
        RelationshipAnalysis.model_validate(invalid_payload)


def test_scan_plan_rejects_authn_step_even_when_documented_example_is_valid() -> None:
    plan_payload = _load_contract_examples()["scan_plan"]
    ScanPlan.model_validate(plan_payload)

    invalid_payload = deepcopy(plan_payload)
    invalid_payload["steps"][0]["module_id"] = "AUTHN-001"  # type: ignore[index]
    with pytest.raises(ValidationError):
        ScanPlan.model_validate(invalid_payload)
