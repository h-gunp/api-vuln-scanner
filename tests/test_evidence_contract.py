from __future__ import annotations

import pytest
from pydantic import ValidationError

import scanner.contracts as contracts


def _evidence_type():
    model = getattr(contracts, "EvidenceArtifact", None)
    assert model is not None, "EvidenceArtifact contract is not implemented"
    return model


def _valid_payload() -> dict[str, object]:
    return {
        "scan_id": "scan-001",
        "operation_id": "GET:/api/accounts/{account_id}",
        "module_id": "BOLA-001",
        "rule_id": "VERIFY-BOLA-001",
        "verified_conditions": ["BOLA_FOREIGN_OBJECT_RETURNED"],
        "affected_fields": [
            {
                "location": "response",
                "field_path": "items[].account_id",
                "data_class": "account",
            }
        ],
        "baseline": {
            "actor_id": "user_a",
            "status_code": 200,
            "response_structure_sha256": "a" * 64,
            "observed_field_paths": [],
        },
        "variant": {
            "actor_id": "user_a",
            "status_code": 200,
            "response_structure_sha256": None,
            "observed_field_paths": ["items[].account_id"],
        },
    }


def test_evidence_artifact_preserves_auditable_semantic_metadata() -> None:
    artifact = _evidence_type().model_validate(_valid_payload())

    assert artifact.model_dump(mode="json") == _valid_payload()


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("raw_response_body", {"account_id": "private-account-42"}),
        ("response_value", "private-account-42"),
        ("credentials", {"authorization": "Bearer runtime-token-a"}),
        ("object_id", "private-account-42"),
        (
            "concrete_query_url",
            "https://scanner.test/api/accounts?account_id=private-account-42",
        ),
        ("unknown_field", "unsafe"),
    ],
)
def test_evidence_artifact_rejects_non_allowlisted_runtime_fields(
    field: str, value: object
) -> None:
    payload = _valid_payload()
    payload[field] = value

    with pytest.raises(ValidationError):
        _evidence_type().model_validate(payload)


@pytest.mark.parametrize("actor_id", ["admin", "attacker", "user_c"])
def test_evidence_observation_rejects_unknown_actor_ids(actor_id: str) -> None:
    payload = _valid_payload()
    payload["baseline"] = {
        **payload["baseline"],  # type: ignore[dict-item]
        "actor_id": actor_id,
    }

    with pytest.raises(ValidationError):
        _evidence_type().model_validate(payload)


@pytest.mark.parametrize("status_code", [99, 600, "200", True])
def test_evidence_observation_rejects_non_http_or_untyped_status_codes(
    status_code: object,
) -> None:
    payload = _valid_payload()
    payload["baseline"] = {
        **payload["baseline"],  # type: ignore[dict-item]
        "status_code": status_code,
    }

    with pytest.raises(ValidationError):
        _evidence_type().model_validate(payload)


@pytest.mark.parametrize(
    "structure_hash",
    ["A" * 64, "a" * 63, "a" * 65, "not-a-sha256"],
)
def test_evidence_observation_rejects_noncanonical_sha256(
    structure_hash: str,
) -> None:
    payload = _valid_payload()
    payload["baseline"] = {
        **payload["baseline"],  # type: ignore[dict-item]
        "response_structure_sha256": structure_hash,
    }

    with pytest.raises(ValidationError):
        _evidence_type().model_validate(payload)


@pytest.mark.parametrize(
    "field_path",
    [
        "items[0].account_id",
        "account_id=private-account-42",
        "https://scanner.test/api/accounts?account_id=42",
        "/api/accounts?account_id=42",
        "items[].account id",
    ],
)
def test_evidence_observation_rejects_urls_queries_indexes_and_values(
    field_path: str,
) -> None:
    payload = _valid_payload()
    payload["variant"] = {
        **payload["variant"],  # type: ignore[dict-item]
        "observed_field_paths": [field_path],
    }

    with pytest.raises(ValidationError):
        _evidence_type().model_validate(payload)


def test_evidence_observation_requires_a_structure_hash_or_field_path() -> None:
    payload = _valid_payload()
    payload["baseline"] = {
        **payload["baseline"],  # type: ignore[dict-item]
        "response_structure_sha256": None,
        "observed_field_paths": [],
    }

    with pytest.raises(ValidationError):
        _evidence_type().model_validate(payload)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("rule_id", "VERIFY-INPUT-001"),
        ("verified_conditions", ["INPUT_INVALID_VALUE_EXPANDED_SCOPE"]),
    ],
)
def test_evidence_artifact_rejects_rule_metadata_from_a_different_module(
    field: str,
    value: object,
) -> None:
    payload = _valid_payload()
    payload[field] = value

    with pytest.raises(ValidationError):
        _evidence_type().model_validate(payload)
