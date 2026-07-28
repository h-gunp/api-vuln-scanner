import hashlib
import json

import pytest

from scanner.artifacts import ArtifactBuilder, Redactor
from scanner.audit import AuditEvent, InMemoryAuditSink


def _reject_duplicate_json_keys(pairs):
    keys = [key for key, _ in pairs]
    assert len(keys) == len(set(keys))
    return dict(pairs)


def test_redactor_removes_secret_keys_runtime_values_and_url_query_secrets():
    raw = {
        "headers": {"Authorization": "Bearer token-a", "Cookie": "sid=cookie-a"},
        "request": {"password": "pw-a", "account_id": "acct-b-1"},
        "url": "http://vuln-bank.local/api/a?token=token-a",
    }

    cleaned = Redactor().redact(
        raw,
        sensitive_values={"token-a", "cookie-a", "pw-a", "acct-b-1"},
    )

    rendered = json.dumps(cleaned)
    for secret in ("token-a", "cookie-a", "pw-a", "acct-b-1"):
        assert secret not in rendered


def test_redactor_removes_values_from_sequences_strings_and_exception_details():
    raw = {
        "items": ["token-a", {"message": "request failed: token-a"}],
        "error": ValueError("unexpected token-a"),
    }

    cleaned = Redactor().redact(raw, sensitive_values={"token-a"})

    assert "token-a" not in json.dumps(cleaned)


def test_redactor_removes_non_string_runtime_values_and_relative_query_secrets():
    cleaned = Redactor().redact(
        {
            "observed_parameter": 42,
            "request_target": "/api/a?token=token-a",
            "status": 200,
        },
        sensitive_values={42},
    )

    rendered = json.dumps(cleaned)
    assert "42" not in rendered
    assert "token-a" not in rendered
    assert cleaned["observed_parameter"] == "[REDACTED]"
    assert cleaned["status"] == 200


def test_redactor_removes_sensitive_numeric_and_string_mapping_keys():
    cleaned = Redactor().redact(
        {42: "safe-label", "token-a": "safe-label"},
        sensitive_values={42, "token-a"},
    )

    rendered = json.dumps(cleaned)
    assert "42" not in rendered
    assert "token-a" not in rendered


def test_artifact_builder_hashes_redacted_canonical_bytes():
    envelope = ArtifactBuilder(Redactor()).build(
        scan_id="scan-001",
        artifact_type="diagnostic",
        schema_version=None,
        payload={"token": "token-a", "status": 200},
        sensitive_values={"token-a"},
    )

    assert envelope.sha256 == hashlib.sha256(envelope.content).hexdigest()
    assert envelope.size == len(envelope.content)
    assert b"token-a" not in envelope.content
    assert envelope.content == b'{"[REDACTED]":"[REDACTED]","status":200}'


def test_artifact_builder_preserves_typed_evidence_without_runtime_values():
    payload = {
        "scan_id": "scan-001",
        "operation_id": "GET:/api/profile",
        "module_id": "DATA-001",
        "rule_id": "VERIFY-DATA-001",
        "verified_conditions": ["DATA_SENSITIVE_FIELD_UNMASKED"],
        "affected_fields": [
            {
                "location": "response",
                "field_path": "profile.password",
                "data_class": "authentication",
            }
        ],
        "baseline": {
            "actor_id": "user_a",
            "status_code": 200,
            "response_structure_sha256": "a" * 64,
            "observed_field_paths": ["profile.password"],
        },
        "variant": {
            "actor_id": "user_a",
            "status_code": 200,
            "response_structure_sha256": "a" * 64,
            "observed_field_paths": ["profile.password"],
        },
    }

    envelope = ArtifactBuilder(Redactor()).build(
        scan_id="scan-001",
        artifact_type="evidence",
        schema_version=None,
        payload=payload,
        sensitive_values={"runtime-token-a", "private-account-42"},
    )

    decoded = json.loads(
        envelope.content,
        object_pairs_hook=_reject_duplicate_json_keys,
    )
    assert decoded == payload
    assert b"runtime-token-a" not in envelope.content
    assert b"private-account-42" not in envelope.content
    assert b"[REDACTED]" not in envelope.content


def test_artifact_builder_rejects_sensitive_values_inside_evidence_metadata():
    payload = {
        "scan_id": "scan-001",
        "operation_id": "GET:/api/runtime-token-a",
        "module_id": "DATA-001",
        "rule_id": "VERIFY-DATA-001",
        "verified_conditions": ["DATA_SENSITIVE_FIELD_UNMASKED"],
        "affected_fields": [
            {
                "location": "response",
                "field_path": "profile.password",
                "data_class": "authentication",
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
            "response_structure_sha256": "a" * 64,
            "observed_field_paths": [],
        },
    }

    with pytest.raises(ValueError, match="invalid evidence artifact payload"):
        ArtifactBuilder(Redactor()).build(
            scan_id="scan-001",
            artifact_type="evidence",
            schema_version=None,
            payload=payload,
            sensitive_values={"runtime-token-a"},
        )


def test_artifact_builder_only_exact_matches_short_evidence_secrets():
    payload = {
        "scan_id": "scan-001",
        "operation_id": "GET:/api/profile",
        "module_id": "DATA-001",
        "rule_id": "VERIFY-DATA-001",
        "verified_conditions": ["DATA_SENSITIVE_FIELD_UNMASKED"],
        "affected_fields": [
            {
                "location": "response",
                "field_path": "profile.password",
                "data_class": "authentication",
            }
        ],
        "baseline": {
            "actor_id": "user_a",
            "status_code": 200,
            "response_structure_sha256": "1" * 64,
            "observed_field_paths": ["profile.password"],
        },
        "variant": {
            "actor_id": "user_a",
            "status_code": 200,
            "response_structure_sha256": "1" * 64,
            "observed_field_paths": ["profile.password"],
        },
    }

    envelope = ArtifactBuilder(Redactor()).build(
        scan_id="scan-001",
        artifact_type="evidence",
        schema_version=None,
        payload=payload,
        sensitive_values={"1"},
    )

    assert json.loads(envelope.content) == payload

    exact_match = {**payload, "scan_id": "pw"}
    with pytest.raises(ValueError, match="invalid evidence artifact payload"):
        ArtifactBuilder(Redactor()).build(
            scan_id="pw",
            artifact_type="evidence",
            schema_version=None,
            payload=exact_match,
            sensitive_values={"pw"},
        )


def test_artifact_builder_never_serializes_raw_exception_details():
    envelope = ArtifactBuilder(Redactor()).build(
        scan_id="scan-001",
        artifact_type="diagnostic",
        schema_version=None,
        payload={"error": ValueError("database response: private-account-42")},
    )

    assert b"private-account-42" not in envelope.content


def test_artifact_builder_never_serializes_raw_response_text_by_default():
    envelope = ArtifactBuilder(Redactor()).build(
        scan_id="scan-001",
        artifact_type="diagnostic",
        schema_version=None,
        payload={"response": "private-account-42", "status": 200},
    )

    assert b"private-account-42" not in envelope.content
    assert envelope.content == b'{"[REDACTED]":"[REDACTED]","status":200}'


def test_artifact_builder_never_serializes_arbitrary_evidence_text_by_default():
    envelope = ArtifactBuilder(Redactor()).build(
        scan_id="scan-001",
        artifact_type="diagnostic",
        schema_version=None,
        payload={"note": "private-account-42", "status": 200},
    )

    assert b"private-account-42" not in envelope.content
    assert envelope.content == b'{"[REDACTED]":"[REDACTED]","status":200}'


def test_artifact_builder_never_serializes_arbitrary_evidence_mapping_keys():
    envelope = ArtifactBuilder(Redactor()).build(
        scan_id="scan-001",
        artifact_type="diagnostic",
        schema_version=None,
        payload={"private-account-42": "safe", "status": 200},
    )

    assert b"private-account-42" not in envelope.content
    assert envelope.content == b'{"[REDACTED]":"[REDACTED]","status":200}'


def test_artifact_builder_preserves_normalized_graph_structural_text():
    envelope = ArtifactBuilder(Redactor()).build(
        scan_id="scan-001",
        artifact_type="normalized_api_graph",
        schema_version="1.1",
        payload={
            "schema_version": "1.1",
            "scan_id": "scan-001",
            "operations": [
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
                    "outputs": [{"field_path": "balance", "type": "number"}],
                }
            ],
        },
    )

    assert b"GET:/api/accounts/{account_id}" in envelope.content
    assert b"/api/accounts/{account_id}" in envelope.content


def test_artifact_builder_preserves_scan_result_structural_text():
    envelope = ArtifactBuilder(Redactor()).build(
        scan_id="scan-001",
        artifact_type="scan_result",
        schema_version="1.2",
        payload={
            "schema_version": "1.2",
            "scan_id": "scan-001",
            "findings": [
                {
                    "finding_id": "finding-001",
                    "operation_id": "GET:/api/accounts/{account_id}",
                    "vulnerability_type": "BOLA",
                    "verification": {
                        "rule_id": "BOLA-001",
                        "verified_conditions": ["ownership mismatch"],
                    },
                    "affected_fields": [
                        {
                            "location": "response",
                            "field_path": "account_id",
                            "data_class": "account",
                        }
                    ],
                    "evidence_refs": ["artifact:1"],
                }
            ],
        },
    )

    assert b"BOLA-001" in envelope.content
    assert b"account_id" in envelope.content


@pytest.mark.parametrize(
    ("artifact_type", "schema_version", "payload"),
    [
        (
            "normalized_api_graph",
            "1.1",
            {"schema_version": "1.1", "scan_id": "scan-001", "operations": [], "raw": "secret-a"},
        ),
        (
            "scan_result",
            "1.2",
            {"schema_version": "1.2", "scan_id": "scan-001", "findings": [], "raw": "secret-a"},
        ),
    ],
)
def test_artifact_builder_rejects_extra_fields_in_structural_artifacts(
    artifact_type, schema_version, payload
):
    with pytest.raises(ValueError, match="invalid structural artifact payload") as error:
        ArtifactBuilder(Redactor()).build(
            scan_id="scan-001",
            artifact_type=artifact_type,
            schema_version=schema_version,
            payload=payload,
        )

    assert "secret-a" not in str(error.value)


def test_in_memory_audit_sink_stores_redacted_event_details():
    sink = InMemoryAuditSink()

    sink.emit(
        AuditEvent(
            code="AUTH_FAILED",
            level="WARNING",
            job_id="job-001",
            scan_id="scan-001",
            operation_id=None,
            module_id=None,
            details={"authorization": "Bearer token-a"},
        )
    )

    assert sink.events[-1].details == {"authorization": "[REDACTED]"}


def test_in_memory_audit_sink_never_stores_raw_exception_or_response_details():
    sink = InMemoryAuditSink()

    sink.emit(
        AuditEvent(
            code="REQUEST_FAILED",
            level="WARNING",
            job_id="job-001",
            scan_id="scan-001",
            operation_id=None,
            module_id=None,
            details={
                "error": ValueError("response body: private-account-42"),
                "response": "private-account-42",
                "status": 502,
            },
        )
    )

    rendered = json.dumps(sink.events[-1].details)
    assert "private-account-42" not in rendered
    assert sink.events[-1].details["status"] == 502


def test_in_memory_audit_sink_removes_numeric_runtime_values_but_keeps_counts():
    sink = InMemoryAuditSink()

    sink.emit(
        AuditEvent(
            code="DISCOVERY_PROGRESS",
            level="INFO",
            job_id="job-001",
            scan_id="scan-001",
            operation_id=None,
            module_id=None,
            details={"object_id": 42, "operations": 3, "status": 200},
        )
    )

    assert sink.events[-1].details["object_id"] == "[REDACTED]"
    assert sink.events[-1].details["operations"] == 3
    assert sink.events[-1].details["status"] == 200


def test_in_memory_audit_sink_removes_non_string_runtime_mapping_keys():
    sink = InMemoryAuditSink()

    sink.emit(
        AuditEvent(
            code="DISCOVERY_PROGRESS",
            level="INFO",
            job_id="job-001",
            scan_id="scan-001",
            operation_id=None,
            module_id=None,
            details={42: "private-account-42", "status": 200},
        )
    )

    assert "42" not in json.dumps(sink.events[-1].details)
