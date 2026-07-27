import hashlib
import json

from scanner.artifacts import ArtifactBuilder, Redactor
from scanner.audit import AuditEvent, InMemoryAuditSink


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


def test_artifact_builder_hashes_redacted_canonical_bytes():
    envelope = ArtifactBuilder(Redactor()).build(
        scan_id="scan-001",
        artifact_type="evidence",
        schema_version=None,
        payload={"token": "token-a", "status": 200},
        sensitive_values={"token-a"},
    )

    assert envelope.sha256 == hashlib.sha256(envelope.content).hexdigest()
    assert envelope.size == len(envelope.content)
    assert b"token-a" not in envelope.content
    assert envelope.content == b'{"status":200,"token":"[REDACTED]"}'


def test_artifact_builder_never_serializes_raw_exception_details():
    envelope = ArtifactBuilder(Redactor()).build(
        scan_id="scan-001",
        artifact_type="evidence",
        schema_version=None,
        payload={"error": ValueError("database response: private-account-42")},
    )

    assert b"private-account-42" not in envelope.content


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
