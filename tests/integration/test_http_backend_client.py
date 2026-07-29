from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Callable

import httpx
import pytest

from scanner.artifacts import ArtifactEnvelope
from scanner.contracts import ApprovalStatus, PlanApprovalDecision
from scanner.integration.backend_client import (
    BackendIntegrationError,
    BackendSettings,
    HttpBackendClient,
    JobKind,
    ScannerErrorReport,
    ScannerStage,
)


BASE_URL = "https://backend.internal"
TOKEN = "internal-token-secret"
SCAN_ID = "scan-001"
JOB_ID = "job-001"


def _settings(
    *,
    auth_enabled: bool = False,
    token: str | None = None,
    timeout: float = 7.5,
) -> BackendSettings:
    return BackendSettings(
        base_url=BASE_URL,
        internal_auth_enabled=auth_enabled,
        internal_service_token=token,
        timeout_seconds=timeout,
    )


def _client(
    handler: Callable[[httpx.Request], httpx.Response],
    *,
    settings: BackendSettings | None = None,
) -> HttpBackendClient:
    transport = httpx.MockTransport(handler)
    return HttpBackendClient(
        settings or _settings(),
        client=httpx.Client(transport=transport),
    )


def _artifact(
    artifact_type: str,
    payload: dict[str, object],
) -> ArtifactEnvelope:
    content = json.dumps(payload, separators=(",", ":")).encode()
    return ArtifactEnvelope(
        scan_id=SCAN_ID,
        artifact_type=artifact_type,
        schema_version="1.1" if artifact_type != "evidence" else None,
        content=content,
        sha256=hashlib.sha256(content).hexdigest(),
        size=len(content),
    )


def _artifact_response(artifact_id: str = "stored_123") -> dict[str, object]:
    return {
        "status": "SUCCESS",
        "message": None,
        "details": {"artifact_id": artifact_id},
    }


def _assert_safe(error: BaseException, *secret_values: str) -> None:
    rendered = f"{error!s} {error!r}"
    for secret in secret_values:
        assert secret not in rendered


def test_backend_settings_parse_defaults_and_environment() -> None:
    defaults = BackendSettings.from_env({})

    assert defaults.base_url == "http://backend:8000"
    assert defaults.internal_auth_enabled is False
    assert defaults.internal_service_token is None
    assert defaults.timeout_seconds == 10.0

    configured = BackendSettings.from_env(
        {
            "BACKEND_BASE_URL": "https://api.internal/base/",
            "INTERNAL_AUTH_ENABLED": "true",
            "INTERNAL_SERVICE_TOKEN": TOKEN,
            "BACKEND_TIMEOUT_SECONDS": "2.25",
        }
    )

    assert configured.base_url == "https://api.internal/base"
    assert configured.internal_auth_enabled is True
    assert configured.internal_service_token == TOKEN
    assert configured.timeout_seconds == 2.25
    assert TOKEN not in repr(configured)


@pytest.mark.parametrize("timeout", [0.0, -1.0, math.inf, -math.inf, math.nan])
def test_backend_settings_reject_non_positive_or_non_finite_timeout(
    timeout: float,
) -> None:
    with pytest.raises(
        BackendIntegrationError,
        match="^backend client configuration is invalid$",
    ):
        _settings(timeout=timeout)


def test_backend_settings_reject_auth_without_token() -> None:
    with pytest.raises(
        BackendIntegrationError,
        match="^backend client configuration is invalid$",
    ):
        _settings(auth_enabled=True)


@pytest.mark.parametrize(
    "settings",
    [
        {
            "base_url": "https://backend.internal:not-a-port",
            "internal_auth_enabled": False,
        },
        {
            "base_url": BASE_URL,
            "internal_auth_enabled": "false",
            "internal_service_token": TOKEN,
        },
    ],
)
def test_backend_settings_reject_malformed_url_or_non_boolean_auth_flag(
    settings: dict[str, object],
) -> None:
    with pytest.raises(
        BackendIntegrationError,
        match="^backend client configuration is invalid$",
    ):
        BackendSettings(**settings)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("job_kind", "stage", "backend_stage"),
    [
        (JobKind.DISCOVERY, ScannerStage.PROFILE_LOADING, "API_DISCOVERY"),
        (JobKind.DISCOVERY, ScannerStage.AUTHENTICATING, "API_DISCOVERY"),
        (JobKind.DISCOVERY, ScannerStage.DISCOVERING, "API_DISCOVERY"),
        (JobKind.DISCOVERY, ScannerStage.OBJECT_DISCOVERY, "API_DISCOVERY"),
        (JobKind.DISCOVERY, ScannerStage.NORMALIZING, "API_NORMALIZATION"),
        (JobKind.DISCOVERY, ScannerStage.COMPLETED, "API_NORMALIZATION"),
        (JobKind.EXECUTION, ScannerStage.PROFILE_LOADING, "PLAN_VALIDATION"),
        (JobKind.EXECUTION, ScannerStage.AUTHENTICATING, "PLAN_VALIDATION"),
        (JobKind.EXECUTION, ScannerStage.POLICY_VALIDATION, "PLAN_VALIDATION"),
        (JobKind.EXECUTION, ScannerStage.EXECUTING, "MODULE_EXECUTION"),
        (JobKind.EXECUTION, ScannerStage.VERIFYING, "RESULT_VALIDATION"),
        (JobKind.EXECUTION, ScannerStage.COMPLETED, "RESULT_VALIDATION"),
    ],
)
def test_progress_maps_every_scanner_stage_and_clamps_completion(
    job_kind: JobKind,
    stage: ScannerStage,
    backend_stage: str,
) -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(204)

    client = _client(handler)
    client.report_progress(
        JOB_ID,
        stage,
        100,
        {"requests_used": 4},
        scan_id=SCAN_ID,
        job_kind=job_kind,
    )

    expected_path = (
        f"/internal/scans/{SCAN_ID}/progress"
        if job_kind is JobKind.DISCOVERY
        else f"/internal/scans/{SCAN_ID}/execution-progress"
    )
    assert len(requests) == 1
    assert requests[0].method == "POST"
    assert requests[0].url.path == expected_path
    assert json.loads(requests[0].content) == {
        "stage": backend_stage,
        "progress": 99,
        "message": None,
        "metrics": {"requests_used": 4},
    }


def test_authorization_header_is_present_only_when_enabled() -> None:
    authorization_values: list[str | None] = []

    def handler(request: httpx.Request) -> httpx.Response:
        authorization_values.append(request.headers.get("Authorization"))
        return httpx.Response(204)

    _client(handler).report_progress(
        JOB_ID,
        ScannerStage.DISCOVERING,
        10,
        {},
        scan_id=SCAN_ID,
        job_kind=JobKind.DISCOVERY,
    )
    _client(
        handler,
        settings=_settings(auth_enabled=True, token=TOKEN),
    ).report_progress(
        JOB_ID,
        ScannerStage.DISCOVERING,
        10,
        {},
        scan_id=SCAN_ID,
        job_kind=JobKind.DISCOVERY,
    )

    assert authorization_values == [None, f"Bearer {TOKEN}"]


@pytest.mark.parametrize(
    ("job_kind", "expected_path"),
    [
        (JobKind.DISCOVERY, f"/internal/scans/{SCAN_ID}/progress"),
        (JobKind.EXECUTION, f"/internal/scans/{SCAN_ID}/execution-progress"),
    ],
)
def test_progress_posts_exact_route_body_and_auth(
    job_kind: JobKind,
    expected_path: str,
) -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(204)

    client = _client(handler, settings=_settings(auth_enabled=True, token=TOKEN))
    stage = (
        ScannerStage.NORMALIZING
        if job_kind is JobKind.DISCOVERY
        else ScannerStage.EXECUTING
    )
    client.report_progress(
        JOB_ID,
        stage,
        65,
        {"operations": 3},
        scan_id=SCAN_ID,
        job_kind=job_kind,
    )

    assert requests[0].method == "POST"
    assert requests[0].url.path == expected_path
    assert requests[0].headers["Authorization"] == f"Bearer {TOKEN}"
    assert json.loads(requests[0].content) == {
        "stage": (
            "API_NORMALIZATION"
            if job_kind is JobKind.DISCOVERY
            else "MODULE_EXECUTION"
        ),
        "progress": 65,
        "message": None,
        "metrics": {"operations": 3},
    }


@pytest.mark.parametrize(
    "statistics",
    [
        {"secret": 1},
        {"operations": "runtime-secret"},
        {"operations": True},
        {"operations": 0.5},
        {"operations": math.inf},
        {"operations": math.nan},
        {"operations": -1},
    ],
)
def test_progress_rejects_unsafe_metrics_before_sending(
    statistics: dict[str, object],
) -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(204)

    client = _client(handler)

    with pytest.raises(
        BackendIntegrationError,
        match="^backend callback payload is invalid$",
    ) as caught:
        client.report_progress(
            JOB_ID,
            ScannerStage.DISCOVERING,
            10,
            statistics,  # type: ignore[arg-type]
            scan_id=SCAN_ID,
            job_kind=JobKind.DISCOVERY,
        )

    assert requests == []
    _assert_safe(caught.value, "runtime-secret")


def test_progress_accepts_only_known_nonnegative_integer_metrics() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(204)

    client = _client(handler)
    client.report_progress(
        JOB_ID,
        ScannerStage.COMPLETED,
        100,
        {
            "actors": 2,
            "operations": 3,
            "object_types": 1,
            "requests_used": 4,
            "findings": 0,
        },
        scan_id=SCAN_ID,
        job_kind=JobKind.DISCOVERY,
    )

    assert json.loads(requests[0].content)["metrics"] == {
        "actors": 2,
        "operations": 3,
        "object_types": 1,
        "requests_used": 4,
        "findings": 0,
    }


@pytest.mark.parametrize(
    ("artifact_type", "job_kind", "expected_path", "payload"),
    [
        (
            "normalized_api_graph",
            JobKind.DISCOVERY,
            f"/internal/scans/{SCAN_ID}/normalized-api-graph",
            {"schema_version": "1.1", "scan_id": SCAN_ID, "operations": []},
        ),
        (
            "scan_result",
            JobKind.EXECUTION,
            f"/internal/scans/{SCAN_ID}/scan-result",
            {"schema_version": "1.1", "scan_id": SCAN_ID, "findings": []},
        ),
        (
            "evidence",
            JobKind.EXECUTION,
            f"/internal/scans/{SCAN_ID}/evidence",
            {
                "scan_id": SCAN_ID,
                "operation_id": "GET:/accounts",
                "module_id": "BOLA-001",
            },
        ),
    ],
)
def test_artifact_callbacks_post_decoded_json_and_return_opaque_reference(
    artifact_type: str,
    job_kind: JobKind,
    expected_path: str,
    payload: dict[str, object],
) -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(201, json=_artifact_response())

    client = _client(handler, settings=_settings(auth_enabled=True, token=TOKEN))
    artifact_ref = client.publish_artifact(
        _artifact(artifact_type, payload),
        job_id=JOB_ID,
        scan_id=SCAN_ID,
        job_kind=job_kind,
    )

    assert artifact_ref == "artifact:stored_123"
    assert requests[0].method == "POST"
    assert requests[0].url.path == expected_path
    assert requests[0].headers["Authorization"] == f"Bearer {TOKEN}"
    assert json.loads(requests[0].content) == payload


@pytest.mark.parametrize(
    ("status", "reason_codes"),
    [
        (ApprovalStatus.APPROVED, ()),
        (ApprovalStatus.REJECTED, ("PLAN_REQUEST_COUNT_STALE",)),
    ],
)
def test_plan_decision_posts_exact_route_and_payload(
    status: ApprovalStatus,
    reason_codes: tuple[str, ...],
) -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(204)

    decision = PlanApprovalDecision(
        scan_id=SCAN_ID,
        plan_id="plan-001",
        status=status,
        reason_codes=reason_codes,
    )
    client = _client(handler)
    client.report_approval(
        JOB_ID,
        decision,
        scan_id=SCAN_ID,
        job_kind=JobKind.EXECUTION,
    )

    assert requests[0].method == "POST"
    assert requests[0].url.path == f"/internal/scans/{SCAN_ID}/plan-approval"
    assert json.loads(requests[0].content) == {
        "job_id": JOB_ID,
        "plan_id": "plan-001",
        "status": status.value,
        "reason_codes": list(reason_codes),
    }


def test_failure_posts_safe_exact_route_and_payload() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(204)

    client = _client(handler)
    client.report_error(
        JOB_ID,
        ScannerErrorReport(
            code="MODULE_EXECUTION_FAILED",
            stage=ScannerStage.EXECUTING,
            retryable=False,
        ),
        scan_id=SCAN_ID,
        job_kind=JobKind.EXECUTION,
    )

    assert requests[0].method == "POST"
    assert requests[0].url.path == f"/internal/scans/{SCAN_ID}/failed"
    assert json.loads(requests[0].content) == {
        "source": "SCANNER",
        "stage": "MODULE_EXECUTION",
        "error": {
            "code": "MODULE_EXECUTION_FAILED",
            "message": "scanner job failed",
            "details": {"retryable": False},
        },
    }


def test_fetch_artifact_allows_only_same_origin_relative_paths() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, content=b'{"scan_id":"scan-001"}')

    client = _client(handler)
    content = client.fetch_artifact(
        "/internal/artifacts/input_1?download=1",
        job_id=JOB_ID,
        scan_id=SCAN_ID,
        job_kind=JobKind.EXECUTION,
    )

    assert content == b'{"scan_id":"scan-001"}'
    assert requests[0].method == "GET"
    assert requests[0].url == httpx.URL(
        f"{BASE_URL}/internal/artifacts/input_1?download=1"
    )

    for invalid_ref in (
        "https://other.example/internal/artifacts/secret",
        "//other.example/internal/artifacts/secret",
        "artifact:secret",
    ):
        with pytest.raises(
            BackendIntegrationError,
            match="^backend artifact location is invalid$",
        ):
            client.fetch_artifact(
                invalid_ref,
                job_id=JOB_ID,
                scan_id=SCAN_ID,
                job_kind=JobKind.EXECUTION,
            )


def test_http_client_budget_and_cancellation_reads_are_local_defaults() -> None:
    def fail_if_called(request: httpx.Request) -> httpx.Response:
        raise AssertionError(f"unexpected request: {request.method}")

    client = _client(fail_if_called)

    assert (
        client.get_requests_used(
            JOB_ID,
            scan_id=SCAN_ID,
            job_kind=JobKind.EXECUTION,
        )
        == 0
    )
    assert (
        client.is_cancelled(
            JOB_ID,
            scan_id=SCAN_ID,
            job_kind=JobKind.EXECUTION,
        )
        is False
    )


def test_http_client_rejects_missing_callback_routing_context() -> None:
    client = _client(lambda request: httpx.Response(204))

    with pytest.raises(
        BackendIntegrationError,
        match="^backend callback context is required$",
    ):
        client.report_progress(
            JOB_ID,
            ScannerStage.DISCOVERING,
            10,
            {},
        )

    with pytest.raises(
        BackendIntegrationError,
        match="^backend callback context is required$",
    ):
        client.publish_artifact(
            _artifact(
                "normalized_api_graph",
                {"schema_version": "1.1", "scan_id": SCAN_ID, "operations": []},
            )
        )


@pytest.mark.parametrize("failure_kind", ["timeout", "connection", "status"])
def test_transport_and_status_failures_are_fixed_and_secret_free(
    failure_kind: str,
) -> None:
    response_secret = "response-body-secret"
    concrete_query = "token=query-secret"

    def handler(request: httpx.Request) -> httpx.Response:
        if failure_kind == "timeout":
            raise httpx.ReadTimeout(
                f"{TOKEN} {concrete_query}",
                request=request,
            )
        if failure_kind == "connection":
            raise httpx.ConnectError(
                f"{TOKEN} {concrete_query}",
                request=request,
            )
        return httpx.Response(500, text=response_secret)

    client = _client(handler, settings=_settings(auth_enabled=True, token=TOKEN))
    with pytest.raises(
        BackendIntegrationError,
        match="^backend request failed$",
    ) as caught:
        client.report_progress(
            JOB_ID,
            ScannerStage.EXECUTING,
            50,
            {"operations": 1},
            scan_id=SCAN_ID,
            job_kind=JobKind.EXECUTION,
        )

    _assert_safe(caught.value, TOKEN, response_secret, concrete_query)


@pytest.mark.parametrize(
    ("response", "message"),
    [
        (
            httpx.Response(201, text="not-json response-body-secret"),
            "backend artifact response is invalid",
        ),
        (
            httpx.Response(
                201,
                json={"status": "SUCCESS", "details": {}},
            ),
            "backend artifact response is invalid",
        ),
        (
            httpx.Response(
                201,
                json=_artifact_response("bad/id?token=response-body-secret"),
            ),
            "backend artifact response is invalid",
        ),
    ],
)
def test_invalid_artifact_responses_are_fixed_and_secret_free(
    response: httpx.Response,
    message: str,
) -> None:
    submitted_secret = "submitted-artifact-secret"
    client = _client(lambda request: response)
    envelope = _artifact(
        "evidence",
        {
            "scan_id": SCAN_ID,
            "operation_id": "GET:/accounts",
            "module_id": "BOLA-001",
            "secret": submitted_secret,
        },
    )

    with pytest.raises(
        BackendIntegrationError,
        match=f"^{message}$",
    ) as caught:
        client.publish_artifact(
            envelope,
            job_id=JOB_ID,
            scan_id=SCAN_ID,
            job_kind=JobKind.EXECUTION,
        )

    _assert_safe(
        caught.value,
        TOKEN,
        submitted_secret,
        "response-body-secret",
    )
