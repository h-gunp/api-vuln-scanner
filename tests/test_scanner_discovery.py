from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Literal

import httpx
import pytest

from scanner.artifacts import ArtifactEnvelope
from scanner.audit import InMemoryAuditSink
from scanner.auth.session_manager import (
    ActorSession,
    SessionManager,
    _RuntimeSecret,
)
from scanner.contracts import ContractSource, DiscoveryJobRequest, TargetProfile
from scanner.crawler.katana_runner import KatanaError, KatanaRecord, KatanaRunResult
from scanner.integration.backend_client import FakeBackendClient, ScannerStage
from scanner.policy import CancellationRequested
from scanner.scanner import (
    OPENAPI_PATH_CANDIDATES,
    DiscoveryJobError,
    Scanner,
    load_contract_source,
)


SCAN_ID = "scan-001"
JOB_ID = "job-001"


def profile_payload(
    *,
    scan_id: str = SCAN_ID,
    sources: list[str] | None = None,
    allowed_paths: list[str] | None = None,
    max_requests: int = 40,
) -> dict[str, object]:
    return {
        "schema_version": "1.1",
        "scan_id": scan_id,
        "target": {
            "base_url": "http://vuln-bank.local",
            "allowed_paths": allowed_paths
            or ["/openapi.json", "/api/*"],
            "allowed_methods": ["GET"],
        },
        "discovery": {
            "sources": sources or ["openapi", "crawl"],
            "max_depth": 2,
        },
        "authentication": {
            "login": {
                "method": "POST",
                "path": "/api/login",
                "content_type": "application/json",
                "username_field": "username",
                "password_field": "password",
                "session": {
                    "type": "bearer",
                    "token_field": "access_token",
                },
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
            "max_requests": max_requests,
            "requests_per_second": 10000,
            "state_change_policy": "deny",
            "approved_modules": [
                "authz",
                "input_validation",
                "data_exposure",
            ],
        },
    }


def openapi_document() -> dict[str, object]:
    return {
        "openapi": "3.1.0",
        "paths": {
            "/api/accounts": {
                "get": {
                    "responses": {
                        "200": {
                            "description": "accounts",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "array",
                                        "items": {
                                            "type": "object",
                                            "properties": {
                                                "account_id": {"type": "string"},
                                                "balance": {"type": "number"},
                                            },
                                        },
                                    }
                                }
                            },
                        }
                    }
                }
            },
            "/private/admin": {
                "get": {
                    "responses": {"200": {"description": "must be filtered"}}
                }
            },
            "/api/transfer": {
                "post": {
                    "responses": {"200": {"description": "must be filtered"}}
                }
            },
        },
    }


def numeric_sensitive_openapi_document(
    *,
    declare_output: bool,
) -> dict[str, object]:
    response: dict[str, object] = {"description": "cards"}
    if declare_output:
        response["content"] = {
            "application/json": {
                "schema": {
                    "type": "object",
                    "properties": {
                        "items": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "card_number": {"type": "integer"}
                                },
                            },
                        }
                    },
                }
            }
        }
    return {
        "openapi": "3.1.0",
        "paths": {
            "/api/cards": {
                "get": {
                    "responses": {"200": response},
                }
            }
        },
    }


class RecordingBackend(FakeBackendClient):
    def __init__(self) -> None:
        super().__init__()
        self.published: list[ArtifactEnvelope] = []

    def publish_artifact(self, envelope: ArtifactEnvelope) -> str:
        self.published.append(envelope)
        return super().publish_artifact(envelope)


@dataclass
class FakeKatanaRunner:
    records: tuple[KatanaRecord, ...] = (
        KatanaRecord("GET", "http://vuln-bank.local/api/cards/42"),
        KatanaRecord("GET", "http://attacker.local/api/stolen"),
        KatanaRecord("GET", "http://vuln-bank.local/private/admin"),
        KatanaRecord("POST", "http://vuln-bank.local/api/transfer"),
    )
    fail: bool = False

    def __post_init__(self) -> None:
        self.actors: list[str] = []
        self.tokens: list[str] = []

    def run(
        self,
        profile: TargetProfile,
        *,
        session: ActorSession,
        allocated_requests: int,
        budget,
        cancellation_guard,
        job_id: str,
    ) -> KatanaRunResult:
        self.actors.append(session.actor_id)
        self.tokens.append(session.authorization_headers()["Authorization"])
        cancellation_guard.raise_if_cancelled(job_id)
        if allocated_requests:
            lease = budget.lease(1)
            lease.close()
        if self.fail:
            raise KatanaError("katana execution failed")
        return KatanaRunResult(records=self.records, requests_made=1)

    def __repr__(self) -> str:
        return "FakeKatanaRunner()"


@pytest.fixture(autouse=True)
def actor_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("USER_A_USERNAME", "user-a")
    monkeypatch.setenv("USER_A_PASSWORD", "password-a")
    monkeypatch.setenv("USER_B_USERNAME", "user-b")
    monkeypatch.setenv("USER_B_PASSWORD", "password-b")


def request_for(
    source: ContractSource,
    *,
    job_id: str = JOB_ID,
) -> DiscoveryJobRequest:
    return DiscoveryJobRequest(
        job_id=job_id,
        scan_id=SCAN_ID,
        target_profile=source,
    )


def discovery_transport(
    calls: list[tuple[str, str, str | None]],
    *,
    openapi_succeeds: bool = True,
):
    def handler(request: httpx.Request) -> httpx.Response:
        body: dict[str, str] = {}
        if request.content:
            body = json.loads(request.content)
        calls.append(
            (request.method, request.url.path, body.get("username"))
        )
        if request.method == "POST" and request.url.path == "/api/login":
            actor = body["username"][-1]
            return httpx.Response(
                200,
                json={"access_token": f"token-{actor}"},
                request=request,
            )
        if request.url.path == "/openapi.json" and openapi_succeeds:
            return httpx.Response(200, json=openapi_document(), request=request)
        if request.url.path == "/api/accounts":
            authorization = request.headers["authorization"]
            actor = authorization[-1]
            return httpx.Response(
                200,
                json={
                    "items": [
                        {
                            "account_id": f"account-{actor}-secret",
                            "balance": 10,
                        }
                    ]
                },
                request=request,
            )
        return httpx.Response(404, json={"detail": "not found"}, request=request)

    return httpx.MockTransport(handler)


def test_contract_source_loads_strict_v11_inline_and_artifact_profile() -> None:
    backend = RecordingBackend()
    payload = profile_payload()
    backend.set_artifact("artifact:profile", json.dumps(payload).encode())

    inline = load_contract_source(
        ContractSource(inline=payload),
        TargetProfile,
        backend,
    )
    artifact = load_contract_source(
        ContractSource(artifact_ref="artifact:profile"),
        TargetProfile,
        backend,
    )

    assert inline == artifact
    assert inline.schema_version == "1.1"


@pytest.mark.parametrize(
    "source",
    [
        ContractSource(artifact_ref="artifact:bad-json"),
        ContractSource(inline=profile_payload(scan_id="other-scan")),
    ],
)
def test_invalid_profile_or_scan_id_reports_fixed_non_retryable_error(
    source: ContractSource,
) -> None:
    backend = RecordingBackend()
    backend.set_artifact(
        "artifact:bad-json",
        b'{"password":"raw-payload-secret"',
    )
    scanner = Scanner(
        backend,
        transport=httpx.MockTransport(lambda request: pytest.fail("no transport")),
        katana_runner=FakeKatanaRunner(),
    )

    with pytest.raises(
        DiscoveryJobError,
        match="^discovery profile is invalid$",
    ) as error:
        scanner.run_discovery(request_for(source))

    assert backend.error_reports
    report = backend.error_reports[-1]
    assert report.code == "DISCOVERY_PROFILE_INVALID"
    assert report.stage is ScannerStage.PROFILE_LOADING
    assert report.retryable is False
    rendered = repr(error.value) + repr(backend.error_reports)
    assert "raw-payload-secret" not in rendered
    assert "other-scan" not in rendered


def test_discovery_orchestrates_sources_collection_artifact_and_progress() -> None:
    backend = RecordingBackend()
    backend.set_requests_used(JOB_ID, 3)
    calls: list[tuple[str, str, str | None]] = []
    katana = FakeKatanaRunner()
    audit = InMemoryAuditSink()
    scanner = Scanner(
        backend,
        transport=discovery_transport(calls),
        katana_runner=katana,
        audit_sink=audit,
    )

    outcome = scanner.run_discovery(
        request_for(ContractSource(inline=profile_payload()))
    )

    assert [event.stage for event in backend.progress_events] == [
        ScannerStage.PROFILE_LOADING,
        ScannerStage.AUTHENTICATING,
        ScannerStage.DISCOVERING,
        ScannerStage.NORMALIZING,
        ScannerStage.OBJECT_DISCOVERY,
        ScannerStage.COMPLETED,
    ]
    assert [event.progress for event in backend.progress_events] == sorted(
        event.progress for event in backend.progress_events
    )
    assert calls[:2] == [
        ("POST", "/api/login", "user-a"),
        ("POST", "/api/login", "user-b"),
    ]
    openapi_calls = [
        path
        for method, path, _ in calls
        if method == "GET" and path in OPENAPI_PATH_CANDIDATES
    ]
    assert openapi_calls == [
        "/openapi.json",
        "/api/openapi.json",
        "/api/swagger.json",
    ]
    assert katana.actors == ["user_a", "user_b"]
    assert katana.tokens == ["Bearer token-a", "Bearer token-b"]
    assert calls[-2:] == [
        ("GET", "/api/accounts", None),
        ("GET", "/api/accounts", None),
    ]

    assert outcome.job_id == JOB_ID
    assert outcome.scan_id == SCAN_ID
    assert outcome.graph.schema_version == "1.1"
    assert [
        (operation.method, operation.path_template)
        for operation in outcome.graph.operations
    ] == [
        ("GET", "/api/accounts"),
        ("GET", "/api/cards/{id}"),
    ]
    assert outcome.available_object_types == ("account",)
    assert outcome.requests_used == 12
    assert backend.progress_events[-1].statistics == {
        "actors": 2,
        "operations": 2,
        "object_types": 1,
        "requests_used": 12,
    }

    assert len(backend.published) == 1
    artifact = backend.published[0]
    assert artifact.scan_id == SCAN_ID
    assert artifact.artifact_type == "normalized_api_graph"
    assert artifact.schema_version == "1.1"
    assert artifact.sha256
    assert artifact.size == len(artifact.content)
    assert outcome.graph_artifact_ref == "artifact:1"
    rendered = (
        outcome.graph.model_dump_json()
        + artifact.content.decode()
        + repr(audit.events)
        + repr(scanner)
    )
    for secret in (
        "user-a",
        "password-a",
        "token-a",
        "account-a-secret",
        "account-b-secret",
        "42",
    ):
        assert secret not in rendered


def test_cancellation_before_authentication_uses_zero_transport_requests() -> None:
    backend = RecordingBackend()
    backend.cancel(JOB_ID)
    calls: list[httpx.Request] = []
    scanner = Scanner(
        backend,
        transport=httpx.MockTransport(
            lambda request: calls.append(request) or httpx.Response(200)
        ),
        katana_runner=FakeKatanaRunner(),
    )

    with pytest.raises(CancellationRequested, match="^scan cancelled$"):
        scanner.run_discovery(
            request_for(ContractSource(inline=profile_payload()))
        )

    assert calls == []
    assert [event.stage for event in backend.progress_events] == [
        ScannerStage.CANCELED
    ]


def test_cancellation_during_authentication_reports_canceled_not_auth_failure() -> None:
    backend = RecordingBackend()
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        backend.cancel(JOB_ID)
        return httpx.Response(
            200,
            json={"access_token": "token-a"},
            request=request,
        )

    scanner = Scanner(
        backend,
        transport=httpx.MockTransport(handler),
        katana_runner=FakeKatanaRunner(),
    )

    with pytest.raises(CancellationRequested, match="^scan cancelled$"):
        scanner.run_discovery(
            request_for(ContractSource(inline=profile_payload()))
        )

    assert len(calls) == 1
    assert backend.progress_events[-1].stage is ScannerStage.CANCELED
    assert backend.error_reports == []


def test_cancellation_between_openapi_probes_reports_canceled() -> None:
    backend = RecordingBackend()

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            username = json.loads(request.content)["username"]
            return httpx.Response(
                200,
                json={"access_token": f"token-{username[-1]}"},
                request=request,
            )
        backend.cancel(JOB_ID)
        return httpx.Response(
            200,
            json=openapi_document(),
            request=request,
        )

    scanner = Scanner(
        backend,
        transport=httpx.MockTransport(handler),
        katana_runner=FakeKatanaRunner(),
    )

    with pytest.raises(CancellationRequested, match="^scan cancelled$"):
        scanner.run_discovery(
            request_for(
                ContractSource(
                    inline=profile_payload(sources=["openapi"])
                )
            )
        )

    assert backend.progress_events[-1].stage is ScannerStage.CANCELED
    assert backend.error_reports == []


def test_invalid_restored_request_count_fails_before_transport() -> None:
    backend = RecordingBackend()
    backend.set_requests_used(JOB_ID, -1)
    calls: list[httpx.Request] = []
    scanner = Scanner(
        backend,
        transport=httpx.MockTransport(
            lambda request: calls.append(request) or httpx.Response(200)
        ),
        katana_runner=FakeKatanaRunner(),
    )

    with pytest.raises(
        DiscoveryJobError,
        match="^discovery request count is invalid$",
    ):
        scanner.run_discovery(
            request_for(ContractSource(inline=profile_payload()))
        )

    assert calls == []
    assert backend.error_reports[-1].code == "DISCOVERY_REQUEST_COUNT_INVALID"


def test_same_scan_new_job_rejects_retained_count_above_current_profile_cap() -> None:
    backend = RecordingBackend()
    calls: list[tuple[str, str, str | None]] = []
    scanner = Scanner(
        backend,
        transport=discovery_transport(calls),
        katana_runner=FakeKatanaRunner(),
    )
    first = scanner.run_discovery(
        request_for(
            ContractSource(
                inline=profile_payload(sources=["openapi"])
            )
        )
    )
    second_job_calls_start = len(calls)

    with pytest.raises(
        DiscoveryJobError,
        match="^discovery request count is invalid$",
    ):
        scanner.run_discovery(
            request_for(
                ContractSource(
                    inline=profile_payload(
                        sources=["openapi"],
                        max_requests=first.requests_used - 1,
                    )
                ),
                job_id="job-002",
            )
        )

    assert len(calls) == second_job_calls_start
    assert backend.error_events[-1].job_id == "job-002"
    assert backend.error_reports[-1].code == "DISCOVERY_REQUEST_COUNT_INVALID"


def test_same_scan_new_job_budget_checks_current_job_cancellation() -> None:
    backend = RecordingBackend()
    calls: list[tuple[str, str, str | None]] = []
    second_job = False

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal second_job
        body = json.loads(request.content) if request.content else {}
        calls.append(
            (request.method, request.url.path, body.get("username"))
        )
        if request.method == "POST":
            if second_job:
                backend.cancel("job-002")
            username = body["username"]
            return httpx.Response(
                200,
                json={"access_token": f"token-{username[-1]}"},
                request=request,
            )
        if request.url.path == "/openapi.json":
            return httpx.Response(
                200,
                json=openapi_document(),
                request=request,
            )
        if request.url.path == "/api/accounts":
            return httpx.Response(
                200,
                json={"items": []},
                request=request,
            )
        return httpx.Response(404, request=request)

    scanner = Scanner(
        backend,
        transport=httpx.MockTransport(handler),
        katana_runner=FakeKatanaRunner(),
    )
    scanner.run_discovery(
        request_for(
            ContractSource(
                inline=profile_payload(sources=["openapi"])
            )
        )
    )
    second_job = True
    second_job_calls_start = len(calls)

    with pytest.raises(CancellationRequested, match="^scan cancelled$"):
        scanner.run_discovery(
            request_for(
                ContractSource(
                    inline=profile_payload(sources=["openapi"])
                ),
                job_id="job-002",
            )
        )

    assert len(calls) - second_job_calls_start == 1
    assert backend.progress_events[-1].job_id == "job-002"
    assert backend.progress_events[-1].stage is ScannerStage.CANCELED


def test_openapi_success_and_katana_failure_completes_with_warning() -> None:
    backend = RecordingBackend()
    calls: list[tuple[str, str, str | None]] = []
    audit = InMemoryAuditSink()
    scanner = Scanner(
        backend,
        transport=discovery_transport(calls),
        katana_runner=FakeKatanaRunner(fail=True),
        audit_sink=audit,
    )

    outcome = scanner.run_discovery(
        request_for(ContractSource(inline=profile_payload()))
    )

    assert outcome.graph.operations
    assert backend.error_reports == []
    assert any(
        event.code == "DISCOVERY_KATANA_FAILED"
        and event.level == "WARNING"
        for event in audit.events
    )


def test_default_scanner_retains_redacted_katana_failure_warning() -> None:
    backend = RecordingBackend()
    calls: list[tuple[str, str, str | None]] = []
    scanner = Scanner(
        backend,
        transport=discovery_transport(calls),
        katana_runner=FakeKatanaRunner(fail=True),
    )

    scanner.run_discovery(
        request_for(ContractSource(inline=profile_payload()))
    )

    assert any(
        event.code == "DISCOVERY_KATANA_FAILED"
        and event.level == "WARNING"
        for event in scanner.audit_events
    )


def test_openapi_failure_and_katana_success_completes() -> None:
    backend = RecordingBackend()
    calls: list[tuple[str, str, str | None]] = []
    katana = FakeKatanaRunner(
        records=(
            KatanaRecord(
                "GET",
                "http://vuln-bank.local/api/accounts",
            ),
        )
    )
    scanner = Scanner(
        backend,
        transport=discovery_transport(calls, openapi_succeeds=False),
        katana_runner=katana,
    )

    outcome = scanner.run_discovery(
        request_for(ContractSource(inline=profile_payload()))
    )

    assert [
        operation.path_template for operation in outcome.graph.operations
    ] == ["/api/accounts"]
    assert outcome.available_object_types == ("account",)


def test_both_discovery_sources_failing_reports_fixed_error_code() -> None:
    backend = RecordingBackend()
    calls: list[tuple[str, str, str | None]] = []
    scanner = Scanner(
        backend,
        transport=discovery_transport(calls, openapi_succeeds=False),
        katana_runner=FakeKatanaRunner(fail=True),
    )

    with pytest.raises(
        DiscoveryJobError,
        match="^discovery sources failed$",
    ):
        scanner.run_discovery(
            request_for(ContractSource(inline=profile_payload()))
        )

    assert backend.error_reports[-1].code == "DISCOVERY_SOURCES_FAILED"
    assert backend.error_reports[-1].stage is ScannerStage.DISCOVERING
    assert backend.error_reports[-1].retryable is True
    assert backend.published == []


def test_openapi_and_katana_operations_are_refiltered_before_graph_publish() -> None:
    backend = RecordingBackend()
    calls: list[tuple[str, str, str | None]] = []
    scanner = Scanner(
        backend,
        transport=discovery_transport(calls),
        katana_runner=FakeKatanaRunner(),
    )

    outcome = scanner.run_discovery(
        request_for(ContractSource(inline=profile_payload()))
    )

    paths = {operation.path_template for operation in outcome.graph.operations}
    assert "/private/admin" not in paths
    assert "/api/transfer" not in paths
    assert "/api/stolen" not in paths
    assert all(operation.method == "GET" for operation in outcome.graph.operations)


def test_openapi_paths_generalize_value_segments_without_credential_substrings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = RecordingBackend()
    monkeypatch.setenv("USER_A_USERNAME", "pi")
    monkeypatch.setenv("USER_A_PASSWORD", "d")
    uuid_v7 = "01890abc-def0-7abc-8def-0123456789ab"

    document = {
        "openapi": "3.1.0",
        "paths": {
            "/api/users/42": {
                "get": {
                    "responses": {
                        "200": {
                            "description": "numeric concrete path",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "id": {"type": "string"},
                                            "api_status": {"type": "string"},
                                        },
                                    }
                                }
                            },
                        }
                    }
                }
            },
            f"/api/audit/{uuid_v7}": {
                "get": {
                    "responses": {
                        "200": {"description": "uuid concrete path"}
                    }
                }
            },
            "/api/users/{user_id}": {
                "get": {
                    "parameters": [
                        {
                            "name": "user_id",
                            "in": "path",
                            "required": True,
                            "schema": {"type": "string"},
                        }
                    ],
                    "responses": {
                        "200": {"description": "declared template"}
                    }
                }
            },
        },
    }

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            username = json.loads(request.content)["username"]
            return httpx.Response(
                200,
                json={"access_token": f"token-{len(username)}"},
                request=request,
            )
        if request.url.path == "/openapi.json":
            return httpx.Response(200, json=document, request=request)
        return httpx.Response(200, json={}, request=request)

    scanner = Scanner(
        backend,
        transport=httpx.MockTransport(handler),
        katana_runner=FakeKatanaRunner(),
    )

    outcome = scanner.run_discovery(
        request_for(
            ContractSource(
                inline=profile_payload(sources=["openapi"])
            )
        )
    )

    paths = {
        operation.path_template: operation for operation in outcome.graph.operations
    }
    assert set(paths) == {
        "/api/audit/{id}",
        "/api/users/{id}",
        "/api/users/{user_id}",
    }
    assert paths["/api/audit/{id}"].operation_id == "GET:/api/audit/{id}"
    assert paths["/api/users/{id}"].operation_id == "GET:/api/users/{id}"
    assert {field.field_path for field in paths["/api/users/{id}"].outputs} >= {
        "id",
        "api_status",
    }
    rendered = (
        outcome.graph.model_dump_json()
        + backend.published[0].content.decode()
        + repr(backend.__dict__)
        + repr(scanner)
    )
    for secret in ("token-2", "password-b", uuid_v7):
        assert secret not in rendered
    assert "/42" not in rendered
    assert "/api/" in rendered
    assert '"field_path":"id"' in outcome.graph.model_dump_json()
    assert b'"field_path":"id"' in backend.published[0].content


def test_collected_object_id_generalizes_matching_authoritative_path_segment() -> None:
    backend = RecordingBackend()
    runtime_account_id = "account-a-secret"
    document = {
        "openapi": "3.1.0",
        "paths": {
            "/api/accounts": {
                "get": {
                    "responses": {
                        "200": {
                            "description": "account collection",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "items": {
                                                "type": "array",
                                                "items": {
                                                    "type": "object",
                                                    "properties": {
                                                        "account_id": {
                                                            "type": "string"
                                                        }
                                                    },
                                                },
                                            }
                                        },
                                    }
                                }
                            },
                        }
                    }
                }
            },
            f"/api/accounts/{runtime_account_id}": {
                "get": {
                    "responses": {
                        "200": {"description": "concrete account path"}
                    }
                }
            },
        },
    }

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            username = json.loads(request.content)["username"]
            return httpx.Response(
                200,
                json={"access_token": f"token-{username[-1]}"},
                request=request,
            )
        if request.url.path == "/openapi.json":
            return httpx.Response(200, json=document, request=request)
        if request.url.path == "/api/accounts":
            return httpx.Response(
                200,
                json={"items": [{"account_id": runtime_account_id}]},
                request=request,
            )
        return httpx.Response(200, json={}, request=request)

    scanner = Scanner(
        backend,
        transport=httpx.MockTransport(handler),
        katana_runner=FakeKatanaRunner(),
    )

    outcome = scanner.run_discovery(
        request_for(ContractSource(inline=profile_payload(sources=["openapi"])))
    )

    operations = {
        operation.path_template: operation for operation in outcome.graph.operations
    }
    assert set(operations) == {"/api/accounts", "/api/accounts/{id}"}
    generalized = operations["/api/accounts/{id}"]
    assert generalized.operation_id == "GET:/api/accounts/{id}"
    assert {
        (field.location, field.field_path) for field in generalized.inputs
    } == {("path", "id")}
    rendered = (
        outcome.graph.model_dump_json()
        + backend.published[0].content.decode()
        + repr(backend.__dict__)
        + repr(scanner)
    )
    assert runtime_account_id not in rendered


def test_numeric_sensitive_live_output_keeps_integer_type_without_raw_value() -> None:
    backend = RecordingBackend()
    card_number = 4111111111111111

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            username = json.loads(request.content)["username"]
            return httpx.Response(
                200,
                json={"access_token": f"token-{username[-1]}"},
                request=request,
            )
        if request.url.path == "/openapi.json":
            return httpx.Response(
                200,
                json=numeric_sensitive_openapi_document(declare_output=False),
                request=request,
            )
        if request.url.path == "/api/cards":
            return httpx.Response(
                200,
                json={"items": [{"card_number": card_number}]},
                request=request,
            )
        return httpx.Response(404, request=request)

    scanner = Scanner(
        backend,
        transport=httpx.MockTransport(handler),
        katana_runner=FakeKatanaRunner(records=()),
    )

    outcome = scanner.run_discovery(
        request_for(ContractSource(inline=profile_payload(sources=["openapi"])))
    )

    operation = outcome.graph.operations[0]
    assert [
        (field.field_path, field.type)
        for field in operation.outputs
        if field.field_path == "items[].card_number"
    ] == [("items[].card_number", "integer")]
    rendered = (
        outcome.graph.model_dump_json()
        + backend.published[0].content.decode()
        + repr(backend.__dict__)
        + repr(scanner)
    )
    assert str(card_number) not in rendered


def test_numeric_sensitive_live_output_does_not_add_string_to_openapi_integer() -> None:
    backend = RecordingBackend()
    card_number = 4111111111111111

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            username = json.loads(request.content)["username"]
            return httpx.Response(
                200,
                json={"access_token": f"token-{username[-1]}"},
                request=request,
            )
        if request.url.path == "/openapi.json":
            return httpx.Response(
                200,
                json=numeric_sensitive_openapi_document(declare_output=True),
                request=request,
            )
        if request.url.path == "/api/cards":
            return httpx.Response(
                200,
                json={"items": [{"card_number": card_number}]},
                request=request,
            )
        return httpx.Response(404, request=request)

    scanner = Scanner(
        backend,
        transport=httpx.MockTransport(handler),
        katana_runner=FakeKatanaRunner(records=()),
    )

    outcome = scanner.run_discovery(
        request_for(ContractSource(inline=profile_payload(sources=["openapi"])))
    )

    operation = outcome.graph.operations[0]
    assert [
        (field.field_path, field.type)
        for field in operation.outputs
        if field.field_path == "items[].card_number"
    ] == [("items[].card_number", "integer")]
    rendered = (
        outcome.graph.model_dump_json()
        + backend.published[0].content.decode()
        + repr(backend.__dict__)
        + repr(scanner)
    )
    assert str(card_number) not in rendered


def test_object_id_openapi_placeholder_is_renamed_with_matching_path_input() -> None:
    backend = RecordingBackend()
    runtime_object_id = "opaque-account-id"
    document = {
        "openapi": "3.1.0",
        "paths": {
            "/api/accounts": {
                "get": {
                    "responses": {
                        "200": {
                            "description": "account collection",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "items": {
                                                "type": "array",
                                                "items": {
                                                    "type": "object",
                                                    "properties": {
                                                        "account_id": {
                                                            "type": "string"
                                                        }
                                                    },
                                                },
                                            }
                                        },
                                    }
                                }
                            },
                        }
                    }
                }
            },
            f"/api/accounts/{{id}}/sessions/{{{runtime_object_id}}}": {
                "get": {
                    "parameters": [
                        {
                            "name": "id",
                            "in": "path",
                            "required": True,
                            "schema": {"type": "string"},
                        },
                        {
                            "name": runtime_object_id,
                            "in": "path",
                            "required": True,
                            "schema": {"type": "string"},
                        },
                    ],
                    "responses": {
                        "200": {"description": "declared template"}
                    },
                }
            }
        },
    }

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            return httpx.Response(
                200,
                json={"access_token": "ordinary-token"},
                request=request,
            )
        if request.url.path == "/openapi.json":
            return httpx.Response(200, json=document, request=request)
        if request.url.path == "/api/accounts":
            return httpx.Response(
                200,
                json={"items": [{"account_id": runtime_object_id}]},
                request=request,
            )
        return httpx.Response(200, json={}, request=request)

    scanner = Scanner(
        backend,
        transport=httpx.MockTransport(handler),
        katana_runner=FakeKatanaRunner(),
    )

    outcome = scanner.run_discovery(
        request_for(ContractSource(inline=profile_payload(sources=["openapi"])))
    )

    operation = next(
        item
        for item in outcome.graph.operations
        if "/sessions/" in item.path_template
    )
    assert operation.path_template == (
        "/api/accounts/{id}/sessions/{id_2}"
    )
    assert operation.operation_id == (
        "GET:/api/accounts/{id}/sessions/{id_2}"
    )
    assert {
        (field.location, field.field_path) for field in operation.inputs
    } == {("path", "id"), ("path", "id_2")}
    artifact_graph = json.loads(backend.published[0].content)
    artifact_operation = next(
        item
        for item in artifact_graph["operations"]
        if "/sessions/" in item["path_template"]
    )
    assert artifact_operation["path_template"] == (
        "/api/accounts/{id}/sessions/{id_2}"
    )
    assert artifact_operation["operation_id"] == (
        "GET:/api/accounts/{id}/sessions/{id_2}"
    )
    assert {
        (field["location"], field["field_path"])
        for field in artifact_operation["inputs"]
    } == {("path", "id"), ("path", "id_2")}
    rendered = (
        outcome.graph.model_dump_json()
        + backend.published[0].content.decode()
        + repr(backend.__dict__)
        + repr(scanner)
    )
    assert runtime_object_id not in rendered


@pytest.mark.parametrize(
    ("secret_kind", "runtime_secret"),
    [
        ("token", "opaque-session-field"),
        ("credential", "credential-field-name"),
        ("cookie", "cookie-field-name"),
    ],
)
def test_structural_runtime_secret_fields_are_absent_from_graph_and_artifact(
    monkeypatch: pytest.MonkeyPatch,
    secret_kind: str,
    runtime_secret: str,
) -> None:
    backend = RecordingBackend()
    if secret_kind == "credential":
        monkeypatch.setenv("USER_A_PASSWORD", runtime_secret)
    if secret_kind == "cookie":
        original_authenticate = SessionManager.authenticate

        def authenticate_with_cookie(
            manager: SessionManager,
            profile: TargetProfile,
        ):
            runtime = original_authenticate(manager, profile)
            runtime.sessions["user_a"].cookies["sid"] = _RuntimeSecret(
                runtime_secret
            )
            return runtime

        monkeypatch.setattr(
            SessionManager,
            "authenticate",
            authenticate_with_cookie,
        )
    document = {
        "openapi": "3.1.0",
        "paths": {
            "/api/accounts": {
                "get": {
                    "parameters": [
                        {
                            "name": runtime_secret,
                            "in": "query",
                            "schema": {"type": "string"},
                        },
                        {
                            "name": "id",
                            "in": "query",
                            "schema": {"type": "string"},
                        },
                    ],
                    "responses": {
                        "200": {
                            "description": "authoritative fields",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            runtime_secret: {"type": "string"},
                                            "id": {"type": "string"},
                                            "api_status": {"type": "string"},
                                        },
                                    }
                                }
                            },
                        }
                    },
                }
            }
        },
    }

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            return httpx.Response(
                200,
                json={
                    "access_token": (
                        runtime_secret
                        if secret_kind == "token"
                        else "ordinary-token"
                    )
                },
                request=request,
            )
        if request.url.path == "/openapi.json":
            return httpx.Response(200, json=document, request=request)
        return httpx.Response(
            200,
            json={"id": "ordinary-id", "api_status": "ok"},
            request=request,
        )

    scanner = Scanner(
        backend,
        transport=httpx.MockTransport(handler),
        katana_runner=FakeKatanaRunner(),
    )

    outcome = scanner.run_discovery(
        request_for(ContractSource(inline=profile_payload(sources=["openapi"])))
    )

    operation = outcome.graph.operations[0]
    assert {field.field_path for field in operation.inputs} == {"id"}
    assert {field.field_path for field in operation.outputs} == {
        "api_status",
        "id",
    }
    artifact_graph = json.loads(backend.published[0].content)
    artifact_operation = artifact_graph["operations"][0]
    assert {field["field_path"] for field in artifact_operation["inputs"]} == {"id"}
    assert {field["field_path"] for field in artifact_operation["outputs"]} == {
        "api_status",
        "id",
    }
    assert runtime_secret not in outcome.graph.model_dump_json()
    assert runtime_secret not in backend.published[0].content.decode()


def test_short_structural_runtime_secrets_are_removed_and_path_is_generalized(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = RecordingBackend()
    monkeypatch.setenv("USER_A_PASSWORD", "pw")
    original_authenticate = SessionManager.authenticate

    def authenticate_with_cookie(
        manager: SessionManager,
        profile: TargetProfile,
    ):
        runtime = original_authenticate(manager, profile)
        runtime.sessions["user_a"].cookies["sid"] = _RuntimeSecret("ck")
        return runtime

    monkeypatch.setattr(
        SessionManager,
        "authenticate",
        authenticate_with_cookie,
    )
    short_components = ("pw", "tk", "ck", "42")
    document = {
        "openapi": "3.1.0",
        "paths": {
            "/api/accounts": {
                "get": {
                    "parameters": [
                        {
                            "name": component,
                            "in": "query",
                            "schema": {"type": "string"},
                        }
                        for component in (*short_components, "safe")
                    ],
                    "responses": {
                        "200": {
                            "description": "authoritative fields",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            component: {"type": "string"}
                                            for component in (
                                                *short_components,
                                                "safe",
                                                "account_id",
                                            )
                                        },
                                    }
                                }
                            },
                        }
                    },
                }
            },
            "/api/secrets/{pw}/{tk}/{ck}/{42}": {
                "get": {
                    "parameters": [
                        {
                            "name": component,
                            "in": "path",
                            "required": True,
                            "schema": {"type": "string"},
                        }
                        for component in short_components
                    ],
                    "responses": {
                        "200": {"description": "authoritative path"}
                    },
                }
            },
        },
    }

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            return httpx.Response(
                200,
                json={"access_token": "tk"},
                request=request,
            )
        if request.url.path == "/openapi.json":
            return httpx.Response(200, json=document, request=request)
        if request.url.path == "/api/accounts":
            return httpx.Response(
                200,
                json={"account_id": 42, "safe": "ok"},
                request=request,
            )
        return httpx.Response(200, json={}, request=request)

    scanner = Scanner(
        backend,
        transport=httpx.MockTransport(handler),
        katana_runner=FakeKatanaRunner(records=()),
    )

    outcome = scanner.run_discovery(
        request_for(ContractSource(inline=profile_payload(sources=["openapi"])))
    )

    operations = {
        operation.path_template: operation for operation in outcome.graph.operations
    }
    assert set(operations) == {
        "/api/accounts",
        "/api/secrets/{id}/{id_2}/{id_3}/{id_4}",
    }
    assert {field.field_path for field in operations["/api/accounts"].inputs} == {
        "safe"
    }
    assert {field.field_path for field in operations["/api/accounts"].outputs} == {
        "account_id",
        "safe",
    }
    assert {
        field.field_path
        for field in operations[
            "/api/secrets/{id}/{id_2}/{id_3}/{id_4}"
        ].inputs
    } == {"id", "id_2", "id_3", "id_4"}
    artifact_graph = json.loads(backend.published[0].content)
    assert artifact_graph == outcome.graph.model_dump(mode="json")
    rendered = outcome.graph.model_dump_json() + backend.published[0].content.decode()
    for component in short_components:
        assert f'"field_path":"{component}"' not in rendered
        assert f"{{{component}}}" not in rendered


def test_short_live_token_component_is_rejected_from_graph_and_artifact() -> None:
    backend = RecordingBackend()
    document = {
        "openapi": "3.1.0",
        "paths": {
            "/api/accounts": {
                "get": {
                    "responses": {
                        "200": {"description": "live-only structure"}
                    }
                }
            }
        },
    }

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            return httpx.Response(
                200,
                json={"access_token": "tk"},
                request=request,
            )
        if request.url.path == "/openapi.json":
            return httpx.Response(200, json=document, request=request)
        if request.url.path == "/api/accounts":
            return httpx.Response(
                200,
                json={"safe": {"status": "ok"}, "tk": {"value": 1}},
                request=request,
            )
        return httpx.Response(404, request=request)

    scanner = Scanner(
        backend,
        transport=httpx.MockTransport(handler),
        katana_runner=FakeKatanaRunner(records=()),
    )

    outcome = scanner.run_discovery(
        request_for(ContractSource(inline=profile_payload(sources=["openapi"])))
    )

    output_paths = {
        field.field_path for field in outcome.graph.operations[0].outputs
    }
    assert output_paths == {"safe", "safe.status"}
    assert '"field_path":"tk"' not in outcome.graph.model_dump_json()
    assert b'"field_path":"tk"' not in backend.published[0].content


def test_katana_query_values_do_not_delete_authoritative_fields_but_object_id_does() -> None:
    backend = RecordingBackend()
    runtime_object_id = "shared_secret_key"
    document = {
        "openapi": "3.1.0",
        "paths": {
            "/api/accounts": {
                "get": {
                    "responses": {
                        "200": {
                            "description": "authoritative account list",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "items": {
                                                "type": "array",
                                                "items": {
                                                    "type": "object",
                                                    "properties": {
                                                        "name": {"type": "string"},
                                                        "status": {"type": "string"},
                                                    },
                                                },
                                            }
                                        },
                                    }
                                }
                            },
                        }
                    }
                }
            }
        },
    }

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            username = json.loads(request.content)["username"]
            return httpx.Response(
                200,
                json={"access_token": f"token-{username[-1]}"},
                request=request,
            )
        if request.url.path == "/openapi.json":
            return httpx.Response(200, json=document, request=request)
        if request.url.path == "/api/accounts":
            return httpx.Response(
                200,
                json={
                    "items": [
                        {
                            "account_id": runtime_object_id,
                            "name": "Alice",
                            "status": "active",
                        }
                    ],
                    runtime_object_id: "dynamic value",
                },
                request=request,
            )
        return httpx.Response(404, request=request)

    scanner = Scanner(
        backend,
        transport=httpx.MockTransport(handler),
        katana_runner=FakeKatanaRunner(
            records=(
                KatanaRecord(
                    "GET",
                    "http://vuln-bank.local/api/accounts?field=name&mode=status",
                ),
            )
        ),
    )

    outcome = scanner.run_discovery(
        request_for(
            ContractSource(inline=profile_payload(sources=["openapi", "crawl"]))
        )
    )

    operation = outcome.graph.operations[0]
    output_paths = {field.field_path for field in operation.outputs}
    assert {"items[].name", "items[].status"} <= output_paths
    assert runtime_object_id not in output_paths
    assert runtime_object_id not in outcome.graph.model_dump_json()


def test_live_output_union_keeps_names_and_rejects_dynamic_mapping_keys(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = RecordingBackend()
    monkeypatch.setenv("USER_A_PASSWORD", "id")
    monkeypatch.setenv("USER_B_PASSWORD", "id")
    dynamic_uuid = "01890abc-def0-7abc-8def-0123456789ab"
    dynamic_hex = "abcdef0123456789"
    runtime_object_id = "shared_secret_key"
    document = {
        "openapi": "3.1.0",
        "paths": {
            "/api/accounts": {
                "get": {
                    "responses": {
                        "200": {
                            "description": "declared structure",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "declared-hyphen": {
                                                "type": "string"
                                            }
                                        },
                                    }
                                }
                            },
                        }
                    }
                }
            }
        },
    }

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            username = json.loads(request.content)["username"]
            return httpx.Response(
                200,
                json={
                    "access_token": f"session_secret_{username[-1]}"
                },
                request=request,
            )
        if request.url.path == "/openapi.json":
            return httpx.Response(200, json=document, request=request)
        if request.url.path == "/api/accounts":
            is_actor_a = (
                request.headers["authorization"] == "Bearer session_secret_a"
            )
            session_key = (
                "session_secret_a" if is_actor_a else "session_secret_b"
            )
            body = {
                "common": {"status": "ok"},
                "id": "ordinary-id-value",
                "account_id": runtime_object_id,
                runtime_object_id: {"balance": 10},
                "shared-dynamic-key": {"value": 1},
                dynamic_uuid: {"value": 1},
                dynamic_hex: {"value": 1},
                "123": {"value": 1},
                session_key: {"value": 1},
            }
            body["ssn" if is_actor_a else "admin_note"] = (
                "111-22-3333" if is_actor_a else "admin-secret-value"
            )
            return httpx.Response(200, json=body, request=request)
        return httpx.Response(404, request=request)

    scanner = Scanner(
        backend,
        transport=httpx.MockTransport(handler),
        katana_runner=FakeKatanaRunner(),
    )

    outcome = scanner.run_discovery(
        request_for(
            ContractSource(
                inline=profile_payload(sources=["openapi"])
            )
        )
    )

    output_paths = {
        field.field_path for field in outcome.graph.operations[0].outputs
    }
    assert output_paths >= {
        "declared-hyphen",
        "common",
        "common.status",
        "account_id",
        "ssn",
        "admin_note",
    }
    for rejected in (
        runtime_object_id,
        "shared-dynamic-key",
        dynamic_uuid,
        dynamic_hex,
        "123",
        "session_secret_a",
        "session_secret_b",
    ):
        assert all(
            rejected not in field_path for field_path in output_paths
        )
    assert "id" not in output_paths

    rendered = (
        outcome.graph.model_dump_json()
        + backend.published[0].content.decode()
        + repr(backend.__dict__)
        + repr(scanner)
    )
    for secret in (
        runtime_object_id,
        dynamic_uuid,
        dynamic_hex,
        "111-22-3333",
        "admin-secret-value",
        "ordinary-id-value",
        "session_secret_a",
        "session_secret_b",
    ):
        assert secret not in rendered


def test_cancellation_from_final_object_response_prevents_graph_publication() -> None:
    backend = RecordingBackend()

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            username = json.loads(request.content)["username"]
            return httpx.Response(
                200,
                json={"access_token": f"token-{username[-1]}"},
                request=request,
            )
        if request.url.path == "/openapi.json":
            return httpx.Response(
                200,
                json=openapi_document(),
                request=request,
            )
        if request.url.path == "/api/accounts":
            if request.headers["authorization"] == "Bearer token-b":
                backend.cancel(JOB_ID)
            return httpx.Response(
                200,
                json={"items": [{"account_id": "account-secret"}]},
                request=request,
            )
        return httpx.Response(404, request=request)

    scanner = Scanner(
        backend,
        transport=httpx.MockTransport(handler),
        katana_runner=FakeKatanaRunner(),
    )

    with pytest.raises(CancellationRequested, match="^scan cancelled$"):
        scanner.run_discovery(
            request_for(
                ContractSource(
                    inline=profile_payload(sources=["openapi"])
                )
            )
        )

    assert backend.published == []
    assert backend.progress_events[-1].stage is ScannerStage.CANCELED
    assert all(
        event.stage is not ScannerStage.COMPLETED
        for event in backend.progress_events
    )
