from __future__ import annotations

import json
from dataclasses import dataclass

import httpx
import pytest

from scanner.artifacts import ArtifactEnvelope
from scanner.audit import InMemoryAuditSink
from scanner.contracts import (
    ContractSource,
    DiscoveryJobRequest,
    ExecutionJobRequest,
    VulnerabilityType,
)
from scanner.crawler.katana_runner import KatanaRunResult
from scanner.integration.backend_client import FakeBackendClient, ScannerStage
from scanner.scanner import ExecutionJobError, Scanner


SCAN_ID = "integration-scan-001"
DISCOVERY_JOB_ID = "integration-discovery"
EXECUTION_JOB_ID = "integration-execution"
RUNTIME_VALUES = (
    "fixture-user-a",
    "fixture-user-b",
    "pw-a",
    "pw-b",
    "token-a",
    "token-b",
    "cookie-a",
    "cookie-b",
    "acct-a-1",
    "acct-b-1",
    "clear-profile-secret",
)


def profile_payload() -> dict[str, object]:
    return {
        "schema_version": "1.1",
        "scan_id": SCAN_ID,
        "target": {
            "base_url": "http://vuln-bank.local",
            "allowed_paths": ["/openapi.json", "/api/*"],
            "allowed_methods": ["GET"],
        },
        "discovery": {"sources": ["openapi"], "max_depth": 1},
        "authentication": {
            "login": {
                "method": "POST",
                "path": "/api/login",
                "content_type": "application/json",
                "username_field": "username",
                "password_field": "password",
                "session": {"type": "bearer", "token_field": "access_token"},
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
            "max_requests": 80,
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
    account_schema = {
        "type": "object",
        "properties": {
            "account_id": {"type": "string"},
            "display_name": {"type": "string"},
        },
    }
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
                                        "type": "object",
                                        "properties": {
                                            "items": {
                                                "type": "array",
                                                "items": account_schema,
                                            }
                                        },
                                    }
                                }
                            },
                        }
                    }
                }
            },
            "/api/accounts/{account_id}": {
                "get": {
                    "parameters": [
                        {
                            "name": "account_id",
                            "in": "path",
                            "required": True,
                            "schema": {"type": "string"},
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "account",
                            "content": {
                                "application/json": {"schema": account_schema}
                            },
                        }
                    },
                }
            },
            "/api/search": {
                "get": {
                    "parameters": [
                        {
                            "name": "page",
                            "in": "query",
                            "schema": {"type": "integer", "default": 1},
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "search",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "items": {
                                                "type": "array",
                                                "items": account_schema,
                                            }
                                        },
                                    }
                                }
                            },
                        }
                    },
                }
            },
            "/api/profile": {
                "get": {
                    "responses": {
                        "200": {
                            "description": "profile",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "display_name": {"type": "string"},
                                            "password": {"type": "string"},
                                        },
                                    }
                                }
                            },
                        }
                    }
                }
            },
        },
    }


def analysis_payload() -> dict[str, object]:
    return {
        "schema_version": "1.2",
        "scan_id": SCAN_ID,
        "model_name": "external-llm-fixture",
        "prompt_version": "fixture-v1",
        "prompt_sha256": "1" * 64,
        "approved_module_ids": ["BOLA-001", "INPUT-001", "DATA-001"],
        "relationships": [],
        "test_candidates": [
            {
                "candidate_id": "bola-candidate",
                "module_id": "BOLA-001",
                "target_operation_id": "GET:/api/accounts/{account_id}",
                "required_object_types": ["account"],
                "rationale": "foreign account binding",
                "priority": 1,
                "executable": True,
                "missing_requirements": [],
                "binding_hints": [
                    {
                        "parameter": "account_id",
                        "location": "path",
                        "binding_type": "object_binding",
                        "object_type": "account",
                    }
                ],
            },
            {
                "candidate_id": "input-candidate",
                "module_id": "INPUT-001",
                "target_operation_id": "GET:/api/search",
                "required_object_types": [],
                "rationale": "query mutation",
                "priority": 2,
                "executable": True,
                "missing_requirements": [],
                "binding_hints": [
                    {
                        "parameter": "page",
                        "location": "query",
                        "binding_type": "parameter_binding",
                        "object_type": None,
                    }
                ],
            },
            {
                "candidate_id": "data-candidate",
                "module_id": "DATA-001",
                "target_operation_id": "GET:/api/profile",
                "required_object_types": [],
                "rationale": "profile data exposure",
                "priority": 3,
                "executable": True,
                "missing_requirements": [],
                "binding_hints": [],
            },
        ],
    }


def plan_payload(requests_used: int) -> dict[str, object]:
    return {
        "schema_version": "1.2",
        "plan_id": "integration-plan",
        "scan_id": SCAN_ID,
        "model_name": "external-llm-fixture",
        "prompt_version": "fixture-v1",
        "prompt_sha256": "1" * 64,
        "status": "PENDING_APPROVAL",
        "budget": {
            "requests_already_used": requests_used,
            "estimated_execution_requests": 5,
            "max_requests": 80,
            "within_budget": True,
        },
        "steps": [
            {
                "order": 1,
                "candidate_id": "bola-candidate",
                "module_id": "BOLA-001",
                "target_operation_id": "GET:/api/accounts/{account_id}",
                "target_endpoint": {
                    "method": "GET",
                    "path_template": "/api/accounts/{account_id}",
                },
                "input_bindings": [
                    {
                        "parameter": "account_id",
                        "location": "path",
                        "binding_type": "object_binding",
                        "object_type": "account",
                        "owner": "user_b",
                    }
                ],
            },
            {
                "order": 2,
                "candidate_id": "input-candidate",
                "module_id": "INPUT-001",
                "target_operation_id": "GET:/api/search",
                "target_endpoint": {
                    "method": "GET",
                    "path_template": "/api/search",
                },
                "input_bindings": [
                    {
                        "parameter": "page",
                        "location": "query",
                        "binding_type": "parameter_binding",
                        "object_type": None,
                        "owner": None,
                    }
                ],
            },
            {
                "order": 3,
                "candidate_id": "data-candidate",
                "module_id": "DATA-001",
                "target_operation_id": "GET:/api/profile",
                "target_endpoint": {
                    "method": "GET",
                    "path_template": "/api/profile",
                },
                "input_bindings": [],
            },
        ],
    }


@dataclass
class NoopKatana:
    def run(self, *args: object, **kwargs: object) -> KatanaRunResult:
        return KatanaRunResult(records=(), requests_made=0)


class RecordingBackend(FakeBackendClient):
    def __init__(self) -> None:
        super().__init__()
        self.published: list[ArtifactEnvelope] = []
        self.timeline: list[str] = []

    def publish_artifact(self, envelope: ArtifactEnvelope) -> str:
        self.published.append(envelope)
        self.timeline.append(f"artifact:{envelope.artifact_type}")
        return super().publish_artifact(envelope)

    def report_approval(self, job_id, decision) -> None:
        self.timeline.append("approval")
        super().report_approval(job_id, decision)

    def report_progress(self, job_id, stage, progress, statistics) -> None:
        self.timeline.append(f"progress:{job_id}:{stage.value}")
        super().report_progress(job_id, stage, progress, statistics)


class LocalBankTransport:
    def __init__(self, *, vulnerable: bool) -> None:
        self.vulnerable = vulnerable
        self.requests: list[dict[str, object]] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content) if request.content else {}
        authorization = request.headers.get("authorization", "")
        self.requests.append(
            {
                "method": request.method,
                "scheme": request.url.scheme,
                "host": request.url.host,
                "path": request.url.path,
                "query": dict(request.url.params),
                "authorization": authorization,
            }
        )
        if request.method == "POST" and request.url.path == "/api/login":
            actor = "a" if body["username"] == "fixture-user-a" else "b"
            return httpx.Response(
                200,
                json={"access_token": f"token-{actor}"},
                headers={"set-cookie": f"session=cookie-{actor}; HttpOnly"},
                request=request,
            )
        if request.url.path == "/openapi.json":
            return httpx.Response(200, json=openapi_document(), request=request)
        if request.url.path in {
            "/swagger.json",
            "/api/openapi.json",
            "/api/swagger.json",
        }:
            return httpx.Response(404, json={}, request=request)

        actor = "b" if authorization == "Bearer token-b" else "a"
        account_id = f"acct-{actor}-1"
        if request.url.path == "/api/accounts":
            return httpx.Response(
                200,
                json={
                    "items": [
                        {"account_id": account_id, "display_name": f"actor-{actor}"}
                    ]
                },
                request=request,
            )
        if request.url.path.startswith("/api/accounts/"):
            requested_id = request.url.path.rsplit("/", 1)[-1]
            if requested_id == "acct-b-1" and actor == "a" and not self.vulnerable:
                return httpx.Response(403, json={"detail": "forbidden"}, request=request)
            return httpx.Response(
                200,
                json={"account_id": requested_id, "display_name": "account"},
                request=request,
            )
        if request.url.path == "/api/search":
            page = request.url.params.get("page")
            if page == "-1" and self.vulnerable:
                account_id = "acct-b-1"
            elif page == "-1":
                return httpx.Response(400, json={"detail": "invalid"}, request=request)
            return httpx.Response(
                200,
                json={"items": [{"account_id": account_id}]},
                request=request,
            )
        if request.url.path == "/api/profile":
            password = "clear-profile-secret" if self.vulnerable else "********"
            return httpx.Response(
                200,
                json={"display_name": f"actor-{actor}", "password": password},
                request=request,
            )
        return httpx.Response(404, json={}, request=request)


@pytest.fixture(autouse=True)
def credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("USER_A_USERNAME", "fixture-user-a")
    monkeypatch.setenv("USER_A_PASSWORD", "pw-a")
    monkeypatch.setenv("USER_B_USERNAME", "fixture-user-b")
    monkeypatch.setenv("USER_B_PASSWORD", "pw-b")


@pytest.mark.parametrize(
    ("vulnerable", "expected_types"),
    [
        (
            True,
            {
                VulnerabilityType.BOLA,
                VulnerabilityType.INPUT_VALIDATION,
                VulnerabilityType.DATA_EXPOSURE,
            },
        ),
        (False, set()),
    ],
)
def test_complete_local_discovery_and_execution_flow_is_fixed_rule_safe_and_secret_free(
    vulnerable: bool,
    expected_types: set[VulnerabilityType],
) -> None:
    backend = RecordingBackend()
    audit = InMemoryAuditSink()
    bank = LocalBankTransport(vulnerable=vulnerable)
    scanner = Scanner(
        backend,
        transport=httpx.MockTransport(bank.handler),
        katana_runner=NoopKatana(),
        audit_sink=audit,
    )

    discovery = scanner.run_discovery(
        DiscoveryJobRequest(
            job_id=DISCOVERY_JOB_ID,
            scan_id=SCAN_ID,
            target_profile=ContractSource(inline=profile_payload()),
        )
    )
    execution = scanner.run_execution(
        ExecutionJobRequest(
            job_id=EXECUTION_JOB_ID,
            scan_id=SCAN_ID,
            target_profile=ContractSource(inline=profile_payload()),
            normalized_api_graph=ContractSource(
                inline=discovery.graph.model_dump(mode="json")
            ),
            relationship_analysis=ContractSource(inline=analysis_payload()),
            scan_plan=ContractSource(
                inline=plan_payload(discovery.requests_used)
            ),
        )
    )

    assert execution.scan_result is not None
    assert {
        finding.vulnerability_type for finding in execution.scan_result.findings
    } == expected_types
    expected_rules = {
        VulnerabilityType.BOLA: "VERIFY-BOLA-001",
        VulnerabilityType.INPUT_VALIDATION: "VERIFY-INPUT-001",
        VulnerabilityType.DATA_EXPOSURE: "VERIFY-DATA-001",
    }
    assert {
        finding.verification.rule_id
        for finding in execution.scan_result.findings
    } == {expected_rules[item] for item in expected_types}
    assert execution.scan_result.schema_version == "1.2"
    assert execution.result_artifact_ref is not None

    assert all(
        request["scheme"] == "http"
        and request["host"] == "vuln-bank.local"
        and (
            request["path"] == "/openapi.json"
            or str(request["path"]).startswith("/api/")
        )
        for request in bank.requests
    )
    active = [
        request
        for request in bank.requests
        if request["path"] != "/api/login"
    ]
    assert all(request["method"] == "GET" for request in active)
    assert [request["method"] for request in bank.requests].count("POST") == 2
    assert not any(
        forbidden in repr((execution.scan_result, backend.published))
        for forbidden in ("AUTHN-001", "TRANSACTION-001")
    )

    execution_stages = [
        event.stage
        for event in backend.progress_events
        if event.job_id == EXECUTION_JOB_ID
    ]
    assert execution_stages == [
        ScannerStage.PROFILE_LOADING,
        ScannerStage.POLICY_VALIDATION,
        ScannerStage.EXECUTING,
        ScannerStage.VERIFYING,
        ScannerStage.COMPLETED,
    ]
    assert backend.timeline.index("approval") < backend.timeline.index(
        "artifact:scan_result"
    )
    assert backend.timeline.index("artifact:scan_result") < backend.timeline.index(
        f"progress:{EXECUTION_JOB_ID}:COMPLETED"
    )

    structural = "".join(
        envelope.content.decode("utf-8")
        for envelope in backend.published
        if envelope.artifact_type in {"normalized_api_graph", "scan_result"}
    )
    rendered = json.dumps(
        {
            "graph": discovery.graph.model_dump(mode="json"),
            "result": execution.scan_result.model_dump(mode="json"),
            "artifacts": [
                envelope.content.decode("utf-8") for envelope in backend.published
            ],
            "audit": repr(audit.events),
            "errors": repr(backend.error_reports),
            "scanner": repr(scanner),
            "backend": repr(backend),
        },
        sort_keys=True,
    )
    assert "verdict" not in structural
    assert "severity" not in structural
    for runtime_value in RUNTIME_VALUES:
        assert runtime_value not in rendered


def test_exact_short_runtime_plan_id_is_blocked_before_approval_report() -> None:
    backend = RecordingBackend()
    bank = LocalBankTransport(vulnerable=False)
    scanner = Scanner(
        backend,
        transport=httpx.MockTransport(bank.handler),
        katana_runner=NoopKatana(),
    )
    discovery = scanner.run_discovery(
        DiscoveryJobRequest(
            job_id=DISCOVERY_JOB_ID,
            scan_id=SCAN_ID,
            target_profile=ContractSource(inline=profile_payload()),
        )
    )
    plan = plan_payload(discovery.requests_used)
    plan["plan_id"] = "1"
    plan["steps"] = []
    plan["budget"]["estimated_execution_requests"] = 0  # type: ignore[index]

    with pytest.raises(ExecutionJobError, match="^execution contract is invalid$"):
        scanner.run_execution(
            ExecutionJobRequest(
                job_id=EXECUTION_JOB_ID,
                scan_id=SCAN_ID,
                target_profile=ContractSource(inline=profile_payload()),
                normalized_api_graph=ContractSource(
                    inline=discovery.graph.model_dump(mode="json")
                ),
                relationship_analysis=ContractSource(inline=analysis_payload()),
                scan_plan=ContractSource(inline=plan),
            )
        )

    assert backend.approval_events == []
    assert not any(
        envelope.artifact_type == "scan_result"
        for envelope in backend.published
    )
