# Notion-Specified API Vulnerability Scanner Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the scanner-only Python worker that discovers vuln-bank APIs, preserves secret A/B runtime state in memory, lets its Executor approve or reject LLM scan plans, runs only BOLA, non-state-changing input validation, and data exposure probes, and publishes verified-only results through a backend integration port.

**Architecture:** A synchronous Python package separates strict JSON contracts, backend integration ports, redacted artifacts, request policy, authenticated discovery, fixed-rule modules, Executor approval, and job orchestration. Discovery and Execution are separate worker entry points; backend and LLM implementations are injected or represented only by protocols/fakes. The original `scan_plan.json` stays `PENDING_APPROVAL`, while Executor produces its own immutable `APPROVED` or `REJECTED` decision.

**Tech Stack:** Python 3.11+, Pydantic 2, HTTPX, pytest, standard-library subprocess/JSON/hashlib/pathlib/tempfile

## Global Constraints

- Work only on `feature/scanner`.
- Do not implement backend REST APIs, database models, queues, LLM calls/prompts, frontend code, AI reports, PDF reports, or severity calculation.
- External contract versions are exactly: Target Profile 1.1, Normalized API Graph 1.1, Relationship Analysis 1.2, Scan Plan 1.2, Scan Result 1.2.
- Active policy-to-plan mappings are exactly `authz -> BOLA-001`, `input_validation -> INPUT-001`, and `data_exposure -> DATA-001`.
- `AUTHN-001`, Transaction, unknown modules, state-changing probes, and non-GET active requests must never reach the network.
- Executor is the final plan approval or rejection authority.
- Do not mutate the original `scan_plan.json.status=PENDING_APPROVAL`.
- Do not create `scanner/verifier.py`, `runtime_scan_context.json`, or `execution_evidence.json`.
- `normalized_api_graph.json` contains only operation ID, method, path template, inputs, and outputs from the v1.1 contract.
- Actual credentials, tokens, cookies, object IDs, observed parameter values, and raw response values must never appear in external JSON, logs, exceptions, or stored artifacts.
- `scan_result.json` contains verified findings only and must not contain `verdict` or `severity`.
- All tests are local-only. Use HTTPX MockTransport, Fake BackendClient, and Fake Katana; never scan an external target.

---

## File Map

```text
pyproject.toml
scanner/__init__.py
scanner/contracts.py
scanner/audit.py
scanner/artifacts.py
scanner/policy.py
scanner/http_client.py
scanner/auth/__init__.py
scanner/auth/session_manager.py
scanner/crawler/__init__.py
scanner/crawler/normalizer.py
scanner/crawler/katana_runner.py
scanner/modules/__init__.py
scanner/modules/base.py
scanner/modules/bola.py
scanner/modules/input_validation.py
scanner/modules/data_exposure.py
scanner/modules/auth.py
scanner/integration/__init__.py
scanner/integration/backend_client.py
scanner/executor.py
scanner/scanner.py
tests/
```

---

### Task 1: Package Bootstrap and Exact External Contracts

**Files:**
- Create: `pyproject.toml`
- Create: `scanner/__init__.py`
- Create: `scanner/contracts.py`
- Create: `tests/test_contracts.py`

**Interfaces:**
- Consumes: no earlier interfaces
- Produces: all strict external JSON models, job source models, module enums, finding models, `ApprovalStatus`, `PlanApprovalDecision`

- [ ] **Step 1: Add packaging metadata**

Create `pyproject.toml`:

```toml
[build-system]
requires = ["setuptools>=75"]
build-backend = "setuptools.build_meta"

[project]
name = "api-vuln-scanner"
version = "0.1.0"
requires-python = ">=3.11"
dependencies = [
  "httpx>=0.27,<1",
  "pydantic>=2.8,<3",
]

[project.optional-dependencies]
dev = ["pytest>=8,<9"]

[tool.pytest.ini_options]
testpaths = ["tests"]
addopts = "-ra"
```

- [ ] **Step 2: Write failing contract tests**

Test exact versions, fields, extra-field rejection, actor constraints, and no forbidden
Graph/Result fields:

```python
from pydantic import ValidationError
import pytest

from scanner.contracts import (
    ModuleId,
    NormalizedApiGraph,
    ScanResult,
    TargetProfile,
)


def target_profile_payload() -> dict:
    return {
        "schema_version": "1.1",
        "scan_id": "scan-001",
        "target": {
            "base_url": "http://vuln-bank.local",
            "allowed_paths": ["/api/*", "/openapi.json"],
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
            "approved_modules": ["authz", "input_validation", "data_exposure"],
        },
    }


def test_target_profile_accepts_only_version_11_and_two_fixed_actors():
    profile = TargetProfile.model_validate(target_profile_payload())
    assert profile.schema_version == "1.1"
    assert {actor.actor_id for actor in profile.authentication.actors} == {
        "user_a",
        "user_b",
    }


def test_target_profile_rejects_unknown_policy_module_and_extra_field():
    payload = target_profile_payload()
    payload["safety_policy"]["approved_modules"] = ["transaction"]
    with pytest.raises(ValidationError):
        TargetProfile.model_validate(payload)
    payload = target_profile_payload()
    payload["unexpected"] = True
    with pytest.raises(ValidationError):
        TargetProfile.model_validate(payload)


def test_graph_and_result_have_only_fixed_contract_fields():
    graph = NormalizedApiGraph(scan_id="scan-001", operations=[])
    result = ScanResult(scan_id="scan-001", findings=[])
    assert graph.model_dump() == {
        "schema_version": "1.1",
        "scan_id": "scan-001",
        "operations": [],
    }
    assert result.model_dump() == {
        "schema_version": "1.2",
        "scan_id": "scan-001",
        "findings": [],
    }
    assert ModuleId.BOLA.value == "BOLA-001"
```

- [ ] **Step 3: Run the tests to verify failure**

Run:

```powershell
python -m venv .venv
.\.venv\Scripts\python -m pip install -e ".[dev]"
.\.venv\Scripts\python -m pytest tests/test_contracts.py -v
```

Expected: collection fails because `scanner.contracts` does not exist.

- [ ] **Step 4: Implement strict shared and Target Profile models**

Use `ConfigDict(extra="forbid")`. Define:

```python
class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class PolicyModule(StrEnum):
    AUTHZ = "authz"
    INPUT_VALIDATION = "input_validation"
    DATA_EXPOSURE = "data_exposure"


class ModuleId(StrEnum):
    BOLA = "BOLA-001"
    AUTHN = "AUTHN-001"
    INPUT = "INPUT-001"
    DATA = "DATA-001"
```

Create the complete v1.1 Target Profile hierarchy:

```text
TargetProfile(
    schema_version: Literal["1.1"],
    scan_id: str,
    target: TargetConfig,
    discovery: DiscoveryConfig,
    authentication: AuthenticationConfig,
    safety_policy: SafetyPolicy,
)
```

Use exact documented nested fields. Normalize methods to uppercase. Require positive
`max_requests`, positive integer `requests_per_second`, exactly the actor ID set
`{"user_a", "user_b"}`, unique approved modules, HTTP(S) base URL, and
`state_change_policy: Literal["deny"]`.

- [ ] **Step 5: Implement exact Graph, Relationship, Plan, and Result models**

Define Graph fields without internal metadata:

```python
class InputField(StrictModel):
    location: Literal["path", "query", "header", "body"]
    field_path: str
    type: Literal["string", "integer", "number", "boolean", "object", "array", "unknown"]


class OutputField(StrictModel):
    field_path: str
    type: Literal["string", "integer", "number", "boolean", "object", "array", "unknown"]


class Operation(StrictModel):
    operation_id: str
    method: str
    path_template: str
    inputs: list[InputField]
    outputs: list[OutputField]


class NormalizedApiGraph(StrictModel):
    schema_version: Literal["1.1"] = "1.1"
    scan_id: str
    operations: list[Operation]
```

Implement every documented field for:

```python
class Relationship(StrictModel):
    relationship_id: str
    source_operation_id: str
    target_operation_id: str
    source_field: str | None = None
    target_parameter: str | None = None
    target_parameter_location: Literal["path", "query", "header", "body"] | None = None
    relationship_type: Literal["id_flow", "ownership", "call_order", "data_flow"]
    confidence: float = Field(ge=0.5, le=1.0)


class BindingHint(StrictModel):
    parameter: str
    location: Literal["path", "query", "header", "body"]
    binding_type: Literal["object_binding", "parameter_binding"]
    object_type: str | None = None


class TestCandidate(StrictModel):
    candidate_id: str
    module_id: str
    target_operation_id: str
    required_object_types: list[str]
    rationale: str
    priority: int
    executable: bool
    missing_requirements: list[str]
    binding_hints: list[BindingHint]


class RelationshipAnalysis(StrictModel):
    schema_version: Literal["1.2"]
    scan_id: str
    model_name: str
    prompt_version: str
    prompt_sha256: str
    approved_module_ids: list[str]
    relationships: list[Relationship]
    test_candidates: list[TestCandidate]


class PlanBudget(StrictModel):
    requests_already_used: int = Field(ge=0)
    estimated_execution_requests: int = Field(ge=0)
    max_requests: int = Field(gt=0)
    within_budget: bool


class TargetEndpoint(StrictModel):
    method: str
    path_template: str


class InputBinding(StrictModel):
    parameter: str
    location: Literal["path", "query", "header", "body"]
    binding_type: Literal["object_binding", "parameter_binding"]
    object_type: str | None = None
    owner: Literal["user_a", "user_b"] | None = None


class ScanStep(StrictModel):
    order: int = Field(gt=0)
    candidate_id: str
    module_id: str
    target_operation_id: str
    target_endpoint: TargetEndpoint
    input_bindings: list[InputBinding]


class ScanPlan(StrictModel):
    schema_version: Literal["1.2"]
    plan_id: str
    scan_id: str
    model_name: str
    prompt_version: str
    prompt_sha256: str
    status: Literal["PENDING_APPROVAL"]
    budget: PlanBudget
    steps: list[ScanStep]
```

Use these exact vulnerability enums, then add result models with the exact fields:

```python
class VulnerabilityType(StrEnum):
    BOLA = "BOLA"
    INPUT_VALIDATION = "INPUT_VALIDATION"
    DATA_EXPOSURE = "DATA_EXPOSURE"


class Verification(StrictModel):
    rule_id: str
    verified_conditions: list[str]


class AffectedField(StrictModel):
    location: Literal["request", "response"]
    field_path: str
    data_class: Literal[
        "identity", "account", "financial", "authentication", "transaction", "other"
    ]


class Finding(StrictModel):
    finding_id: str
    operation_id: str
    vulnerability_type: VulnerabilityType
    verification: Verification
    affected_fields: list[AffectedField]
    evidence_refs: list[str]


class ScanResult(StrictModel):
    schema_version: Literal["1.2"] = "1.2"
    scan_id: str
    findings: list[Finding]
```

Do not add `required`, `security`, `requests_used`, `verdict`, or `severity` to external
contracts.

- [ ] **Step 6: Add internal contract source and Job request models**

Define an exactly-one source:

```python
class ContractSource(StrictModel):
    inline: dict[str, object] | None = None
    artifact_ref: str | None = None
```

Add a model validator requiring exactly one field. Define:

```text
DiscoveryJobRequest(job_id: str, scan_id: str, target_profile: ContractSource)
ExecutionJobRequest(
    job_id: str,
    scan_id: str,
    target_profile: ContractSource,
    normalized_api_graph: ContractSource,
    relationship_analysis: ContractSource,
    scan_plan: ContractSource,
)
```

Define Executor-owned approval types here so integration ports can consume them without a
dependency on `executor.py`:

```python
class ApprovalStatus(StrEnum):
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"


@dataclass(frozen=True)
class PlanApprovalDecision:
    scan_id: str
    plan_id: str
    status: ApprovalStatus
    reason_codes: tuple[str, ...]
```

- [ ] **Step 7: Run contract tests**

Run: `.\.venv\Scripts\python -m pytest tests/test_contracts.py -v`

Expected: all tests pass.

- [ ] **Step 8: Commit**

```powershell
git add pyproject.toml scanner/__init__.py scanner/contracts.py tests/test_contracts.py
git commit -m "feat(scanner): add exact JSON contracts"
```

---

### Task 2: Backend Integration Port, Audit Events, and Redacted Artifacts

**Files:**
- Create: `scanner/integration/__init__.py`
- Create: `scanner/integration/backend_client.py`
- Create: `scanner/audit.py`
- Create: `scanner/artifacts.py`
- Create: `tests/integration/test_backend_client.py`
- Create: `tests/test_artifacts.py`

**Interfaces:**
- Consumes: contract/job identifiers from Task 1
- Produces: `BackendClient`, `FakeBackendClient`, `ScannerStage`, `ScannerErrorReport`, `AuditSink`, `Redactor`, `ArtifactEnvelope`, `ArtifactBuilder`

- [ ] **Step 1: Write failing BackendClient port tests**

Test the Fake implementation without any HTTP server:

```python
def test_fake_backend_stores_progress_approval_artifacts_and_cancel_state():
    backend = FakeBackendClient()
    approved_decision = PlanApprovalDecision(
        scan_id="scan-001",
        plan_id="plan-001",
        status=ApprovalStatus.APPROVED,
        reason_codes=(),
    )
    content = b'{"schema_version":"1.1","scan_id":"scan-001","operations":[]}'
    artifact_envelope = ArtifactEnvelope(
        scan_id="scan-001",
        artifact_type="normalized_api_graph",
        schema_version="1.1",
        content=content,
        sha256=hashlib.sha256(content).hexdigest(),
        size=len(content),
    )
    backend.set_artifact("profile:1", b'{"schema_version":"1.1"}')
    assert backend.fetch_artifact("profile:1") == b'{"schema_version":"1.1"}'

    backend.report_progress("job-1", ScannerStage.AUTHENTICATING, 20, {"actors": 1})
    backend.report_approval("job-1", approved_decision)
    ref = backend.publish_artifact(artifact_envelope)
    backend.cancel("job-1")

    assert ref.startswith("artifact:")
    assert backend.is_cancelled("job-1") is True
    assert backend.progress_events[-1].progress == 20
    assert backend.approval_decisions[-1].status == ApprovalStatus.APPROVED
```

Verify repeated upload of the same scan/type/checksum is idempotent.

- [ ] **Step 2: Implement the integration Protocol and Fake**

Expose these exact methods:

```text
BackendClient.fetch_artifact(ref: str) -> bytes
BackendClient.get_requests_used(job_id: str) -> int
BackendClient.report_progress(
    job_id: str,
    stage: ScannerStage,
    progress: int,
    statistics: Mapping[str, int],
) -> None
BackendClient.report_approval(job_id: str, decision: PlanApprovalDecision) -> None
BackendClient.publish_artifact(envelope: ArtifactEnvelope) -> str
BackendClient.report_error(job_id: str, report: ScannerErrorReport) -> None
BackendClient.is_cancelled(job_id: str) -> bool
```

`FakeBackendClient` stores values in memory. It must not implement a REST endpoint, DB,
queue, service token issuance, or request signing.

Define stages and error reports:

```python
class ScannerStage(StrEnum):
    PROFILE_LOADING = "PROFILE_LOADING"
    AUTHENTICATING = "AUTHENTICATING"
    DISCOVERING = "DISCOVERING"
    NORMALIZING = "NORMALIZING"
    OBJECT_DISCOVERY = "OBJECT_DISCOVERY"
    POLICY_VALIDATION = "POLICY_VALIDATION"
    EXECUTING = "EXECUTING"
    VERIFYING = "VERIFYING"
    COMPLETED = "COMPLETED"
    CANCELED = "CANCELED"


@dataclass(frozen=True)
class ScannerErrorReport:
    code: str
    stage: ScannerStage
    retryable: bool
```

- [ ] **Step 3: Write failing redaction and artifact tests**

```python
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
```

- [ ] **Step 4: Implement audit, redaction, and artifact building**

Redact mapping values for case-insensitive keys:

```text
authorization, cookie, set-cookie, password, passwd, token, access_token,
refresh_token, secret, api_key, pin, cvv, session
```

Recursively redact exact runtime sensitive values in mappings, sequences, strings, URLs,
and exception details. Serialize with sorted keys and compact separators.

Define:

```text
ArtifactEnvelope(
    scan_id: str,
    artifact_type: str,
    schema_version: str | None,
    content: bytes,
    sha256: str,
    size: int,
)
AuditEvent(code, level, job_id, scan_id, operation_id, module_id, details)
AuditSink.emit(event) -> None
InMemoryAuditSink
```

- [ ] **Step 5: Run focused tests**

Run:

```powershell
.\.venv\Scripts\python -m pytest tests/integration/test_backend_client.py tests/test_artifacts.py -v
```

Expected: all tests pass.

- [ ] **Step 6: Commit**

```powershell
git add scanner/integration scanner/audit.py scanner/artifacts.py tests/integration tests/test_artifacts.py
git commit -m "feat(scanner): add backend port and redacted artifacts"
```

---

### Task 3: Scope Policy, Request Budget, Rate Limit, and Cancellation

**Files:**
- Create: `scanner/policy.py`
- Create: `scanner/http_client.py`
- Create: `tests/test_policy.py`
- Create: `tests/test_http_client.py`

**Interfaces:**
- Consumes: `TargetProfile`, policy modules, `BackendClient`, `Redactor`, `AuditSink`
- Produces: `PolicyEnforcer`, `RequestBudget`, `BudgetLease`, `CancellationGuard`, `SafeHttpClient`, `ResponseSnapshot`

- [ ] **Step 1: Write failing PolicyEnforcer tests**

Cover:

```python
def test_login_bypasses_active_method_only(profile):
    policy.authorize(
        "POST",
        "http://vuln-bank.local/api/login",
        module_id=None,
        is_login=True,
        is_state_change=False,
    )
    with pytest.raises(PolicyViolation):
        policy.authorize(
            "POST",
            "http://attacker.local/api/login",
            module_id=None,
            is_login=True,
            is_state_change=False,
        )


def test_authn_transaction_and_post_probe_are_denied(profile):
    for module_id in ("AUTHN-001", "TRANSACTION-001"):
        with pytest.raises(PolicyViolation):
            policy.authorize(
                "GET",
                "http://vuln-bank.local/api/accounts",
                module_id=module_id,
                is_login=False,
                is_state_change=False,
            )
    with pytest.raises(PolicyViolation):
        policy.authorize(
            "POST",
            "http://vuln-bank.local/api/accounts",
            module_id="INPUT-001",
            is_login=False,
            is_state_change=True,
        )
```

Also test path normalization/traversal, user-info URLs, fragments, exact origin, allowed
path patterns, request count restore, last allowed request, overflow, deterministic RPS
sleep, cancellation before reserve, and a Katana lease that blocks other reservations and
consumes its full allowance when closed.

- [ ] **Step 2: Run policy tests to verify failure**

Run: `.\.venv\Scripts\python -m pytest tests/test_policy.py -v`

Expected: import failure for `scanner.policy`.

- [ ] **Step 3: Implement policy and cancellation**

Use `urllib.parse.urlsplit`, `posixpath.normpath`, and `fnmatch.fnmatchcase`. Define:

```text
PolicyEnforcer.authorize(
    method: str,
    url: str,
    *,
    module_id: str | None,
    is_login: bool,
    is_state_change: bool,
) -> None
RequestBudget.restore(value: int) -> None
RequestBudget.reserve() -> None
RequestBudget.lease(max_requests: int) -> BudgetLease
RequestBudget.requests_used -> int
BudgetLease.close() -> None
CancellationGuard.raise_if_cancelled(job_id: str) -> None
```

`reserve()` checks cancellation, applies injected clock/sleeper rate limiting, rejects
overflow, then increments. Login is exempt only from active method/module checks, never
origin/path/budget/rate/cancel checks.

`lease()` reserves an exclusive upper bound for an external crawler without immediately
making that capacity available to direct HTTP requests. Closing the lease consumes its
full allowance, even if Katana emitted fewer JSONL records, because failed crawler requests
may not be observable. This conservative accounting can under-use the budget but can never
exceed `max_requests`.

- [ ] **Step 4: Write failing SafeHttpClient tests**

Use `httpx.MockTransport` counters. Verify:

- rejected policy results in zero transport calls;
- allowed GET results in one call and one budget increment;
- same-origin allowed redirect gets a second full policy check;
- external or disallowed-path redirect performs no second transport call;
- cancellation after the first redirect prevents the second request;
- network/timeout exceptions become sanitized `ScannerRequestError`;
- Authorization and Cookie never appear in snapshot headers or errors.

- [ ] **Step 5: Implement policy-enforced HTTP**

Define:

```python
@dataclass(frozen=True)
class ResponseSnapshot:
    status_code: int
    headers: Mapping[str, str]
    cookies: Mapping[str, str]
    json_body: object | None
    url: str

    @property
    def is_success(self) -> bool:
        return 200 <= self.status_code < 300
```

Expose:

```text
SafeHttpClient.request(
    method: str,
    url: str,
    *,
    module_id: str | None = None,
    is_login: bool = False,
    is_state_change: bool = False,
    headers: Mapping[str, str] | None = None,
    params: Mapping[str, object] | None = None,
    json_body: object | None = None,
    sensitive_values: set[str] | None = None,
) -> ResponseSnapshot
```

Use `follow_redirects=False`; resolve Location manually; re-authorize and reserve every
hop. Do not retry inside this client.

- [ ] **Step 6: Run policy and HTTP tests**

Run:

```powershell
.\.venv\Scripts\python -m pytest tests/test_policy.py tests/test_http_client.py -v
```

Expected: all tests pass.

- [ ] **Step 7: Commit**

```powershell
git add scanner/policy.py scanner/http_client.py tests/test_policy.py tests/test_http_client.py
git commit -m "feat(scanner): enforce safe request policy"
```

---

### Task 4: Secret Runtime Context and A/B Session Management

**Files:**
- Create: `scanner/auth/__init__.py`
- Create: `scanner/auth/session_manager.py`
- Create: `tests/auth/test_session_manager.py`

**Interfaces:**
- Consumes: `TargetProfile`, `SafeHttpClient`
- Produces: `ActorSession`, `RuntimeDiscoveryMetadata`, `RuntimeContext`, `SessionManager`

- [ ] **Step 1: Write failing login and secret isolation tests**

Monkeypatch the four credential environment variables and MockTransport login responses:

```python
runtime = manager.authenticate(profile)
assert set(runtime.sessions) == {"user_a", "user_b"}
assert runtime.sessions["user_a"].authorization_headers() == {
    "Authorization": "Bearer token-a"
}
assert "token-a" not in repr(runtime.sessions["user_a"])
assert runtime.sensitive_values() >= {
    "user-a", "user-b", "pw-a", "pw-b", "token-a", "token-b"
}
```

Test missing env variables, failed login, missing token field, non-JSON response, and
exception redaction.

- [ ] **Step 2: Write failing object and input-example collection tests**

```python
manager.collect_response(
    runtime,
    actor_id="user_b",
    operation_id="GET:/api/accounts",
    body={
        "items": [{"account_id": "acct-b-1"}],
        "next_page": 2,
    },
    observed_query={"page": "1"},
)
assert runtime.object_ids["user_b"]["account"] == {"acct-b-1"}
assert runtime.parameter_examples[
    ("GET:/api/accounts", "query", "page")
] == {"1"}
```

Ensure Runtime Context cannot be serialized with Pydantic or JSON and all secret fields
use `repr=False`.

- [ ] **Step 3: Implement Runtime Context and authentication**

Define dataclasses:

```python
@dataclass
class ActorSession:
    actor_id: Literal["user_a", "user_b"]
    token: str | None = field(default=None, repr=False)
    cookies: dict[str, str] = field(default_factory=dict, repr=False)


@dataclass
class RuntimeContext:
    scan_id: str
    sessions: dict[str, ActorSession] = field(default_factory=dict, repr=False)
    credentials: set[str] = field(default_factory=set, repr=False)
    object_ids: dict[str, dict[str, set[str]]] = field(default_factory=dict, repr=False)
    parameter_examples: dict[
        tuple[str, str, str], set[str]
    ] = field(default_factory=dict, repr=False)
    required_inputs: dict[str, set[tuple[str, str]]] = field(
        default_factory=dict,
        repr=False,
    )
```

`RuntimeContext.sensitive_values()` returns credentials, tokens, cookies, and all object
IDs. `SessionManager.authenticate()` resolves configured env references and uses the login
method/path/body/session field exactly as documented.

Recursively collect scalar `account_id`, `transaction_id`, and `card_id` values under
canonical object types. Store observed OpenAPI/Katana examples privately.

- [ ] **Step 4: Run session tests**

Run: `.\.venv\Scripts\python -m pytest tests/auth/test_session_manager.py -v`

Expected: all tests pass.

- [ ] **Step 5: Commit**

```powershell
git add scanner/auth tests/auth
git commit -m "feat(scanner): isolate actor runtime sessions"
```

---

### Task 5: OpenAPI/Katana Normalization and Safe Katana Runner

**Files:**
- Create: `scanner/crawler/__init__.py`
- Create: `scanner/crawler/normalizer.py`
- Create: `scanner/crawler/katana_runner.py`
- Create: `tests/crawler/test_normalizer.py`
- Create: `tests/crawler/test_katana_runner.py`

**Interfaces:**
- Consumes: Graph contracts, `RuntimeContext`, cancellation and budget interfaces
- Produces: `KatanaRecord`, `KatanaRunResult`, `KatanaRunner`, `normalize_openapi()`, `merge_katana_records()`, `infer_output_fields()`

- [ ] **Step 1: Write failing OpenAPI normalization tests**

Use an OpenAPI fixture containing list/detail GET operations, path/query parameters,
nested arrays, and a POST transfer. Assert:

- operation IDs are `METHOD:<path_template>`;
- path/query/header/body inputs have only location, field path, type;
- nested response paths use `items[].account_id`;
- no required/security/source/example fields enter Graph JSON;
- required flags and examples are stored in Runtime Context;
- operations sort deterministically;
- a Katana duplicate does not duplicate the OpenAPI operation;
- an out-of-scope operation is removed.

- [ ] **Step 2: Run normalizer tests to verify failure**

Run: `.\.venv\Scripts\python -m pytest tests/crawler/test_normalizer.py -v`

Expected: import failure for the normalizer.

- [ ] **Step 3: Implement deterministic normalization**

Expose:

```text
normalize_openapi(
    scan_id: str,
    document: Mapping[str, object],
    runtime: RuntimeContext,
) -> NormalizedApiGraph
merge_katana_records(
    graph: NormalizedApiGraph,
    records: Iterable[KatanaRecord],
) -> NormalizedApiGraph
infer_output_fields(value: object) -> list[OutputField]
```

Flatten OpenAPI JSON schemas recursively. Store default/example and required metadata only
in Runtime Context. Generalize numeric, UUID, and 16+ hex Katana path segments to stable
`{id}`, `{id_2}` templates only when no OpenAPI template already matches.

- [ ] **Step 4: Write failing Katana runner tests**

Inject a Fake process object and temporary directory. Verify exact argv includes:

```text
-c 1
-p 1
-rl <profile_rps>
-rlm <allocated_requests>
-ct 59
-retry 0
-jsonl
-omit-raw
-omit-body
```

Verify:

- A and B runs use different temporary Header files;
- token values are in the temporary files but not argv, audit, repr, or exceptions;
- header files are deleted after success, failure, and cancellation;
- scope regex is derived from same origin and allowed paths;
- non-zero exit raises a sanitized Katana error;
- cancellation terminates the process;
- no allocation means Katana is not started;
- JSONL request records become `requests_made`.

- [ ] **Step 5: Implement safe Katana subprocess execution**

Use `subprocess.Popen` without `shell=True`. Define:

```python
@dataclass(frozen=True)
class KatanaRecord:
    method: str
    url: str


@dataclass(frozen=True)
class KatanaRunResult:
    records: tuple[KatanaRecord, ...]
    requests_made: int
```

Create the Header file with `NamedTemporaryFile(delete=False)`, close before launching on
Windows, pass its path with `-H`, poll with finite timeouts, terminate on cancel, parse only
request method/endpoint, and delete the file in `finally`.

Acquire an exclusive `BudgetLease` before launch. Pass its allowance to Katana as the
per-minute maximum. Always close the lease in `finally`; the shared counter consumes the
full allowance once, never the JSONL count in addition. Keep `requests_made` only as a
collection statistic.

- [ ] **Step 6: Run crawler tests**

Run: `.\.venv\Scripts\python -m pytest tests/crawler -v`

Expected: all tests pass.

- [ ] **Step 7: Commit**

```powershell
git add scanner/crawler tests/crawler
git commit -m "feat(scanner): discover and normalize API operations"
```

---

### Task 6: Discovery Job Orchestration

**Files:**
- Create: `scanner/scanner.py`
- Modify: `scanner/__init__.py`
- Create: `tests/test_scanner_discovery.py`

**Interfaces:**
- Consumes: Tasks 1-5
- Produces: `Scanner.run_discovery()`, `DiscoveryOutcome`, contract-source loading

- [ ] **Step 1: Write failing contract-source loading tests**

Verify inline and artifact-ref Profile inputs both parse as v1.1, invalid JSON gets a
non-retryable error report, and request/job/Profile scan IDs must match.

- [ ] **Step 2: Write failing Discovery Job tests**

With MockTransport, Fake Katana, and Fake BackendClient verify:

- progress stages are reported in order;
- cancellation before authentication sends zero requests;
- A/B login occurs independently;
- allowed OpenAPI paths are probed in deterministic order;
- authenticated Katana runs for both actors;
- allowed GET list operations collect actor-specific objects;
- Graph is v1.1 and contains no secrets or runtime values;
- Graph Artifact metadata has checksum/size/schema;
- collection statistics are reported;
- OpenAPI success plus Katana failure succeeds with a warning;
- both Discovery sources failing reports a non-empty fixed error code;
- output `requests_used` equals the shared budget counter.

- [ ] **Step 3: Implement contract loading and Discovery outcome**

Define:

```python
@dataclass(frozen=True)
class DiscoveryOutcome:
    job_id: str
    scan_id: str
    graph: NormalizedApiGraph
    graph_artifact_ref: str
    available_object_types: tuple[str, ...]
    requests_used: int
```

Load `ContractSource.inline` directly or fetch `artifact_ref` from BackendClient and parse
with the requested Pydantic model. Never include raw payloads in validation errors.

- [ ] **Step 4: Implement `Scanner.run_discovery()`**

Signature:

```text
Scanner.run_discovery(request: DiscoveryJobRequest) -> DiscoveryOutcome
```

Order:

```text
cancel -> profile load -> policy setup -> A/B auth -> OpenAPI ->
Katana A/B -> normalize -> allowed GET object/output probing ->
Graph artifact publish -> progress complete
```

Retain Runtime Context and shared request budget privately by `scan_id`. Publish Graph
through ArtifactBuilder/BackendClient. Do not call an LLM.

- [ ] **Step 5: Run Discovery tests**

Run: `.\.venv\Scripts\python -m pytest tests/test_scanner_discovery.py -v`

Expected: all tests pass.

- [ ] **Step 6: Commit**

```powershell
git add scanner/scanner.py scanner/__init__.py tests/test_scanner_discovery.py
git commit -m "feat(scanner): orchestrate discovery jobs"
```

---

### Task 7: Module Base Types, Binding, and BOLA

**Files:**
- Create: `scanner/modules/__init__.py`
- Create: `scanner/modules/base.py`
- Create: `scanner/modules/bola.py`
- Create: `tests/modules/test_bindings.py`
- Create: `tests/modules/test_bola.py`

**Interfaces:**
- Consumes: Graph/Plan contracts, Runtime Context, SafeHttpClient
- Produces: `ModuleVerdict`, `ModuleOutcome`, `ModuleExecutionContext`, `bind_operation()`, `BolaModule`

- [ ] **Step 1: Write failing binding tests**

Test deterministic object binding:

```python
bound = bind_operation(
    operation=account_detail,
    bindings=[
        InputBinding(
            parameter="account_id",
            location="path",
            binding_type="object_binding",
            object_type="account",
            owner="user_b",
        )
    ],
    runtime=runtime,
)
assert bound.path == "/api/accounts/acct-b-1"
```

Unknown parameter, location mismatch, missing actor object, missing required input, and
unbound body input must raise `BindingError` before network.

- [ ] **Step 2: Implement module base types and binding**

Define:

```python
class ModuleVerdict(StrEnum):
    VERIFIED = "verified"
    NOT_FOUND = "not_found"
    INCONCLUSIVE = "inconclusive"


@dataclass(frozen=True)
class ModuleOutcome:
    verdict: ModuleVerdict
    rule_id: str
    conditions: tuple[str, ...] = ()
    affected_fields: tuple[AffectedField, ...] = ()
    evidence: Mapping[str, object] = field(default_factory=dict)
    reason_code: str | None = None
```

`bind_operation()` consumes declared Plan bindings only, selects a stable sorted runtime
value, URL-encodes path values, and never invents object IDs.

- [ ] **Step 3: Write failing BOLA fixed-rule tests**

Verify:

- A/A baseline 2xx and A/B variant containing B runtime object data -> verified;
- condition is `BOLA_FOREIGN_OBJECT_RETURNED`;
- rule is `VERIFY-BOLA-001`;
- all requests use A Authorization;
- 401/403/404 variant -> not_found;
- variant 2xx without identifiable B data -> not_found;
- baseline failure, missing A/B object, or non-JSON comparison -> inconclusive;
- 2xx alone never verifies.

- [ ] **Step 4: Implement `BolaModule.run()`**

Create baseline bindings by replacing B object owners with A. Run exactly two requests:
baseline A/A then variant A/B. Recursively compare variant scalar values and field paths
against B's runtime object context. Return evidence in memory; Artifact redaction happens
before publication.

- [ ] **Step 5: Run BOLA tests**

Run:

```powershell
.\.venv\Scripts\python -m pytest tests/modules/test_bindings.py tests/modules/test_bola.py -v
```

Expected: all tests pass.

- [ ] **Step 6: Commit**

```powershell
git add scanner/modules tests/modules/test_bindings.py tests/modules/test_bola.py
git commit -m "feat(scanner): add fixed-rule BOLA probe"
```

---

### Task 8: Input Validation and Data Exposure Fixed Rules

**Files:**
- Create: `scanner/modules/input_validation.py`
- Create: `scanner/modules/data_exposure.py`
- Create: `tests/modules/test_input_validation.py`
- Create: `tests/modules/test_data_exposure.py`

**Interfaces:**
- Consumes: module base types, Runtime Context examples, SafeHttpClient
- Produces: `InputValidationModule`, `DataExposureModule`, `find_sensitive_fields()`

- [ ] **Step 1: Write failing INPUT-001 tests**

Cover:

- observed query baseline `page=1` and numeric mutation `page=-1`;
- string example and deterministic invalid-format mutation;
- exactly baseline plus one variant request;
- invalid input rejected -> not_found;
- invalid input 2xx with no expanded object/sensitive fields -> not_found;
- invalid input 5xx only -> not_found;
- invalid input 2xx exposing a B-only object or new sensitive field -> verified;
- condition `INPUT_INVALID_VALUE_EXPANDED_SCOPE`;
- rule `VERIFY-INPUT-001`;
- missing baseline example/binding/comparison evidence -> inconclusive;
- body/header and state-changing inputs never run.

- [ ] **Step 2: Implement deterministic baseline and mutation**

Use OpenAPI default/example first, then sorted observed Katana query values. For numeric
types choose one mutation in order `-1`, `0`, then a bounded overflow candidate different
from baseline. For strings derive one stable invalid value from SHA-256 of operation ID and
field path. Execute only GET path/query inputs.

Compare canonical response field paths and runtime object values. Verify only when the
variant introduces a B-owned object or a sensitive field absent from baseline.

- [ ] **Step 3: Write failing DATA-001 classification tests**

Assert:

```python
assert find_sensitive_fields({"password": "cleartext"}) == [
    SensitiveField("password", "authentication")
]
assert find_sensitive_fields({"card_number": "4111111111111111"}) == [
    SensitiveField("card_number", "financial")
]
assert find_sensitive_fields({"card_number": "4111-****-****-1111"}) == []
assert find_sensitive_fields({"account_id": "acct-1"}) == []
```

Cover password hashes, token, API key, secret, PIN, CVV, resident number, full account
number, nested/list paths, empty values, masked values, and ordinary IDs.

- [ ] **Step 4: Implement sensitive classification and `DataExposureModule.run()`**

Require a successful authenticated JSON response. Use semantic key rules plus value-format
checks. Use Luhn validation for 13-19 digit card numbers. Do not classify ordinary
`*_id` values.

Return:

```text
verified: VERIFY-DATA-001 / DATA_SENSITIVE_FIELD_UNMASKED
not_found: successful response without a forbidden unmasked field
inconclusive: failed or non-JSON response
```

Execute exactly one request.

- [ ] **Step 5: Run focused module tests**

Run:

```powershell
.\.venv\Scripts\python -m pytest tests/modules/test_input_validation.py tests/modules/test_data_exposure.py -v
```

Expected: all tests pass.

- [ ] **Step 6: Commit**

```powershell
git add scanner/modules/input_validation.py scanner/modules/data_exposure.py tests/modules
git commit -m "feat(scanner): add input and exposure rules"
```

---

### Task 9: Executor Plan Approval and Rejection

**Files:**
- Create: `scanner/modules/auth.py`
- Create: `scanner/executor.py`
- Create: `tests/test_executor_approval.py`

**Interfaces:**
- Consumes: every contract including `ApprovalStatus` and `PlanApprovalDecision`, policy, Runtime Context, module registry
- Produces: `Executor.evaluate_plan()`

- [ ] **Step 1: Write failing module mapping tests**

```python
assert module_for_policy("authz") == "BOLA-001"
assert module_for_policy("input_validation") == "INPUT-001"
assert module_for_policy("data_exposure") == "DATA-001"
assert policy_for_module("AUTHN-001") is None
```

`scanner/modules/auth.py` must expose a disabled descriptor only. Calling its `run()` raises
`ModuleNotApproved` before any HTTP client method.

- [ ] **Step 2: Write failing approval tests**

Test one reason code at a time:

```text
PLAN_SCAN_ID_MISMATCH
PLAN_OPERATION_UNKNOWN
PLAN_CANDIDATE_UNKNOWN
PLAN_CANDIDATE_NOT_EXECUTABLE
PLAN_ENDPOINT_MISMATCH
PLAN_BINDING_MISMATCH
PLAN_STEP_ORDER_INVALID
PLAN_MODULE_NOT_APPROVED
PLAN_APPROVED_MODULE_SET_MISMATCH
PLAN_AUTHN_NOT_APPROVED
PLAN_METHOD_NOT_ALLOWED
PLAN_REQUEST_COUNT_STALE
PLAN_ESTIMATE_MISMATCH
PLAN_MAX_REQUESTS_MISMATCH
PLAN_BUDGET_FLAG_INVALID
PLAN_REQUEST_BUDGET_EXCEEDED
```

Assert rejection sends zero module/transport requests. Verify:

- all valid steps -> approved;
- one invalid step rejects the whole plan;
- empty steps -> approved;
- original `plan.status` remains `PENDING_APPROVAL`;
- BackendClient receives the same immutable decision.

- [ ] **Step 3: Implement atomic approval evaluation**

`Executor.evaluate_plan()` returns the Task 1 `PlanApprovalDecision` and validates every
document and Step before execution. Require `relationship_analysis.approved_module_ids` to
equal the Module ID set mapped from `target_profile.safety_policy.approved_modules`, and
require every Candidate Module ID to belong to that set. Recompute:

```python
REQUEST_ESTIMATES = {
    "BOLA-001": 2,
    "INPUT-001": 2,
    "DATA-001": 1,
}
```

Require:

```text
runtime_requests_used == budget.requests_already_used
sum(step estimates) == budget.estimated_execution_requests
profile.max_requests == budget.max_requests
budget.within_budget == (
    requests_already_used + estimated_execution_requests <= max_requests
)
budget.within_budget is True
```

Sort and deduplicate reason codes. Do not mutate Plan.

- [ ] **Step 4: Run approval tests**

Run: `.\.venv\Scripts\python -m pytest tests/test_executor_approval.py -v`

Expected: all tests pass.

- [ ] **Step 5: Commit**

```powershell
git add scanner/modules/auth.py scanner/executor.py tests/test_executor_approval.py
git commit -m "feat(scanner): approve or reject scan plans"
```

---

### Task 10: Executor Module Execution, Evidence, and Scan Result

**Files:**
- Modify: `scanner/executor.py`
- Create: `tests/test_executor_execution.py`

**Interfaces:**
- Consumes: approved plans, modules, ArtifactBuilder, BackendClient, AuditSink
- Produces: `Executor.execute()`, deterministic verified-only `ScanResult`

- [ ] **Step 1: Write failing routing and request-count tests**

With fake modules verify:

- approved Step routes to its exact module;
- rejected decision performs no execution;
- BOLA consumes 2, Input consumes 2, Data consumes 1;
- cancellation between steps stops remaining requests;
- budget exhaustion stops remaining steps and reports a stable error;
- `AUTHN-001`, Transaction, and unknown IDs never route.

- [ ] **Step 2: Write failing result assembly tests**

Provide outcomes:

- verified + successful evidence upload -> one Finding;
- not_found -> no Finding and audit event;
- inconclusive -> no Finding and reason event;
- verified + evidence upload failure -> no Finding and inconclusive event;
- duplicate deterministic Finding -> one Finding;
- empty plan -> `findings: []`.

Assert Finding ID is stable from scan, operation, rule, sorted conditions, and affected
field paths. Assert `evidence_refs` contains only BackendClient's opaque reference.
Assert Result JSON has neither verdict nor severity.

- [ ] **Step 3: Implement execution and result assembly**

Expose:

```text
Executor.execute(
    *,
    job_id: str,
    profile: TargetProfile,
    graph: NormalizedApiGraph,
    analysis: RelationshipAnalysis,
    plan: ScanPlan,
    runtime: RuntimeContext,
    decision: PlanApprovalDecision,
) -> ScanResult
```

Only `APPROVED` executes. Before each Step call cancellation and shared policy. Convert
policy, binding, request, and artifact errors to audit/error codes without raw exception
data.

For verified outcomes:

1. build redacted Evidence Artifact with Runtime Context sensitive values;
2. publish it through BackendClient;
3. create deterministic Finding;
4. deduplicate;
5. sort by `finding_id`.

- [ ] **Step 4: Run execution tests**

Run: `.\.venv\Scripts\python -m pytest tests/test_executor_execution.py -v`

Expected: all tests pass.

- [ ] **Step 5: Commit**

```powershell
git add scanner/executor.py tests/test_executor_execution.py
git commit -m "feat(scanner): execute approved fixed-rule modules"
```

---

### Task 11: Execution Job Orchestration and Full Local Integration

**Files:**
- Modify: `scanner/scanner.py`
- Modify: `scanner/__init__.py`
- Create: `tests/test_scanner_execution.py`
- Create: `tests/test_scanner_integration.py`

**Interfaces:**
- Consumes: all previous tasks
- Produces: `Scanner.run_execution()`, `ExecutionOutcome`, complete local Scanner flow

- [ ] **Step 1: Write failing Execution Job tests**

Verify:

- inline and Artifact-ref Graph/Analysis/Plan loading;
- all scan IDs match Job/Profile;
- retained Runtime Context is reused;
- missing Runtime Context restores backend request count, reauthenticates, and rejects the
  old Plan as `PLAN_REQUEST_COUNT_STALE`;
- approval decision is reported before module execution;
- rejected plan publishes no Scan Result;
- approved empty plan publishes a valid empty Result;
- approved non-empty plan publishes v1.2 Result metadata;
- Graph/Result artifact upload failure fails Job;
- cancellation before approval or between modules sends no subsequent requests;
- Scanner Job completion is separate from AI report completion.

- [ ] **Step 2: Implement `ExecutionOutcome` and `run_execution()`**

Define:

```python
@dataclass(frozen=True)
class ExecutionOutcome:
    job_id: str
    scan_id: str
    decision: PlanApprovalDecision
    scan_result: ScanResult | None
    result_artifact_ref: str | None
```

Signature:

```text
Scanner.run_execution(request: ExecutionJobRequest) -> ExecutionOutcome
```

Order:

```text
cancel -> load/validate contracts -> restore or rehydrate Runtime Context ->
Executor approval -> report decision -> if approved execute ->
publish Result -> report Scanner Job completion
```

Do not call an LLM or generate AI report data.

- [ ] **Step 3: Write full local vulnerable/safe integration tests**

Use one MockTransport representing:

- A/B login;
- OpenAPI list/detail/profile endpoints;
- actor-specific account IDs;
- safe and vulnerable BOLA variants;
- input baseline and invalid variant with/without scope expansion;
- masked and unmasked sensitive fields.

Use Fake Katana and Fake BackendClient. Run Discovery, construct Relationship/Plan objects
as if returned by LLM, then run Execution.

Assert:

- vulnerable flow produces only BOLA/Input/Data Finding types whose rules passed;
- safe flow produces no findings;
- no AUTHN/Transaction/non-GET request occurs;
- every request stays same-origin and allowed-path;
- progress and approval events are ordered;
- Graph, Result, Artifact, audit, error, repr, and serialized Fake backend state contain
  none of the fixture passwords, tokens, cookies, or raw object IDs.

- [ ] **Step 4: Run the complete test suite**

Run:

```powershell
.\.venv\Scripts\python -m pytest -v
```

Expected: all tests pass.

- [ ] **Step 5: Run package and leakage checks**

Run:

```powershell
.\.venv\Scripts\python -m compileall -q scanner tests
.\.venv\Scripts\python -m pip check
rg -n "token-a|token-b|pw-a|pw-b|cookie-a|cookie-b|acct-a-1|acct-b-1" scanner
```

Expected: compile and dependency checks exit 0; leakage scan has no production-code
matches.

- [ ] **Step 6: Audit scanner-only changed paths**

Run:

```powershell
git diff --name-only origin/feature/scanner...HEAD
git status --short --branch
git diff --check
```

Expected: implementation changes are limited to `scanner/`, `tests/`, `pyproject.toml`,
and `docs/superpowers/`. The previously user-deleted
`docs/superpowers/plans/2026-07-25-scanner.md` remains untouched unless the user separately
requests its removal commit.

- [ ] **Step 7: Commit**

```powershell
git add scanner/scanner.py scanner/__init__.py tests/test_scanner_execution.py tests/test_scanner_integration.py
git commit -m "feat(scanner): complete scanner job workflow"
```
