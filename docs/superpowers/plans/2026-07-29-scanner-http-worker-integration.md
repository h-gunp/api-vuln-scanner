# Scanner HTTP Worker Integration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Connect the existing single Scanner Discovery + Executor/Verifier worker to the backend through FastAPI jobs and an HTTP BackendClient, while preserving strict scanner-only scope, fixed JSON contracts, auditable evidence, and active-module safety.

**Architecture:** A FastAPI adapter accepts backend-generated jobs, atomically deduplicates `job_id`, and runs the existing synchronous Scanner in background threads. Scanner-to-backend calls carry explicit job and scan context into a stateless `HttpBackendClient`, which maps internal stages to backend stages and posts contract bodies. Evidence is constructed only through a typed allowlist model. Existing discovery, runtime state, policy, Executor, and fixed-rule modules remain the functional core.

**Tech Stack:** Python 3.11+, FastAPI, Uvicorn, HTTPX, Pydantic 2, pytest, Starlette TestClient, standard-library threading/hashlib/json/tomllib

## Global Constraints

- Work only on `feature/scanner`.
- Do not modify `docs/최종 JSON 데이터 계약.md`.
- Do not implement backend, LLM, frontend, database, queue, report, PDF, or a separate Executor service.
- Scanner remains the sole owner of Discovery and Executor/Verifier behavior.
- The original plan remains `status=PENDING_APPROVAL`; Scanner Executor decides approval or rejection.
- Only `BOLA-001`, `INPUT-001`, and `DATA-001` may appear as executable candidates or plan steps.
- Keep actual credentials, tokens, cookies, object IDs, response values, and concrete URL query data out of artifacts, callback payloads, logs, and exceptions.
- Use `httpx.MockTransport`; tests must not call external services.
- Follow Red-Green-Refactor for every behavior change.

---

### Task 1: Root Packaging and HTTP Runtime Dependencies

**Files:**
- Modify: `pyproject.toml`
- Create: `tests/test_packaging.py`

**Interfaces:**
- Produces: package discovery for `scanner*`, runtime HTTP dependencies, pytest dev extra
- Consumes: no scanner runtime interfaces

- [ ] **Step 1: Write the failing packaging test**

Add tests using `tomllib` that assert:

- `tool.setuptools.packages.find.include == ["scanner*"]`
- no fixed `tool.setuptools.packages` list exists
- project dependencies declare FastAPI, Uvicorn, HTTPX, and Pydantic
- dev dependencies declare pytest

- [ ] **Step 2: Run the focused test and verify RED**

Run:

```powershell
python -m pytest tests/test_packaging.py -q
```

Expected: failure because package discovery and HTTP dependencies are absent.

- [ ] **Step 3: Implement the minimal packaging change**

Update `pyproject.toml` with:

```toml
[tool.setuptools.packages.find]
include = ["scanner*"]
```

Declare compatible `fastapi`, `uvicorn`, `httpx`, `pydantic`, and pytest ranges.
Do not add `llm*` or `openai`.

- [ ] **Step 4: Run the focused test and verify GREEN**

Run:

```powershell
python -m pytest tests/test_packaging.py -q
```

- [ ] **Step 5: Commit**

```powershell
git add pyproject.toml tests/test_packaging.py
git commit -m "build(scanner): discover HTTP worker packages"
```

---

### Task 2: Strengthen External Contract Validation

**Files:**
- Modify: `scanner/contracts.py`
- Modify: `tests/test_contracts.py`

**Interfaces:**
- Produces: normalized operation identity, duplicate protection, active module types, binding cross-validation
- Consumes: immutable examples in `docs/최종 JSON 데이터 계약.md`

- [ ] **Step 1: Add failing Operation and graph tests**

Test that:

- `GET` plus `/api/accounts` requires `operation_id == "GET:/api/accounts"`
- method normalization happens before identity comparison
- duplicate `operation_id` values in a graph are rejected

- [ ] **Step 2: Add failing relationship and binding tests**

Test that:

- relationship types outside `id_flow|ownership|call_order|data_flow` fail
- `object_binding` rejects missing `object_type` or `owner`
- `parameter_binding` rejects non-null `object_type` or `owner`
- valid object and parameter bindings pass

- [ ] **Step 3: Add failing active-module tests**

Introduce an executable module type containing only:

```text
BOLA-001 | INPUT-001 | DATA-001
```

Test that `AUTHN-001` fails in `TestCandidate.module_id` and
`ScanStep.module_id`, while the immutable contract example may still list
`AUTHN-001` in `approved_module_ids`.

- [ ] **Step 4: Run focused tests and verify RED**

Run:

```powershell
python -m pytest tests/test_contracts.py -q
```

- [ ] **Step 5: Implement model validators and active module typing**

Use Pydantic model validators rather than duplicating these checks only in
Executor runtime logic. Preserve the four-value relationship literal.

- [ ] **Step 6: Run focused and dependent tests**

Run:

```powershell
python -m pytest tests/test_contracts.py tests/test_executor_approval.py -q
```

- [ ] **Step 7: Commit**

```powershell
git add scanner/contracts.py tests/test_contracts.py
git commit -m "fix(scanner): enforce executable contract invariants"
```

---

### Task 3: Add Typed Auditable Evidence

**Files:**
- Modify: `scanner/contracts.py`
- Modify: `scanner/artifacts.py`
- Modify: `scanner/executor.py`
- Modify: `tests/test_artifacts.py`
- Modify: `tests/test_executor_execution.py`
- Create: `tests/test_evidence_contract.py`

**Interfaces:**
- Produces: `EvidenceObservation`, `EvidenceArtifact`
- Consumes: fixed-rule module outcomes without storing raw response values

- [ ] **Step 1: Write failing Evidence model tests**

Test that an Evidence artifact preserves:

- `scan_id`, `operation_id`, `module_id`, `rule_id`
- verified condition codes and affected field metadata
- baseline/variant actor IDs and status codes
- response structure SHA-256 or observed field paths

Test that unknown fields, raw response bodies, arbitrary response values,
credentials, object IDs, and concrete query URLs are rejected.

- [ ] **Step 2: Write the failing artifact serialization test**

Build Evidence containing safe rule/condition/field/status data plus runtime
sensitive values supplied to the builder. Assert:

- the safe semantic fields survive unchanged
- secret values do not occur in serialized bytes
- the artifact does not collapse to a `[REDACTED]` key
- JSON keys remain unique

- [ ] **Step 3: Run Evidence tests and verify RED**

Run:

```powershell
python -m pytest tests/test_evidence_contract.py tests/test_artifacts.py -q
```

- [ ] **Step 4: Implement allowlist Evidence models**

Add strict models with:

- fixed actor IDs
- HTTP status bounds
- SHA-256 format validation
- safe observed-field path validation
- cross-validation requiring a structure hash or observed field path

- [ ] **Step 5: Add a dedicated Evidence canonicalization path**

`ArtifactBuilder` must validate and serialize Evidence through
`EvidenceArtifact`. Do not pass Evidence through
`_remove_untyped_runtime_values()`. Keep the Redactor as defense in depth and
validate the cleaned output again.

- [ ] **Step 6: Convert module outcome evidence in Executor**

Replace the free-form `evidence_payload` with a typed Evidence projection:

- derive response structure hashes from structure only
- copy only observed field paths, never values
- assign baseline/variant actors from the executed comparison
- retain rule, verified conditions, and affected fields

Do not change the modules' network behavior or fixed verification rules.

- [ ] **Step 7: Run focused Executor and module tests**

Run:

```powershell
python -m pytest tests/test_evidence_contract.py tests/test_artifacts.py tests/test_executor_execution.py tests/modules -q
```

- [ ] **Step 8: Commit**

```powershell
git add scanner/contracts.py scanner/artifacts.py scanner/executor.py tests/test_artifacts.py tests/test_executor_execution.py tests/test_evidence_contract.py
git commit -m "fix(scanner): preserve auditable typed evidence"
```

---

### Task 4: Implement the Stateless HTTP BackendClient

**Files:**
- Modify: `scanner/integration/backend_client.py`
- Modify: `scanner/integration/__init__.py`
- Modify: `tests/integration/test_backend_client.py`
- Create: `tests/integration/test_http_backend_client.py`

**Interfaces:**
- Produces: `JobKind`, `BackendSettings`, `HttpBackendClient`
- Consumes: explicit `job_id`, `scan_id`, Scanner stage, typed artifacts and decisions

- [ ] **Step 1: Write failing settings and authentication tests**

Test:

- environment/default setting parsing
- positive finite timeout validation
- auth enabled without token is rejected
- Bearer header is present only when auth is enabled

- [ ] **Step 2: Write failing stage mapping tests**

Cover every required Discovery and Execution stage mapping. Verify Scanner
progress 100 is sent as backend progress 99.

- [ ] **Step 3: Write failing callback route and payload tests**

Using `httpx.MockTransport`, assert exact method, path, body, and auth for:

- Discovery progress
- Execution progress
- normalized graph
- scan result
- Evidence
- plan approval/rejection
- failed

Assert `details.artifact_id` is converted to an opaque `artifact:<id>` reference.

- [ ] **Step 4: Write failing safe-error tests**

Simulate timeouts, connection failures, non-2xx responses, malformed JSON, and
missing artifact IDs. Assert errors contain no response body, Authorization
token, concrete URL query, or submitted secret.

- [ ] **Step 5: Run focused tests and verify RED**

Run:

```powershell
python -m pytest tests/integration/test_backend_client.py tests/integration/test_http_backend_client.py -q
```

- [ ] **Step 6: Refactor the BackendClient protocol and Fake**

Make callback context explicit. Keep the Fake deterministic and record
`job_id`, `scan_id`, job kind, mapped input stage, payload, and returned
artifact references for existing Scanner tests.

- [ ] **Step 7: Implement `HttpBackendClient`**

Use a caller-injected or internally owned synchronous `httpx.Client`. Centralize:

- safe URL joining
- conditional authorization
- JSON POST
- response validation
- stage mapping
- error normalization

- [ ] **Step 8: Run focused tests and verify GREEN**

Run:

```powershell
python -m pytest tests/integration -q
```

- [ ] **Step 9: Commit**

```powershell
git add scanner/integration tests/integration
git commit -m "feat(scanner): post worker callbacks to backend"
```

---

### Task 5: Thread Explicit Job Context Through Scanner and Executor

**Files:**
- Modify: `scanner/scanner.py`
- Modify: `scanner/executor.py`
- Modify: `scanner/policy.py`
- Modify: `tests/test_scanner_discovery.py`
- Modify: `tests/test_scanner_execution.py`
- Modify: `tests/test_scanner_integration.py`
- Modify: `tests/test_executor_approval.py`
- Modify: `tests/test_executor_execution.py`

**Interfaces:**
- Produces: correctly routed progress/artifact/approval/failure callbacks
- Consumes: refactored `BackendClient`

- [ ] **Step 1: Update existing tests to require explicit context**

Before implementation, change Spy/Fake assertions so every callback must carry
the backend `job_id`, contract `scan_id`, and correct `JobKind`.

- [ ] **Step 2: Add failing PENDING_APPROVAL execution test**

Pass a valid `PENDING_APPROVAL` plan to `Scanner.run_execution()`. Assert:

- Executor evaluates it internally
- approval or rejection callback is emitted
- Scanner never requires or mutates an `APPROVED` plan

- [ ] **Step 3: Run focused tests and verify RED**

Run:

```powershell
python -m pytest tests/test_scanner_discovery.py tests/test_scanner_execution.py tests/test_scanner_integration.py tests/test_executor_approval.py tests/test_executor_execution.py -q
```

- [ ] **Step 4: Thread context through orchestration**

Update progress, approval, artifact, failure, request-budget and cancellation
calls without introducing mutable current-job state in the backend client.

- [ ] **Step 5: Preserve existing safety behavior**

Confirm:

- runtime-secret isolation
- request budget continuity
- per-hop redirect checks
- exact short-secret matching
- only verified findings enter Scan Result

- [ ] **Step 6: Run the focused Scanner/Executor suite**

Run:

```powershell
python -m pytest tests/test_scanner_discovery.py tests/test_scanner_execution.py tests/test_scanner_integration.py tests/test_executor_approval.py tests/test_executor_execution.py -q
```

- [ ] **Step 7: Commit**

```powershell
git add scanner/scanner.py scanner/executor.py scanner/policy.py tests/test_scanner_discovery.py tests/test_scanner_execution.py tests/test_scanner_integration.py tests/test_executor_approval.py tests/test_executor_execution.py
git commit -m "refactor(scanner): carry explicit backend job context"
```

---

### Task 6: Add FastAPI Job Endpoints and Idempotent Background Execution

**Files:**
- Create: `scanner/api.py`
- Modify: `scanner/__init__.py`
- Create: `tests/test_api.py`

**Interfaces:**
- Produces: `POST /jobs/discovery`, `POST /jobs/execution`, `create_app`, `app`
- Consumes: `Scanner`, `HttpBackendClient`, existing job request contracts

- [ ] **Step 1: Write failing 202 contract tests**

Using `TestClient`, assert each endpoint:

- accepts the exact request shape
- returns status 202
- returns exactly `{"job_id": <input>, "accepted": true}`
- passes the backend-generated `job_id` unchanged
- rejects malformed ContractSource input without running Scanner

- [ ] **Step 2: Write failing idempotency tests**

Submit the same `job_id` twice, including concurrent submissions. Assert:

- both HTTP responses are 202
- exactly one Background execution occurs
- different job IDs execute independently

- [ ] **Step 3: Write failing scan serialization tests**

Submit Discovery and Execution jobs with the same `scan_id`. Assert the scan
lock prevents overlap. Submit jobs with different scan IDs and assert neither
is blocked by a global execution lock.

- [ ] **Step 4: Write failing Background failure tests**

Assert:

- a known Scanner job error is not reported twice
- an unexpected exception posts one safe `/failed` callback
- the accepted job remains registered and is not rerun on retry

- [ ] **Step 5: Run endpoint tests and verify RED**

Run:

```powershell
python -m pytest tests/test_api.py -q
```

- [ ] **Step 6: Implement the app factory and JobRegistry**

Use:

- a lock-protected processed-job set
- scan-ID-to-lock storage
- FastAPI `BackgroundTasks`
- Starlette threadpool execution for synchronous Scanner methods
- dependency injection hooks for tests

- [ ] **Step 7: Add environment-backed default app**

Construct `HttpBackendClient` and the singleton Scanner once per process.
Avoid reading settings or creating HTTP clients per request.

- [ ] **Step 8: Run endpoint tests and verify GREEN**

Run:

```powershell
python -m pytest tests/test_api.py -q
```

- [ ] **Step 9: Commit**

```powershell
git add scanner/api.py scanner/__init__.py tests/test_api.py
git commit -m "feat(scanner): expose idempotent job endpoints"
```

---

### Task 7: Validate Immutable Final JSON Examples

**Files:**
- Create: `tests/test_final_json_contract_examples.py`
- Do not modify: `docs/최종 JSON 데이터 계약.md`

**Interfaces:**
- Produces: executable conformance test for the canonical examples
- Consumes: `TargetProfile`, `NormalizedApiGraph`, `RelationshipAnalysis`, `ScanPlan`, `ScanResult`

- [ ] **Step 1: Write a parser for fenced JSON examples in the test**

Read the immutable UTF-8 document and extract each named JSON block. Replace
angle-bracket placeholders only inside the test fixture with valid values.

- [ ] **Step 2: Validate every final contract example**

Assert each example passes the corresponding Scanner model. Preserve
`approved_module_ids` exactly as documented while ensuring no `AUTHN-001`
executable candidate or plan step is accepted.

- [ ] **Step 3: Run the contract test**

Run:

```powershell
python -m pytest tests/test_final_json_contract_examples.py -q
```

- [ ] **Step 4: Verify the source document is unchanged**

Run:

```powershell
git diff --exit-code -- "docs/최종 JSON 데이터 계약.md"
```

- [ ] **Step 5: Commit**

```powershell
git add tests/test_final_json_contract_examples.py
git commit -m "test(scanner): lock final JSON contract examples"
```

---

### Task 8: Full Regression, Review, and Completion Verification

**Files:**
- Review: all files changed since `0b64c07`
- Do not modify unrelated team-owned files

- [ ] **Step 1: Run the full suite**

Run:

```powershell
python -m pytest -q
```

Expected: all previous 343 tests plus new tests pass.

- [ ] **Step 2: Run bytecode compilation**

Run:

```powershell
python -m compileall -q scanner tests
```

- [ ] **Step 3: Run packaging verification**

Run:

```powershell
python -m pip wheel --no-deps --no-build-isolation .
python -m pip check
```

- [ ] **Step 4: Run safety and scope checks**

Confirm:

- no changes to `docs/최종 JSON 데이터 계약.md`
- no backend, LLM, frontend, DB, queue, or report implementation
- no separate Executor service or `verifier.py`
- no secret/token/cookie/object-ID/raw-response values in Evidence fixtures
- package wheel contains `scanner/api.py` and scanner subpackages

- [ ] **Step 5: Review the complete diff**

Use `superpowers:requesting-code-review`, address all actionable findings, and
rerun affected tests after every fix.

- [ ] **Step 6: Apply verification-before-completion**

Run the full pytest and compileall commands again after the last change. Record
only fresh results.

- [ ] **Step 7: Commit final review fixes if needed**

```powershell
git add <reviewed scanner and test files>
git commit -m "fix(scanner): address integration review findings"
```
