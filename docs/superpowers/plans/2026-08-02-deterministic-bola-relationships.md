# Deterministic BOLA Relationship Recovery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Recover graph-backed BOLA relationships when the LLM omits them and ensure Scanner can bind and verify VulnBank-style account identifiers.

**Architecture:** Post-process validated LLM relationships with deterministic, contract-backed `id_flow` relationships before existing candidate selection. Preserve actor ownership by extending runtime-only identifier collection, then extend the existing fixed BOLA verifier to recognize `account_number` without weakening its foreign-object proof requirement.

**Tech Stack:** Python 3.11+, Pydantic v2, pytest, httpx MockTransport

## Global Constraints

- Do not modify `docs/최종 JSON 데이터 계약.md` or any external JSON schema.
- Keep executable modules limited to `BOLA-001|INPUT-001|DATA-001`.
- Keep `state_change_policy="deny"`; add no non-GET scanning behavior.
- Never persist tokens, credentials, account numbers, object IDs, or raw responses.
- Do not create findings from HTTP status alone; retain `BOLA_FOREIGN_OBJECT_RETURNED` as the only verified BOLA condition.
- Preserve all unrelated dirty-worktree changes and the intentionally deleted `backend/.env.example`.
- Do not commit, push, or create a PR without a separate explicit user request.

---

### Task 1: Recover omitted graph-backed identifier relationships

**Files:**
- Modify: `tests/test_service.py`
- Modify: `llm/service.py`

**Interfaces:**
- Consumes: `TargetProfile`, `NormalizedApiGraph`, validated `list[Relationship]`
- Produces: `LLMService._recover_identifier_relationships(target, graph, relationships) -> list[Relationship]`
- Produces: identifier helpers returning `str | None` object types without reading runtime values

- [ ] **Step 1: Add a failing empty-draft regression test**

Add this test to `LLMServiceTest` in `tests/test_service.py`:

```python
def test_empty_relationship_draft_recovers_graph_backed_bola_candidate(self):
    service = LLMService(
        client=FakeClient([RelationshipDraft(relationships=[])]),
        sleep=lambda _: None,
    )

    analysis = service.analyze_relationships(target_profile(), api_graph())

    self.assertEqual(1, len(analysis.relationships))
    relationship = analysis.relationships[0]
    self.assertEqual("id_flow", relationship.relationship_type)
    self.assertEqual("items[].account_id", relationship.source_field)
    self.assertEqual("account_id", relationship.target_parameter)
    self.assertEqual(1.0, relationship.confidence)
    bola = [
        candidate
        for candidate in analysis.test_candidates
        if candidate.module_id == "BOLA-001"
    ]
    self.assertEqual(1, len(bola))
    self.assertEqual(
        "GET:/api/accounts/{account_id}",
        bola[0].target_operation_id,
    )
    ScannerRelationshipAnalysis.model_validate(analysis.model_dump(mode="json"))
```

- [ ] **Step 2: Run the focused test and confirm RED**

Run:

```powershell
python -m pytest -q tests/test_service.py::LLMServiceTest::test_empty_relationship_draft_recovers_graph_backed_bola_candidate
```

Expected: FAIL because `analysis.relationships` and the BOLA candidate list are empty.

- [ ] **Step 3: Add failing semantic identifier and deduplication tests**

Add a `vulnbank_identifier_graph()` fixture containing these operations:

```python
def vulnbank_identifier_graph() -> dict:
    return {
        "schema_version": "1.1",
        "scan_id": "scan-001",
        "operations": [
            {
                "operation_id": "GET:/api/transactions",
                "method": "GET",
                "path_template": "/api/transactions",
                "inputs": [
                    {
                        "location": "query",
                        "field_path": "account_number",
                        "type": "string",
                    }
                ],
                "outputs": [
                    {"field_path": "account_number", "type": "string"}
                ],
            },
            {
                "operation_id": "GET:/api/virtual-cards",
                "method": "GET",
                "path_template": "/api/virtual-cards",
                "inputs": [],
                "outputs": [
                    {"field_path": "cards[].id", "type": "integer"}
                ],
            },
            {
                "operation_id": "GET:/api/virtual-cards/{card_id}/transactions",
                "method": "GET",
                "path_template": "/api/virtual-cards/{card_id}/transactions",
                "inputs": [
                    {
                        "location": "path",
                        "field_path": "card_id",
                        "type": "integer",
                    }
                ],
                "outputs": [],
            },
            {
                "operation_id": "GET:/api/v1/payments/merchant_id/{merchant_id}",
                "method": "GET",
                "path_template": "/api/v1/payments/merchant_id/{merchant_id}",
                "inputs": [
                    {
                        "location": "path",
                        "field_path": "merchant_id",
                        "type": "integer",
                    }
                ],
                "outputs": [],
            },
        ],
    }
```

Add tests asserting:

```python
def test_recovery_supports_account_number_and_collection_ids(self):
    analysis = LLMService(
        client=FakeClient([RelationshipDraft(relationships=[])]),
        sleep=lambda _: None,
    ).analyze_relationships(target_profile(), vulnbank_identifier_graph())

    pairs = {
        (relationship.source_field, relationship.target_parameter)
        for relationship in analysis.relationships
    }
    self.assertIn(("account_number", "account_number"), pairs)
    self.assertIn(("cards[].id", "card_id"), pairs)
    self.assertNotIn("merchant_id", {
        relationship.target_parameter for relationship in analysis.relationships
    })
    bola_targets = {
        candidate.target_operation_id
        for candidate in analysis.test_candidates
        if candidate.module_id == "BOLA-001"
    }
    self.assertIn("GET:/api/transactions", bola_targets)
    self.assertIn(
        "GET:/api/virtual-cards/{card_id}/transactions",
        bola_targets,
    )

def test_recovery_does_not_duplicate_llm_relationship(self):
    analysis = LLMService(
        client=FakeClient([relationship_draft()]),
        sleep=lambda _: None,
    ).analyze_relationships(target_profile(), api_graph())

    self.assertEqual(1, len(analysis.relationships))
    self.assertEqual("rel-001", analysis.relationships[0].relationship_id)
```

- [ ] **Step 4: Run the new tests and confirm RED**

Run:

```powershell
python -m pytest -q tests/test_service.py -k "empty_relationship or recovery"
```

Expected: empty-draft and semantic recovery tests FAIL; deduplication may already pass.

- [ ] **Step 5: Implement deterministic recovery in `llm/service.py`**

Implement these bounded helpers inside `LLMService`:

```python
@classmethod
def _recover_identifier_relationships(
    cls,
    target: TargetProfile,
    graph: NormalizedApiGraph,
    relationships: list[Relationship],
) -> list[Relationship]:
    existing = {
        cls._relationship_key(relationship)
        for relationship in relationships
    }
    inferred: list[Relationship] = []
    for target_operation in graph.operations:
        if not cls._operation_in_scope(target, target_operation):
            continue
        for target_field in target_operation.inputs:
            if target_field.location not in {"path", "query"}:
                continue
                target_type = cls._input_object_type(
                    target_field.field_path,
                    target_operation.path_template,
                )
                if target_type is None:
                    continue
                for source_operation in graph.operations:
                    if (
                        source_operation.operation_id
                        == target_operation.operation_id
                        and target_field.location == "path"
                    ):
                        continue
                    for source_field in source_operation.outputs:
                    if source_field.type != target_field.type:
                        continue
                    if cls._output_object_type(source_field.field_path) != target_type:
                        continue
                    candidate = Relationship(
                        relationship_id="rel-pending",
                        source_operation_id=source_operation.operation_id,
                        target_operation_id=target_operation.operation_id,
                        source_field=source_field.field_path,
                        target_parameter=target_field.field_path,
                        target_parameter_location=target_field.location,
                        relationship_type="id_flow",
                        confidence=1.0,
                    )
                    key = cls._relationship_key(candidate)
                    if key not in existing:
                        existing.add(key)
                        inferred.append(candidate)
    inferred.sort(key=cls._relationship_key)
    combined = [*relationships, *inferred]
    return [
        relationship.model_copy(
            update={"relationship_id": f"rel-{index:03d}"}
        )
        for index, relationship in enumerate(combined, start=1)
    ]
```

Add the following helper behavior:

```python
@staticmethod
def _relationship_key(relationship: Relationship) -> tuple[str, ...]:
    return (
        relationship.source_operation_id,
        relationship.target_operation_id,
        relationship.source_field or "",
        relationship.target_parameter or "",
        relationship.target_parameter_location or "",
        relationship.relationship_type,
    )

@classmethod
def _input_object_type(
    cls,
    field_path: str,
    path_template: str,
) -> str | None:
    leaf = field_path.rsplit(".", 1)[-1].replace("[]", "").casefold()
    if leaf == "account_number":
        return "account"
    if leaf.endswith("_id") and len(leaf) > 3:
        return leaf[:-3]
    if leaf == "id":
        return cls._object_type(field_path, path_template)
    return None

@classmethod
def _output_object_type(cls, field_path: str) -> str | None:
    parts = field_path.split(".")
    leaf = parts[-1].replace("[]", "").casefold()
    if leaf == "account_number":
        return "account"
    if leaf.endswith("_id") and len(leaf) > 3:
        return leaf[:-3]
    if leaf != "id" or len(parts) < 2:
        return None
    container = parts[-2].replace("[]", "").casefold()
    return cls._singularize(container)

@staticmethod
def _singularize(value: str) -> str:
    if value.endswith("ies") and len(value) > 3:
        return f"{value[:-3]}y"
    if value.endswith("s") and len(value) > 1:
        return value[:-1]
    return value
```

This maps only `account_number -> account`, `*_id -> prefix`, and bare input
`id` to the existing path-resource fallback. Generic output `id` uses only its
immediate parent collection. It intentionally does not attempt general
natural-language inflection.

Call recovery after validating and deduplicating the LLM draft and before
`_select_candidates()`:

```python
relationships = self._recover_identifier_relationships(
    target,
    graph,
    relationships,
)
```

Update `_looks_like_identifier()` to recognize only the existing ID forms and
`account_number`. Update `_object_type()` to return `account` for
`account_number` before its current suffix/path logic.

- [ ] **Step 6: Run LLM tests and confirm GREEN**

Run:

```powershell
python -m pytest -q tests/test_service.py tests/test_llm_api.py tests/test_llm_backend_client.py
```

Expected: all selected tests PASS and existing prompt version/hash assertions remain unchanged.

---

### Task 2: Collect owner-scoped number and collection identifiers

**Files:**
- Modify: `tests/auth/test_session_manager.py`
- Modify: `scanner/auth/session_manager.py`

**Interfaces:**
- Consumes: actor ID and runtime JSON response body already passed to `collect_response()`
- Produces: existing `runtime.object_ids[actor_id][object_type]` sets containing `_RuntimeSecret`

- [ ] **Step 1: Add a failing collection test**

Add:

```python
def test_collect_response_supports_bola_number_and_collection_identifiers():
    profile, manager, _ = make_manager(lambda request: httpx.Response(200))
    runtime = RuntimeContext(scan_id=profile.scan_id)

    manager.collect_response(
        runtime,
        actor_id="user_b",
        operation_id="GET:/api/overview",
        body={
            "account_number": "1100000002",
            "cards": [{"id": 22}],
            "payments": [{"id": 33}],
            "items": [{"id": 999}],
        },
    )

    assert runtime.object_ids["user_b"]["account"] == {"1100000002"}
    assert runtime.object_ids["user_b"]["card"] == {"22"}
    assert runtime.object_ids["user_b"]["payment"] == {"33"}
    assert all("999" not in values for values in runtime.object_ids["user_b"].values())
    assert "1100000002" not in repr(runtime)
    assert "22" not in repr(runtime)
    assert "33" not in repr(runtime)
```

- [ ] **Step 2: Run the focused test and confirm RED**

Run:

```powershell
python -m pytest -q tests/auth/test_session_manager.py::test_collect_response_supports_bola_number_and_collection_identifiers
```

Expected: FAIL because these values are not currently collected.

- [ ] **Step 3: Implement bounded collection context**

In `SessionManager`, add:

```python
_OBJECT_KEYS = {
    "account_id": "account",
    "account_number": "account",
    "transaction_id": "transaction",
    "card_id": "card",
}
_OBJECT_COLLECTIONS = {
    "accounts": "account",
    "transactions": "transaction",
    "cards": "card",
    "payments": "payment",
}
```

Extend `_collect_object_ids()` with the bounded collection context below:

```python
def _collect_object_ids(
    self,
    value: object,
    actor_objects: dict[str, set[_RuntimeSecret]],
    metadata_objects: dict[str, set[_RuntimeSecret]],
    *,
    collection_object_type: str | None = None,
) -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            normalized_key = key if isinstance(key, str) else None
            object_type = (
                self._OBJECT_KEYS.get(normalized_key)
                if normalized_key is not None
                else None
            )
            if (
                object_type is None
                and normalized_key == "id"
                and collection_object_type is not None
            ):
                object_type = collection_object_type
            if object_type is not None and self._is_scalar(item):
                identifier = _RuntimeSecret(str(item))
                actor_objects.setdefault(object_type, set()).add(identifier)
                metadata_objects.setdefault(object_type, set()).add(identifier)
            child_collection_type = (
                self._OBJECT_COLLECTIONS.get(normalized_key)
                if normalized_key is not None
                else None
            )
            self._collect_object_ids(
                item,
                actor_objects,
                metadata_objects,
                collection_object_type=child_collection_type,
            )
    elif isinstance(value, (list, tuple)):
        for item in value:
            self._collect_object_ids(
                item,
                actor_objects,
                metadata_objects,
                collection_object_type=collection_object_type,
            )
```

The collection type crosses only the collection's list boundary and is reset
for unrelated nested mapping keys.

- [ ] **Step 4: Run session manager tests and confirm GREEN**

Run:

```powershell
python -m pytest -q tests/auth/test_session_manager.py tests/modules/test_bindings.py
```

Expected: all selected tests PASS and runtime values remain redacted from representations.

---

### Task 3: Verify account-number BOLA without weakening the rule

**Files:**
- Modify: `tests/modules/test_bola.py`
- Modify: `scanner/modules/bola.py`

**Interfaces:**
- Consumes: BOLA object binding with `object_type="account"`, owner-scoped runtime values, baseline/variant JSON responses
- Produces: existing `ModuleOutcome` with `VERIFY-BOLA-001` and `BOLA_FOREIGN_OBJECT_RETURNED`

- [ ] **Step 1: Add a failing account-number verification test**

Add account-number operation and step fixtures:

```python
def account_number_operation() -> Operation:
    return Operation(
        operation_id="GET:/api/transactions",
        method="GET",
        path_template="/api/transactions",
        inputs=[
            InputField(
                location="query",
                field_path="account_number",
                type="string",
            )
        ],
        outputs=[],
    )

def account_number_step() -> ScanStep:
    return ScanStep(
        order=1,
        candidate_id="candidate-account-number",
        module_id="BOLA-001",
        target_operation_id="GET:/api/transactions",
        target_endpoint=TargetEndpoint(method="GET", path_template="/api/transactions"),
        input_bindings=[
            InputBinding(
                parameter="account_number",
                location="query",
                binding_type="object_binding",
                object_type="account",
                owner="user_b",
            )
        ],
    )
```

Add:

```python
def test_bola_verifies_foreign_account_number_in_response():
    runtime = RuntimeContext(
        scan_id="scan-001",
        sessions={
            "user_a": ActorSession(actor_id="user_a", token="token-a"),
            "user_b": ActorSession(actor_id="user_b", token="token-b"),
        },
    )
    collector = SessionManager(cast(SafeHttpClient, None))
    collector.collect_response(
        runtime,
        actor_id="user_a",
        operation_id="GET:/api/transactions",
        body={"account_number": "1100000001"},
    )
    collector.collect_response(
        runtime,
        actor_id="user_b",
        operation_id="GET:/api/transactions",
        body={"account_number": "1100000002"},
    )

    def handler(request: httpx.Request) -> httpx.Response:
        account_number = request.url.params["account_number"]
        return httpx.Response(
            200,
            json={"account_number": account_number, "transactions": []},
        )

    outcome = BolaModule().run(
        execution_context(
            handler,
            runtime=runtime,
            operation=account_number_operation(),
            step=account_number_step(),
        )
    )

    assert outcome.verdict is ModuleVerdict.VERIFIED
    assert outcome.conditions == ("BOLA_FOREIGN_OBJECT_RETURNED",)
    assert [field.field_path for field in outcome.affected_fields] == [
        "account_number"
    ]
```

- [ ] **Step 2: Add a failing false-positive guard test**

Use the same runtime/context but return
`{"reference_number": account_number}`. Assert:

```python
assert outcome.verdict is ModuleVerdict.NOT_FOUND
assert outcome.reason_code == "BOLA_FOREIGN_OBJECT_NOT_IDENTIFIED"
```

- [ ] **Step 3: Run both tests and confirm RED**

Run:

```powershell
python -m pytest -q tests/modules/test_bola.py -k "account_number or reference_number"
```

Expected: account-number verification FAILS under the current identifying-path rule; the false-positive guard passes or remains NOT_FOUND.

- [ ] **Step 4: Implement the minimal identifying-path extension**

In `_is_identifying_path()` add only:

```python
if object_type.casefold() == "account" and terminal == "account_number":
    return True
```

Keep all existing `account_id` and parent-object `id` checks unchanged. Do not
accept arbitrary `*_number` fields.

Because `SafeHttpClient` redacts `account_number` in the public snapshot, reveal
`variant.runtime_json_body` only for the in-memory `_foreign_object_matches()`
comparison, with `variant.json_body` as a compatibility fallback. Keep the
existing redacted `variant.json_body` in evidence.

- [ ] **Step 5: Run BOLA tests and confirm GREEN**

Run:

```powershell
python -m pytest -q tests/modules/test_bola.py
```

Expected: all BOLA tests PASS, including rejection, shared-object, missing-binding, redaction, and new account-number cases.

---

### Task 4: Contract and regression verification

**Files:**
- Verify only: `docs/최종 JSON 데이터 계약.md`
- Verify only: all modified production and test files

**Interfaces:**
- Consumes: completed Tasks 1–3
- Produces: evidence that the fix preserves contracts and existing scanner behavior

- [ ] **Step 1: Run all directly affected tests**

```powershell
python -m pytest -q tests/test_service.py tests/test_llm_api.py tests/test_llm_backend_client.py tests/auth/test_session_manager.py tests/modules/test_bindings.py tests/modules/test_bola.py
```

Expected: PASS.

- [ ] **Step 2: Run the complete test suite**

```powershell
python -m pytest -q
```

Expected: all tests PASS; report the exact pass/skip counts.

- [ ] **Step 3: Run static verification**

```powershell
python -m compileall -q scanner llm tests
git diff --check
git diff --exit-code -- "docs/최종 JSON 데이터 계약.md"
```

Expected: each command exits 0 with no contract change.

- [ ] **Step 4: Inspect only the task diff**

```powershell
git diff -- llm/service.py scanner/auth/session_manager.py scanner/modules/bola.py tests/test_service.py tests/auth/test_session_manager.py tests/modules/test_bola.py docs/superpowers/specs/2026-08-02-deterministic-bola-relationships-design.md docs/superpowers/plans/2026-08-02-deterministic-bola-relationships.md
```

Confirm there is no unrelated refactor, dependency change, secret value, raw response persistence, or new module ID.

- [ ] **Step 5: Prepare Docker E2E rerun instructions**

Do not start an external scan automatically. Report the exact rebuild and rerun commands separately so the user can confirm credentials and target authorization before a new VulnBank scan.
