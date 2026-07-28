from __future__ import annotations

from typing import cast

import pytest

from scanner.auth.session_manager import RuntimeContext, SessionManager
from scanner.contracts import InputBinding, InputField, Operation
from scanner.http_client import SafeHttpClient
from scanner.modules.base import BindingError, bind_operation


def account_detail_operation(
    *,
    inputs: list[InputField] | None = None,
    path_template: str = "/api/accounts/{account_id}",
) -> Operation:
    return Operation(
        operation_id=f"GET:{path_template}",
        method="GET",
        path_template=path_template,
        inputs=inputs
        if inputs is not None
        else [InputField(location="path", field_path="account_id", type="string")],
        outputs=[],
    )


def runtime_context() -> RuntimeContext:
    runtime = RuntimeContext(scan_id="scan-001")
    collector = SessionManager(cast(SafeHttpClient, None))
    collector.collect_response(
        runtime,
        actor_id="user_a",
        operation_id="GET:/api/accounts",
        body={"items": [{"account_id": "acct-a-2"}, {"account_id": "acct-a-1"}]},
    )
    collector.collect_response(
        runtime,
        actor_id="user_b",
        operation_id="GET:/api/accounts",
        body={"items": [{"account_id": "acct-b-2"}, {"account_id": "acct-b-1"}]},
    )
    return runtime


def object_binding(
    *,
    parameter: str = "account_id",
    location: str = "path",
    owner: str = "user_b",
    object_type: str = "account",
) -> InputBinding:
    return InputBinding(
        parameter=parameter,
        location=location,
        binding_type="object_binding",
        object_type=object_type,
        owner=owner,
    )


def test_object_binding_selects_stable_sorted_runtime_value():
    bound = bind_operation(
        operation=account_detail_operation(),
        bindings=[object_binding()],
        runtime=runtime_context(),
    )

    assert bound.path == "/api/accounts/acct-b-1"
    assert bound.query == {}
    assert bound.headers == {}
    assert bound.json_body is None


def test_path_binding_url_encodes_runtime_value():
    runtime = runtime_context()
    collector = SessionManager(cast(SafeHttpClient, None))
    collector.collect_response(
        runtime,
        actor_id="user_b",
        operation_id="GET:/api/accounts",
        body={"account_id": "acct b/0"},
    )

    bound = bind_operation(
        operation=account_detail_operation(),
        bindings=[object_binding()],
        runtime=runtime,
    )

    assert bound.path == "/api/accounts/acct%20b%2F0"


def test_parameter_bindings_use_only_declared_stable_runtime_examples():
    operation = account_detail_operation(
        path_template="/api/accounts",
        inputs=[
            InputField(location="query", field_path="page", type="integer"),
            InputField(location="header", field_path="X-Trace", type="string"),
        ],
    )
    runtime = runtime_context()
    runtime.parameter_examples[("GET:/api/accounts", "query", "page")] = {"2", "1"}
    runtime.parameter_examples[("GET:/api/accounts", "header", "X-Trace")] = {"z", "a"}

    bound = bind_operation(
        operation=operation,
        bindings=[
            InputBinding(
                parameter="page",
                location="query",
                binding_type="parameter_binding",
            ),
            InputBinding(
                parameter="X-Trace",
                location="header",
                binding_type="parameter_binding",
            ),
        ],
        runtime=runtime,
    )

    assert bound.query == {"page": "1"}
    assert bound.headers == {"X-Trace": "a"}


def test_declared_body_binding_builds_nested_json():
    operation = account_detail_operation(
        path_template="/api/accounts",
        inputs=[InputField(location="body", field_path="filter.account_id", type="string")],
    )

    bound = bind_operation(
        operation=operation,
        bindings=[
            InputBinding(
                parameter="filter.account_id",
                location="body",
                binding_type="object_binding",
                object_type="account",
                owner="user_a",
            )
        ],
        runtime=runtime_context(),
    )

    assert bound.json_body == {"filter": {"account_id": "acct-a-1"}}


@pytest.mark.parametrize(
    ("operation", "bindings", "runtime_mutation"),
    [
        (
            account_detail_operation(),
            [object_binding(parameter="invented_id")],
            None,
        ),
        (
            account_detail_operation(),
            [object_binding(location="query")],
            None,
        ),
        (
            account_detail_operation(),
            [object_binding(owner="user_b")],
            lambda runtime: runtime.object_ids.pop("user_b"),
        ),
    ],
    ids=["unknown-parameter", "location-mismatch", "missing-actor-object"],
)
def test_invalid_object_bindings_fail_without_inventing_values(
    operation: Operation,
    bindings: list[InputBinding],
    runtime_mutation,
):
    runtime = runtime_context()
    if runtime_mutation is not None:
        runtime_mutation(runtime)

    with pytest.raises(BindingError, match="^operation binding failed$"):
        bind_operation(operation=operation, bindings=bindings, runtime=runtime)


def test_missing_required_input_fails():
    operation = account_detail_operation(
        path_template="/api/accounts",
        inputs=[InputField(location="query", field_path="page", type="integer")],
    )
    runtime = runtime_context()
    runtime.required_inputs[operation.operation_id] = {("query", "page")}

    with pytest.raises(BindingError, match="^operation binding failed$"):
        bind_operation(operation=operation, bindings=[], runtime=runtime)


def test_unbound_body_input_fails_even_when_not_marked_required():
    operation = account_detail_operation(
        path_template="/api/accounts",
        inputs=[InputField(location="body", field_path="filter", type="object")],
    )

    with pytest.raises(BindingError, match="^operation binding failed$"):
        bind_operation(operation=operation, bindings=[], runtime=runtime_context())


@pytest.mark.parametrize(
    "field_path",
    ["items[].account_id", "items[0].account_id"],
)
def test_array_body_path_fails_instead_of_inventing_cardinality(field_path: str):
    operation = account_detail_operation(
        path_template="/api/accounts",
        inputs=[InputField(location="body", field_path=field_path, type="string")],
    )

    with pytest.raises(BindingError, match="^operation binding failed$"):
        bind_operation(
            operation=operation,
            bindings=[
                InputBinding(
                    parameter=field_path,
                    location="body",
                    binding_type="object_binding",
                    object_type="account",
                    owner="user_b",
                )
            ],
            runtime=runtime_context(),
        )


def test_binding_error_and_bound_request_repr_do_not_expose_runtime_values():
    runtime = runtime_context()

    bound = bind_operation(
        operation=account_detail_operation(),
        bindings=[object_binding()],
        runtime=runtime,
    )

    assert "acct-b-1" not in repr(bound)
    with pytest.raises(BindingError) as error:
        bind_operation(
            operation=account_detail_operation(),
            bindings=[object_binding(object_type="missing")],
            runtime=runtime,
        )
    assert "acct-b-1" not in repr(error.value)
