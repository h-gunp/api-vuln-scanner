from __future__ import annotations

from scanner.auth.session_manager import RuntimeContext
from scanner.crawler.katana_runner import KatanaRecord
from scanner.crawler.normalizer import (
    infer_output_fields,
    merge_katana_records,
    normalize_openapi,
)


def openapi_document() -> dict[str, object]:
    return {
        "openapi": "3.1.0",
        "security": [{"bearerAuth": []}],
        "paths": {
            "/api/transfer": {
                "post": {
                    "operationId": "transferFunds",
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "required": ["amount"],
                                    "properties": {
                                        "amount": {"type": "number", "example": 100.25}
                                    },
                                }
                            }
                        },
                    },
                    "responses": {"204": {"description": "transferred"}},
                }
            },
            "/api/accounts/{account_id}": {
                "parameters": [
                    {
                        "name": "account_id",
                        "in": "path",
                        "required": True,
                        "example": 41,
                        "schema": {"type": "integer", "default": 7},
                    }
                ],
                "get": {
                    "operationId": "accountDetail",
                    "security": [{"bearerAuth": []}],
                    "parameters": [
                        {
                            "name": "X-Trace",
                            "in": "header",
                            "schema": {"type": "string", "example": "trace-example"},
                        }
                    ],
                    "responses": {
                        "200": {
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "account_id": {"type": "integer"},
                                            "owner": {
                                                "type": "object",
                                                "properties": {
                                                    "name": {"type": "string"}
                                                },
                                            },
                                        },
                                    },
                                    "example": {
                                        "account_id": 41,
                                        "owner": {"name": "private-owner"},
                                    },
                                }
                            }
                        }
                    },
                },
            },
            "/api/accounts": {
                "get": {
                    "parameters": [
                        {
                            "name": "page",
                            "in": "query",
                            "required": True,
                            "example": 3,
                            "schema": {"type": "integer", "default": 1},
                        }
                    ],
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "required": ["owner_id"],
                                    "properties": {
                                        "owner_id": {
                                            "type": "string",
                                            "example": "owner-example",
                                        }
                                    },
                                }
                            }
                        }
                    },
                    "responses": {
                        "200": {
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
                                                        },
                                                        "balance": {"type": "number"},
                                                    },
                                                },
                                            }
                                        },
                                    }
                                }
                            }
                        }
                    },
                }
            },
        },
    }


def test_normalize_openapi_keeps_only_sorted_get_structure_and_runtime_metadata():
    runtime = RuntimeContext(scan_id="scan-001")

    graph = normalize_openapi("scan-001", openapi_document(), runtime)

    assert [operation.operation_id for operation in graph.operations] == [
        "GET:/api/accounts",
        "GET:/api/accounts/{account_id}",
    ]
    list_operation, detail_operation = graph.operations
    assert [field.model_dump() for field in list_operation.inputs] == [
        {"location": "body", "field_path": "owner_id", "type": "string"},
        {"location": "query", "field_path": "page", "type": "integer"},
    ]
    assert [field.model_dump() for field in detail_operation.inputs] == [
        {"location": "header", "field_path": "X-Trace", "type": "string"},
        {"location": "path", "field_path": "account_id", "type": "integer"},
    ]
    assert [field.model_dump() for field in list_operation.outputs] == [
        {"field_path": "items", "type": "array"},
        {"field_path": "items[].account_id", "type": "string"},
        {"field_path": "items[].balance", "type": "number"},
    ]
    assert [field.model_dump() for field in detail_operation.outputs] == [
        {"field_path": "account_id", "type": "integer"},
        {"field_path": "owner", "type": "object"},
        {"field_path": "owner.name", "type": "string"},
    ]

    dumped = graph.model_dump()
    assert all(
        set(operation) == {
            "operation_id",
            "method",
            "path_template",
            "inputs",
            "outputs",
        }
        for operation in dumped["operations"]
    )
    forbidden = ("required", "security", "source", "example", "default")
    assert not any(word in repr(dumped) for word in forbidden)

    assert runtime.required_inputs == {
        "GET:/api/accounts": {("body", "owner_id"), ("query", "page")},
        "GET:/api/accounts/{account_id}": {("path", "account_id")},
    }
    assert runtime.sensitive_values() >= {
        "owner-example",
        "3",
        "1",
        "41",
        "7",
        "trace-example",
    }


def test_merge_katana_records_deduplicates_templates_and_generalizes_identifiers():
    graph = normalize_openapi(
        "scan-001", openapi_document(), RuntimeContext(scan_id="scan-001")
    )

    merged = merge_katana_records(
        graph,
        [
            KatanaRecord("GET", "http://vuln-bank.local/api/accounts/123"),
            KatanaRecord(
                "GET",
                "http://vuln-bank.local/api/cards/123e4567-e89b-12d3-a456-426614174000",
            ),
            KatanaRecord(
                "GET",
                "http://vuln-bank.local/api/ledger/0123456789abcdef/99?view=short",
            ),
            KatanaRecord("POST", "http://vuln-bank.local/api/transfer"),
        ],
    )

    assert [operation.operation_id for operation in merged.operations] == [
        "GET:/api/accounts",
        "GET:/api/accounts/{account_id}",
        "GET:/api/cards/{id}",
        "GET:/api/ledger/{id}/{id_2}",
    ]
    assert [field.model_dump() for field in merged.operations[-1].inputs] == [
        {"location": "path", "field_path": "id", "type": "string"},
        {"location": "path", "field_path": "id_2", "type": "string"},
    ]


def test_infer_output_fields_reports_only_nested_shape():
    output = infer_output_fields(
        {
            "items": [{"account_id": "acct-secret", "active": True}],
            "next_page": 2,
            "metadata": None,
        }
    )

    assert [field.model_dump() for field in output] == [
        {"field_path": "items", "type": "array"},
        {"field_path": "items[].account_id", "type": "string"},
        {"field_path": "items[].active", "type": "boolean"},
        {"field_path": "metadata", "type": "unknown"},
        {"field_path": "next_page", "type": "integer"},
    ]
    assert "acct-secret" not in repr(output)


def test_merge_katana_records_generalizes_uuid_versions_6_7_and_8():
    raw_ids = [
        "1ef01234-5678-6abc-8def-0123456789ab",
        "01890abc-def0-7abc-8def-0123456789ab",
        "01234567-89ab-8cde-8f01-23456789abcd",
    ]
    graph = normalize_openapi(
        "scan-001",
        {"openapi": "3.1.0", "paths": {}},
        RuntimeContext(scan_id="scan-001"),
    )

    merged = merge_katana_records(
        graph,
        [
            KatanaRecord("GET", f"http://vuln-bank.local/api/v{version}/{raw_id}")
            for version, raw_id in zip((6, 7, 8), raw_ids, strict=True)
        ],
    )

    assert [operation.path_template for operation in merged.operations] == [
        "/api/v6/{id}",
        "/api/v7/{id}",
        "/api/v8/{id}",
    ]
    rendered = merged.model_dump_json()
    assert all(raw_id not in rendered for raw_id in raw_ids)


def test_operation_parameter_override_replaces_required_and_example_metadata():
    document = {
        "openapi": "3.1.0",
        "paths": {
            "/api/search": {
                "parameters": [
                    {
                        "name": "page",
                        "in": "query",
                        "required": True,
                        "example": "path-example",
                        "schema": {"type": "integer", "default": 1},
                    }
                ],
                "get": {
                    "parameters": [
                        {
                            "name": "page",
                            "in": "query",
                            "required": False,
                            "example": "operation-example",
                            "schema": {"type": "integer", "default": 9},
                        }
                    ],
                    "responses": {"204": {"description": "no content"}},
                },
            }
        },
    }
    runtime = RuntimeContext(scan_id="scan-001")

    graph = normalize_openapi("scan-001", document, runtime)

    assert [field.model_dump() for field in graph.operations[0].inputs] == [
        {"location": "query", "field_path": "page", "type": "integer"}
    ]
    assert runtime.required_inputs == {}
    assert runtime.sensitive_values() == {"operation-example", "9"}
