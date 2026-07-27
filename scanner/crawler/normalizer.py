"""Deterministic structural normalization for OpenAPI and Katana discovery."""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from urllib.parse import urlsplit

from scanner.auth.session_manager import RuntimeContext, _RuntimeSecret
from scanner.contracts import (
    InputField,
    NormalizedApiGraph,
    Operation,
    OutputField,
)
from scanner.crawler.katana_runner import KatanaRecord


_HTTP_METHODS = frozenset(
    {"get", "put", "post", "delete", "options", "head", "patch", "trace"}
)
_UUID_SEGMENT = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-"
    r"[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
)
_HEX_SEGMENT = re.compile(r"^[0-9a-fA-F]{16,}$")
_NUMERIC_SEGMENT = re.compile(r"^\d+$")
_PATH_PARAMETER = re.compile(r"^\{[^{}\/]+\}$")
_SCHEMA_TYPES = frozenset(
    {"string", "integer", "number", "boolean", "object", "array"}
)


def normalize_openapi(
    scan_id: str,
    document: Mapping[str, object],
    runtime: RuntimeContext,
) -> NormalizedApiGraph:
    """Return GET-only API structure while retaining metadata in runtime memory."""

    if runtime.scan_id != scan_id:
        raise ValueError("runtime scan_id does not match graph scan_id")

    operations: list[Operation] = []
    paths = document.get("paths")
    if not isinstance(paths, Mapping):
        return NormalizedApiGraph(scan_id=scan_id, operations=[])

    for raw_path, raw_path_item in paths.items():
        if not isinstance(raw_path, str) or not raw_path.startswith("/"):
            continue
        if not isinstance(raw_path_item, Mapping):
            continue
        path_parameters = _parameter_list(raw_path_item.get("parameters"))
        for raw_method, raw_operation in raw_path_item.items():
            if not isinstance(raw_method, str) or raw_method.casefold() not in _HTTP_METHODS:
                continue
            method = raw_method.upper()
            if method != "GET" or not isinstance(raw_operation, Mapping):
                continue

            operation_id = f"{method}:{raw_path}"
            operation_parameters = _parameter_list(raw_operation.get("parameters"))
            inputs = _normalize_parameters(
                operation_id,
                [*path_parameters, *operation_parameters],
                runtime,
            )
            inputs.extend(
                _normalize_request_body(operation_id, raw_operation.get("requestBody"), runtime)
            )
            outputs = _normalize_responses(raw_operation.get("responses"))
            operations.append(
                Operation(
                    operation_id=operation_id,
                    method=method,
                    path_template=raw_path,
                    inputs=sorted(
                        _deduplicate_inputs(inputs),
                        key=lambda field: (field.location, field.field_path),
                    ),
                    outputs=sorted(outputs, key=lambda field: field.field_path),
                )
            )

    operations.sort(key=lambda operation: (operation.path_template, operation.method))
    return NormalizedApiGraph(scan_id=scan_id, operations=operations)


def merge_katana_records(
    graph: NormalizedApiGraph,
    records: Iterable[KatanaRecord],
) -> NormalizedApiGraph:
    """Add GET records that do not match an existing OpenAPI path template."""

    operations = list(graph.operations)
    for record in records:
        if record.method.upper() != "GET":
            continue
        path = _safe_record_path(record.url)
        if path is None or any(
            _template_matches(operation.path_template, path)
            for operation in operations
            if operation.method == "GET"
        ):
            continue
        path_template, parameter_names = _generalize_path(path)
        if any(
            operation.method == "GET" and operation.path_template == path_template
            for operation in operations
        ):
            continue
        operations.append(
            Operation(
                operation_id=f"GET:{path_template}",
                method="GET",
                path_template=path_template,
                inputs=[
                    InputField(location="path", field_path=name, type="string")
                    for name in parameter_names
                ],
                outputs=[],
            )
        )

    operations.sort(key=lambda operation: (operation.path_template, operation.method))
    return NormalizedApiGraph(
        schema_version=graph.schema_version,
        scan_id=graph.scan_id,
        operations=operations,
    )


def infer_output_fields(value: object) -> list[OutputField]:
    """Infer response field paths from value shape without retaining any values."""

    fields: list[OutputField] = []
    _flatten_value(value, "", fields, include_current=False)
    return sorted(_deduplicate_outputs(fields), key=lambda field: field.field_path)


def _parameter_list(value: object) -> list[Mapping[str, object]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, Mapping)]


def _normalize_parameters(
    operation_id: str,
    parameters: list[Mapping[str, object]],
    runtime: RuntimeContext,
) -> list[InputField]:
    normalized: dict[tuple[str, str], InputField] = {}
    for parameter in parameters:
        name = parameter.get("name")
        location = parameter.get("in")
        if not isinstance(name, str) or location not in {"path", "query", "header"}:
            continue
        schema = parameter.get("schema")
        schema_mapping = schema if isinstance(schema, Mapping) else {}
        normalized[(location, name)] = InputField(
            location=location,
            field_path=name,
            type=_schema_type(schema_mapping),
        )
        if parameter.get("required") is True:
            runtime.required_inputs.setdefault(operation_id, set()).add((location, name))
        _store_examples(operation_id, location, name, parameter, schema_mapping, runtime)
    return list(normalized.values())


def _normalize_request_body(
    operation_id: str,
    request_body: object,
    runtime: RuntimeContext,
) -> list[InputField]:
    if not isinstance(request_body, Mapping):
        return []
    schema = _content_schema(request_body.get("content"))
    if schema is None:
        return []

    inputs: list[InputField] = []
    _flatten_input_schema(
        schema,
        "",
        operation_id,
        runtime,
        inputs,
        required_names=_required_names(schema),
    )
    return inputs


def _flatten_input_schema(
    schema: Mapping[str, object],
    prefix: str,
    operation_id: str,
    runtime: RuntimeContext,
    fields: list[InputField],
    *,
    required_names: set[str],
) -> None:
    properties = schema.get("properties")
    if not isinstance(properties, Mapping):
        return
    for raw_name, raw_child in properties.items():
        if not isinstance(raw_name, str) or not isinstance(raw_child, Mapping):
            continue
        field_path = f"{prefix}.{raw_name}" if prefix else raw_name
        field_type = _schema_type(raw_child)
        fields.append(
            InputField(location="body", field_path=field_path, type=field_type)
        )
        if raw_name in required_names:
            runtime.required_inputs.setdefault(operation_id, set()).add(
                ("body", field_path)
            )
        _store_examples(
            operation_id, "body", field_path, raw_child, raw_child, runtime
        )
        if field_type == "object":
            _flatten_input_schema(
                raw_child,
                field_path,
                operation_id,
                runtime,
                fields,
                required_names=_required_names(raw_child),
            )
        elif field_type == "array":
            items = raw_child.get("items")
            if isinstance(items, Mapping):
                _flatten_input_schema(
                    items,
                    f"{field_path}[]",
                    operation_id,
                    runtime,
                    fields,
                    required_names=_required_names(items),
                )


def _normalize_responses(responses: object) -> list[OutputField]:
    if not isinstance(responses, Mapping):
        return []
    for status, response in sorted(responses.items(), key=lambda item: str(item[0])):
        if not str(status).startswith("2") or not isinstance(response, Mapping):
            continue
        schema = _content_schema(response.get("content"))
        if schema is None:
            continue
        fields: list[OutputField] = []
        _flatten_output_schema(schema, "", fields, include_current=False)
        return _deduplicate_outputs(fields)
    return []


def _content_schema(content: object) -> Mapping[str, object] | None:
    if not isinstance(content, Mapping):
        return None
    media = content.get("application/json")
    if not isinstance(media, Mapping):
        for candidate in content.values():
            if isinstance(candidate, Mapping):
                media = candidate
                break
    if not isinstance(media, Mapping):
        return None
    schema = media.get("schema")
    return schema if isinstance(schema, Mapping) else None


def _flatten_output_schema(
    schema: Mapping[str, object],
    prefix: str,
    fields: list[OutputField],
    *,
    include_current: bool,
) -> None:
    field_type = _schema_type(schema)
    if include_current and prefix:
        fields.append(OutputField(field_path=prefix, type=field_type))
    if field_type == "object":
        properties = schema.get("properties")
        if not isinstance(properties, Mapping):
            return
        for raw_name, raw_child in properties.items():
            if not isinstance(raw_name, str) or not isinstance(raw_child, Mapping):
                continue
            field_path = f"{prefix}.{raw_name}" if prefix else raw_name
            _flatten_output_schema(
                raw_child, field_path, fields, include_current=True
            )
    elif field_type == "array":
        items = schema.get("items")
        if isinstance(items, Mapping):
            _flatten_output_schema(
                items, f"{prefix}[]", fields, include_current=False
            )


def _flatten_value(
    value: object,
    prefix: str,
    fields: list[OutputField],
    *,
    include_current: bool,
) -> None:
    field_type = _value_type(value)
    if include_current and prefix:
        fields.append(OutputField(field_path=prefix, type=field_type))
    if isinstance(value, Mapping):
        for raw_name, child in value.items():
            if not isinstance(raw_name, str):
                continue
            field_path = f"{prefix}.{raw_name}" if prefix else raw_name
            _flatten_value(child, field_path, fields, include_current=True)
    elif isinstance(value, list) and value:
        _flatten_value(
            value[0],
            f"{prefix}[]",
            fields,
            include_current=False,
        )


def _store_examples(
    operation_id: str,
    location: str,
    field_path: str,
    primary: Mapping[str, object],
    schema: Mapping[str, object],
    runtime: RuntimeContext,
) -> None:
    values: list[object] = []
    for source, key in (
        (primary, "example"),
        (schema, "example"),
        (schema, "default"),
    ):
        if key in source:
            values.append(source[key])
    if not values:
        return
    stored = runtime.parameter_examples.setdefault(
        (operation_id, location, field_path), set()
    )
    for value in values:
        if value is not None:
            stored.add(_RuntimeSecret(str(value)))


def _required_names(schema: Mapping[str, object]) -> set[str]:
    required = schema.get("required")
    if not isinstance(required, list):
        return set()
    return {name for name in required if isinstance(name, str)}


def _schema_type(schema: Mapping[str, object]) -> str:
    raw_type = schema.get("type")
    if raw_type in _SCHEMA_TYPES:
        return str(raw_type)
    if isinstance(schema.get("properties"), Mapping):
        return "object"
    if isinstance(schema.get("items"), Mapping):
        return "array"
    return "unknown"


def _value_type(value: object) -> str:
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, Mapping):
        return "object"
    if isinstance(value, list):
        return "array"
    return "unknown"


def _deduplicate_inputs(fields: Iterable[InputField]) -> list[InputField]:
    unique: dict[tuple[str, str], InputField] = {}
    for field in fields:
        unique[(field.location, field.field_path)] = field
    return list(unique.values())


def _deduplicate_outputs(fields: Iterable[OutputField]) -> list[OutputField]:
    unique: dict[str, OutputField] = {}
    for field in fields:
        unique[field.field_path] = field
    return list(unique.values())


def _safe_record_path(url: str) -> str | None:
    parsed = urlsplit(url)
    if parsed.scheme and parsed.scheme.casefold() not in {"http", "https"}:
        return None
    path = parsed.path or "/"
    if not path.startswith("/") or "%" in path or ".." in path.split("/"):
        return None
    return path


def _template_matches(path_template: str, path: str) -> bool:
    template_parts = path_template.strip("/").split("/")
    path_parts = path.strip("/").split("/")
    if len(template_parts) != len(path_parts):
        return False
    return all(
        _PATH_PARAMETER.fullmatch(template) is not None or template == actual
        for template, actual in zip(template_parts, path_parts, strict=True)
    )


def _generalize_path(path: str) -> tuple[str, list[str]]:
    names: list[str] = []
    segments: list[str] = []
    for segment in path.split("/"):
        if _is_identifier_segment(segment):
            name = "id" if not names else f"id_{len(names) + 1}"
            names.append(name)
            segments.append(f"{{{name}}}")
        else:
            segments.append(segment)
    return "/".join(segments), names


def _is_identifier_segment(segment: str) -> bool:
    return any(
        pattern.fullmatch(segment) is not None
        for pattern in (_NUMERIC_SEGMENT, _UUID_SEGMENT, _HEX_SEGMENT)
    )
