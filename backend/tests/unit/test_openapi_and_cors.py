from fastapi.testclient import TestClient

from app.main import app


def test_scan_status_error_remains_error_detail_object_or_null_in_openapi() -> None:
    schema = app.openapi()["components"]["schemas"]["ScanStatusResponse"]
    error_schema = schema["properties"]["error"]
    variants = error_schema["anyOf"]
    assert {"$ref": "#/components/schemas/ErrorDetail"} in variants
    assert {"type": "null"} in variants


def test_public_wire_schemas_keep_snake_case_names() -> None:
    schemas = app.openapi()["components"]["schemas"]
    assert "operation_id" in schemas["EndpointItem"]["properties"]
    assert "finding_id" in schemas["FindingListItem"]["properties"]
    assert "overall_risk" in schemas["AIReportResponse"]["properties"]
    assert "report_id" in schemas["AIReportResponse"]["properties"]


def test_local_vite_origins_are_allowed_without_wildcard_credentials() -> None:
    with TestClient(app) as client:
        for origin in (
            "http://127.0.0.1:4173",
            "http://localhost:4173",
        ):
            response = client.options(
                "/api/scans",
                headers={
                    "Origin": origin,
                    "Access-Control-Request-Method": "POST",
                },
            )
            assert response.status_code == 200
            assert response.headers["access-control-allow-origin"] == origin
            assert response.headers["access-control-allow-credentials"] == "true"
            assert response.headers["access-control-allow-origin"] != "*"
