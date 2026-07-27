"""In-process backend integration boundary for the scanner worker."""

from scanner.integration.backend_client import (
    BackendClient,
    FakeBackendClient,
    ScannerErrorReport,
    ScannerStage,
)

__all__ = [
    "BackendClient",
    "FakeBackendClient",
    "ScannerErrorReport",
    "ScannerStage",
]
