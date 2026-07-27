"""Safe subprocess boundary for authenticated Katana discovery."""

from __future__ import annotations

import json
import posixpath
import re
import subprocess
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from fnmatch import fnmatchcase
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Any
from urllib.parse import SplitResult, urlsplit

from scanner.artifacts import Redactor
from scanner.audit import AuditEvent, AuditSink
from scanner.auth.session_manager import ActorSession
from scanner.contracts import TargetProfile
from scanner.policy import CancellationGuard, CancellationRequested, RequestBudget


class KatanaError(Exception):
    """A fixed, secret-free Katana subprocess failure."""


@dataclass(frozen=True)
class KatanaRecord:
    method: str
    url: str


@dataclass(frozen=True)
class KatanaRunResult:
    records: tuple[KatanaRecord, ...]
    requests_made: int


class KatanaRunner:
    """Launches Katana with conservative request and credential boundaries."""

    _POLL_TIMEOUT_SECONDS = 0.1
    _TERMINATE_TIMEOUT_SECONDS = 5.0
    _OVERALL_TIMEOUT_SECONDS = 65.0

    def __init__(
        self,
        executable: str = "katana",
        *,
        process_factory: Callable[..., Any] = subprocess.Popen,
        temp_directory: str | Path | None = None,
        redactor: Redactor | None = None,
        audit_sink: AuditSink | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._executable = executable
        self._process_factory = process_factory
        self._temp_directory = (
            Path(temp_directory) if temp_directory is not None else None
        )
        self._redactor = redactor or Redactor()
        self._audit_sink = audit_sink
        self._clock = clock

    def run(
        self,
        profile: TargetProfile,
        *,
        session: ActorSession,
        allocated_requests: int,
        budget: RequestBudget,
        cancellation_guard: CancellationGuard,
        job_id: str,
    ) -> KatanaRunResult:
        """Run one actor crawl and return only safe request method/URL records."""

        if (
            isinstance(allocated_requests, bool)
            or not isinstance(allocated_requests, int)
            or allocated_requests < 0
        ):
            raise ValueError("allocated_requests must be a non-negative integer")
        if allocated_requests == 0:
            return KatanaRunResult(records=(), requests_made=0)

        lease = budget.lease(allocated_requests)
        header_path: Path | None = None
        process: Any | None = None
        failure: str | None = None
        try:
            cancellation_guard.raise_if_cancelled(job_id)
            header_path = self._write_header_file(session.authorization_headers())
            scope_regex = _scope_regex(
                profile.target.base_url, profile.target.allowed_paths
            )
            argv = self._argv(
                profile,
                allocated_requests=lease.max_requests,
                scope_regex=scope_regex,
                header_path=header_path,
            )
            process = self._process_factory(
                argv,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                shell=False,
            )
            stdout = self._communicate(
                process, cancellation_guard=cancellation_guard, job_id=job_id
            )
            if process.returncode != 0:
                raise KatanaError("katana execution failed")

            records = _parse_records(
                stdout,
                base_url=profile.target.base_url,
                allowed_paths=profile.target.allowed_paths,
            )
            result = KatanaRunResult(
                records=tuple(records),
                requests_made=len(records),
            )
            self._emit(
                code="KATANA_COMPLETED",
                level="info",
                profile=profile,
                job_id=job_id,
                details={"requests_used": result.requests_made},
            )
            return result
        except CancellationRequested:
            if process is not None:
                self._terminate(process)
            self._emit(
                code="KATANA_CANCELLED",
                level="info",
                profile=profile,
                job_id=job_id,
                details={},
            )
            failure = "cancelled"
        except Exception:
            if process is not None and process.returncode is None:
                self._terminate(process)
            self._emit(
                code="KATANA_FAILED",
                level="error",
                profile=profile,
                job_id=job_id,
                details={"error": "katana execution failed"},
            )
            failure = "error"
        finally:
            if header_path is not None:
                try:
                    header_path.unlink(missing_ok=True)
                except OSError:
                    pass
            lease.close()
        if failure == "cancelled":
            raise CancellationRequested("scan cancelled")
        raise KatanaError("katana execution failed")

    def _argv(
        self,
        profile: TargetProfile,
        *,
        allocated_requests: int,
        scope_regex: str,
        header_path: Path,
    ) -> list[str]:
        return [
            self._executable,
            "-u",
            profile.target.base_url,
            "-d",
            str(profile.discovery.max_depth),
            "-c",
            "1",
            "-p",
            "1",
            "-rl",
            str(profile.safety_policy.requests_per_second),
            "-rlm",
            str(allocated_requests),
            "-ct",
            "59",
            "-retry",
            "0",
            "-jsonl",
            "-omit-raw",
            "-omit-body",
            "-cs",
            scope_regex,
            "-H",
            str(header_path),
        ]

    def _write_header_file(self, headers: Mapping[str, str]) -> Path:
        for name, value in headers.items():
            if "\r" in name or "\n" in name or "\r" in value or "\n" in value:
                raise KatanaError("katana execution failed")
        directory = str(self._temp_directory) if self._temp_directory is not None else None
        with NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            prefix="katana-",
            suffix=".headers",
            dir=directory,
            delete=False,
        ) as header_file:
            for name, value in headers.items():
                header_file.write(f"{name}: {value}\n")
            return Path(header_file.name)

    def _communicate(
        self,
        process: Any,
        *,
        cancellation_guard: CancellationGuard,
        job_id: str,
    ) -> str:
        deadline = self._clock() + self._OVERALL_TIMEOUT_SECONDS
        while True:
            cancellation_guard.raise_if_cancelled(job_id)
            if self._clock() >= deadline:
                self._terminate(process)
                raise KatanaError("katana execution failed")
            try:
                stdout, _stderr = process.communicate(
                    timeout=self._POLL_TIMEOUT_SECONDS
                )
                return stdout if isinstance(stdout, str) else ""
            except subprocess.TimeoutExpired:
                continue

    def _terminate(self, process: Any) -> None:
        try:
            process.terminate()
            process.wait(timeout=self._TERMINATE_TIMEOUT_SECONDS)
        except Exception:
            return

    def _emit(
        self,
        *,
        code: str,
        level: str,
        profile: TargetProfile,
        job_id: str,
        details: Mapping[str, object],
    ) -> None:
        if self._audit_sink is None:
            return
        safe_details = self._redactor.redact(details)
        self._audit_sink.emit(
            AuditEvent(
                code=code,
                level=level,
                job_id=job_id,
                scan_id=profile.scan_id,
                operation_id=None,
                module_id=None,
                details=safe_details,
            )
        )


def _scope_regex(base_url: str, allowed_paths: Sequence[str]) -> str:
    base = urlsplit(base_url)
    origin = f"{base.scheme}://{base.netloc}"
    path_patterns = "|".join(
        _glob_path_regex(path) for path in sorted(allowed_paths)
    )
    return rf"^{re.escape(origin)}(?:{path_patterns})$"


def _glob_path_regex(path: str) -> str:
    normalized = path if path.startswith("/") else f"/{path}"
    escaped = re.escape(normalized)
    return escaped.replace(r"\*", ".*").replace(r"\?", ".")


def _parse_records(
    stdout: str,
    *,
    base_url: str,
    allowed_paths: Sequence[str],
) -> list[KatanaRecord]:
    records: list[KatanaRecord] = []
    for line in stdout.splitlines():
        try:
            payload = json.loads(line)
        except (json.JSONDecodeError, TypeError):
            continue
        if not isinstance(payload, Mapping):
            continue
        request = payload.get("request")
        if isinstance(request, Mapping):
            method = request.get("method")
            url = request.get("endpoint")
        else:
            method = payload.get("method")
            url = payload.get("url")
        if (
            not isinstance(method, str)
            or not isinstance(url, str)
            or method.upper() != "GET"
            or not _url_in_scope(url, base_url, allowed_paths)
        ):
            continue
        records.append(KatanaRecord(method="GET", url=url))
    return records


def _url_in_scope(
    url: str,
    base_url: str,
    allowed_paths: Sequence[str],
) -> bool:
    parsed = urlsplit(url)
    base = urlsplit(base_url)
    if (
        parsed.scheme.casefold() not in {"http", "https"}
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or parsed.scheme.casefold() != base.scheme.casefold()
        or parsed.netloc.casefold() != base.netloc.casefold()
    ):
        return False
    normalized_path = _normalized_path(parsed)
    if normalized_path is None:
        return False
    return any(
        fnmatchcase(normalized_path, _normalized_allowed_path(pattern))
        for pattern in allowed_paths
    )


def _normalized_path(parsed: SplitResult) -> str | None:
    path = parsed.path or "/"
    if "%" in path or ".." in path.split("/"):
        return None
    normalized = posixpath.normpath(path)
    return normalized if normalized.startswith("/") else f"/{normalized}"


def _normalized_allowed_path(path: str) -> str:
    normalized = posixpath.normpath(path if path.startswith("/") else f"/{path}")
    return normalized if normalized.startswith("/") else f"/{normalized}"
