from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from scanner.audit import InMemoryAuditSink
from scanner.auth.session_manager import ActorSession
from scanner.contracts import TargetProfile
from scanner.crawler.katana_runner import KatanaError, KatanaRunner
from scanner.integration.backend_client import FakeBackendClient
from scanner.policy import (
    BudgetExceeded,
    CancellationGuard,
    CancellationRequested,
    RequestBudget,
)


def target_profile() -> TargetProfile:
    return TargetProfile.model_validate(
        {
            "schema_version": "1.1",
            "scan_id": "scan-001",
            "target": {
                "base_url": "http://vuln-bank.local",
                "allowed_paths": ["/api/*", "/health"],
                "allowed_methods": ["GET"],
            },
            "discovery": {"sources": ["openapi", "crawl"], "max_depth": 2},
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
                "max_requests": 10,
                "requests_per_second": 7,
                "state_change_policy": "deny",
                "approved_modules": ["authz", "input_validation", "data_exposure"],
            },
        }
    )


class FakeProcess:
    def __init__(
        self,
        *,
        stdout: str = "",
        stderr: str = "",
        returncode: int = 0,
        cancel_backend: FakeBackendClient | None = None,
        job_id: str = "job-001",
    ) -> None:
        self._stdout = stdout
        self._stderr = stderr
        self._final_returncode = returncode
        self._cancel_backend = cancel_backend
        self._job_id = job_id
        self._timed_out = False
        self.returncode: int | None = None
        self.terminated = False
        self.wait_timeouts: list[float] = []
        self.communicate_timeouts: list[float] = []

    def communicate(self, *, timeout: float) -> tuple[str, str]:
        self.communicate_timeouts.append(timeout)
        if self._cancel_backend is not None and not self._timed_out:
            self._timed_out = True
            self._cancel_backend.cancel(self._job_id)
            raise subprocess.TimeoutExpired("katana", timeout)
        self.returncode = self._final_returncode
        return self._stdout, self._stderr

    def terminate(self) -> None:
        self.terminated = True
        self.returncode = -15

    def wait(self, *, timeout: float) -> int:
        self.wait_timeouts.append(timeout)
        return self.returncode if self.returncode is not None else 0


class FakeProcessFactory:
    def __init__(self, processes: list[FakeProcess]) -> None:
        self._processes = list(processes)
        self.calls: list[tuple[list[str], dict[str, object]]] = []
        self.header_paths: list[Path] = []
        self.header_contents: list[str] = []

    def __call__(self, argv: list[str], **kwargs: object) -> FakeProcess:
        copied_argv = list(argv)
        self.calls.append((copied_argv, dict(kwargs)))
        header_path = Path(copied_argv[copied_argv.index("-H") + 1])
        self.header_paths.append(header_path)
        self.header_contents.append(header_path.read_text(encoding="utf-8"))
        return self._processes.pop(0)


class FailingProcessFactory:
    def __init__(self) -> None:
        self.header_path: Path | None = None

    def __call__(self, argv: list[str], **kwargs: object) -> FakeProcess:
        self.header_path = Path(argv[argv.index("-H") + 1])
        token = self.header_path.read_text(encoding="utf-8").strip()
        raise RuntimeError(f"launch failed with {token}")


def test_runner_uses_exact_safe_argv_distinct_header_files_and_filtered_records(
    tmp_path: Path,
):
    output = "\n".join(
        [
            json.dumps(
                {
                    "request": {
                        "method": "GET",
                        "endpoint": "http://vuln-bank.local/api/accounts",
                    }
                }
            ),
            json.dumps(
                {
                    "method": "GET",
                    "url": "http://vuln-bank.local/api/cards/abc",
                }
            ),
            json.dumps(
                {"method": "GET", "url": "http://attacker.local/api/accounts"}
            ),
            json.dumps(
                {"method": "GET", "url": "http://vuln-bank.local/private"}
            ),
            json.dumps(
                {"method": "POST", "url": "http://vuln-bank.local/api/transfer"}
            ),
        ]
    )
    factory = FakeProcessFactory(
        [FakeProcess(stdout=output), FakeProcess(stdout=output)]
    )
    audit = InMemoryAuditSink()
    runner = KatanaRunner(
        executable="fake-katana",
        process_factory=factory,
        temp_directory=tmp_path,
        audit_sink=audit,
    )
    budget = RequestBudget(max_requests=6, requests_per_second=100)
    guard = CancellationGuard(FakeBackendClient())

    result_a = runner.run(
        target_profile(),
        session=ActorSession("user_a", token="token-a"),
        allocated_requests=3,
        budget=budget,
        cancellation_guard=guard,
        job_id="job-001",
    )
    result_b = runner.run(
        target_profile(),
        session=ActorSession("user_b", token="token-b"),
        allocated_requests=3,
        budget=budget,
        cancellation_guard=guard,
        job_id="job-001",
    )

    header_path = factory.header_paths[0]
    assert factory.calls[0][0] == [
        "fake-katana",
        "-u",
        "http://vuln-bank.local",
        "-d",
        "2",
        "-c",
        "1",
        "-p",
        "1",
        "-rl",
        "7",
        "-rlm",
        "3",
        "-ct",
        "59",
        "-retry",
        "0",
        "-jsonl",
        "-omit-raw",
        "-omit-body",
        "-cs",
        r"^http://vuln\-bank\.local(?:/api/.*|/health)$",
        "-H",
        str(header_path),
    ]
    assert factory.calls[0][1]["shell"] is False
    assert factory.calls[0][1]["text"] is True
    assert factory.header_paths[0] != factory.header_paths[1]
    assert factory.header_contents == [
        "Authorization: Bearer token-a\n",
        "Authorization: Bearer token-b\n",
    ]
    assert all(not path.exists() for path in factory.header_paths)
    assert result_a == result_b
    assert result_a.requests_made == 2
    assert [(record.method, record.url) for record in result_a.records] == [
        ("GET", "http://vuln-bank.local/api/accounts"),
        ("GET", "http://vuln-bank.local/api/cards/abc"),
    ]
    assert budget.requests_used == 6

    rendered = repr(factory.calls) + repr(audit.events) + repr(runner)
    assert "token-a" not in rendered
    assert "token-b" not in rendered


def test_runner_deletes_header_and_sanitizes_nonzero_exit(
    tmp_path: Path,
):
    factory = FakeProcessFactory(
        [FakeProcess(stderr="token-a raw katana diagnostics", returncode=2)]
    )
    audit = InMemoryAuditSink()
    runner = KatanaRunner(
        process_factory=factory,
        temp_directory=tmp_path,
        audit_sink=audit,
    )
    budget = RequestBudget(max_requests=2, requests_per_second=100)

    with pytest.raises(KatanaError, match="^katana execution failed$") as error:
        runner.run(
            target_profile(),
            session=ActorSession("user_a", token="token-a"),
            allocated_requests=2,
            budget=budget,
            cancellation_guard=CancellationGuard(FakeBackendClient()),
            job_id="job-001",
        )

    assert budget.requests_used == 2
    assert not factory.header_paths[0].exists()
    assert error.value.__cause__ is None
    assert error.value.__context__ is None
    rendered = repr(error.value) + repr(audit.events) + repr(runner)
    assert "token-a" not in rendered
    assert "raw katana diagnostics" not in rendered


def test_runner_detaches_raw_process_launch_error_and_deletes_header(tmp_path: Path):
    factory = FailingProcessFactory()
    runner = KatanaRunner(process_factory=factory, temp_directory=tmp_path)
    budget = RequestBudget(max_requests=2, requests_per_second=100)

    with pytest.raises(KatanaError, match="^katana execution failed$") as error:
        runner.run(
            target_profile(),
            session=ActorSession("user_a", token="token-a"),
            allocated_requests=2,
            budget=budget,
            cancellation_guard=CancellationGuard(FakeBackendClient()),
            job_id="job-001",
        )

    assert factory.header_path is not None
    assert not factory.header_path.exists()
    assert budget.requests_used == 2
    assert error.value.__context__ is None
    assert error.value.__cause__ is None
    assert "token-a" not in repr(error.value)


def test_runner_terminates_on_cancellation_and_deletes_header(
    tmp_path: Path,
):
    backend = FakeBackendClient()
    process = FakeProcess(cancel_backend=backend)
    factory = FakeProcessFactory([process])
    runner = KatanaRunner(process_factory=factory, temp_directory=tmp_path)
    budget = RequestBudget(max_requests=4, requests_per_second=100)

    with pytest.raises(
        CancellationRequested, match="^scan cancelled$"
    ) as cancellation:
        runner.run(
            target_profile(),
            session=ActorSession("user_b", token="token-b"),
            allocated_requests=4,
            budget=budget,
            cancellation_guard=CancellationGuard(backend),
            job_id="job-001",
        )

    assert process.terminated is True
    assert process.communicate_timeouts == [pytest.approx(0.1)]
    assert process.wait_timeouts == [pytest.approx(5.0)]
    assert budget.requests_used == 4
    assert not factory.header_paths[0].exists()
    assert cancellation.value.__context__ is None
    assert cancellation.value.__cause__ is None


def test_runner_does_not_start_without_a_budget_allocation(tmp_path: Path):
    factory = FakeProcessFactory([])
    runner = KatanaRunner(process_factory=factory, temp_directory=tmp_path)
    budget = RequestBudget(max_requests=1, requests_per_second=100)
    arguments = {
        "session": ActorSession("user_a", token="token-a"),
        "budget": budget,
        "cancellation_guard": CancellationGuard(FakeBackendClient()),
        "job_id": "job-001",
    }

    result = runner.run(target_profile(), allocated_requests=0, **arguments)
    assert result.records == ()
    assert result.requests_made == 0
    assert factory.calls == []
    assert list(tmp_path.iterdir()) == []

    with pytest.raises(BudgetExceeded):
        runner.run(target_profile(), allocated_requests=2, **arguments)
    assert factory.calls == []
    assert list(tmp_path.iterdir()) == []


def test_runner_rejects_header_injection_without_leaving_a_temp_file(tmp_path: Path):
    factory = FakeProcessFactory([])
    runner = KatanaRunner(process_factory=factory, temp_directory=tmp_path)
    budget = RequestBudget(max_requests=1, requests_per_second=100)

    with pytest.raises(KatanaError, match="^katana execution failed$"):
        runner.run(
            target_profile(),
            session=ActorSession("user_a", token="token-a\nX-Evil: injected"),
            allocated_requests=1,
            budget=budget,
            cancellation_guard=CancellationGuard(FakeBackendClient()),
            job_id="job-001",
        )

    assert factory.calls == []
    assert budget.requests_used == 1
    assert list(tmp_path.iterdir()) == []
