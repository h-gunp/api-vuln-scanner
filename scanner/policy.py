"""Local safety checks that must pass before a scanner request reaches transport."""

from __future__ import annotations

import posixpath
import time
from dataclasses import dataclass
from fnmatch import fnmatchcase
from typing import Callable
from urllib.parse import SplitResult, urlsplit

from scanner.contracts import PolicyModule, TargetProfile
from scanner.integration.backend_client import BackendClient


class PolicyViolation(Exception):
    """A request is outside the target profile's permitted scope."""


class BudgetExceeded(Exception):
    """A request would exceed the scan's conservative request allowance."""


class CancellationRequested(Exception):
    """The backend cancelled the scanner job before a request was sent."""


class CancellationGuard:
    def __init__(self, backend: BackendClient) -> None:
        self._backend = backend

    def raise_if_cancelled(self, job_id: str) -> None:
        if self._backend.is_cancelled(job_id):
            raise CancellationRequested("scan cancelled")


class PolicyEnforcer:
    """Validates origin, path, method, module, and state-change policy."""

    _MODULE_POLICIES = {
        "BOLA-001": PolicyModule.AUTHZ,
        "INPUT-001": PolicyModule.INPUT_VALIDATION,
        "DATA-001": PolicyModule.DATA_EXPOSURE,
    }

    def __init__(self, profile: TargetProfile) -> None:
        self._profile = profile
        self._base_url = urlsplit(profile.target.base_url)

    def authorize(
        self,
        method: str,
        url: str,
        *,
        module_id: str | None,
        is_login: bool,
        is_state_change: bool,
    ) -> None:
        request_method = method.upper()
        parsed = self._parse_in_scope_url(url)
        normalized_path = self._normalized_path(parsed)

        if not any(
            fnmatchcase(normalized_path, pattern)
            for pattern in self._profile.target.allowed_paths
        ):
            raise PolicyViolation("request violates scanner safety policy")

        if is_login:
            if (
                request_method != self._profile.authentication.login.method
                or normalized_path
                != self._normalize_config_path(self._profile.authentication.login.path)
            ):
                raise PolicyViolation("request violates scanner safety policy")
            return

        if is_state_change or self._profile.safety_policy.state_change_policy != "deny":
            # The current strict contract permits only a deny policy.  Keep the
            # explicit state-change guard at this boundary if that evolves.
            raise PolicyViolation("request violates scanner safety policy")
        if request_method != "GET" or request_method not in self._profile.target.allowed_methods:
            raise PolicyViolation("request violates scanner safety policy")
        if module_id in {None, "AUTHN-001", "TRANSACTION-001"}:
            raise PolicyViolation("request violates scanner safety policy")
        required_policy = self._MODULE_POLICIES.get(module_id)
        if required_policy not in self._profile.safety_policy.approved_modules:
            raise PolicyViolation("request violates scanner safety policy")

    def _parse_in_scope_url(self, url: str) -> SplitResult:
        parsed = urlsplit(url)
        if (
            parsed.scheme.casefold() not in {"http", "https"}
            or parsed.username is not None
            or parsed.password is not None
            or parsed.fragment
            or parsed.scheme.casefold() != self._base_url.scheme.casefold()
            or parsed.netloc.casefold() != self._base_url.netloc.casefold()
        ):
            raise PolicyViolation("request violates scanner safety policy")
        return parsed

    @staticmethod
    def _normalize_config_path(path: str) -> str:
        return posixpath.normpath(path if path.startswith("/") else f"/{path}")

    def _normalized_path(self, parsed: SplitResult) -> str:
        path = parsed.path or "/"
        parts = path.split("/")
        if ".." in parts:
            raise PolicyViolation("request violates scanner safety policy")
        normalized = posixpath.normpath(path)
        if not normalized.startswith("/"):
            normalized = f"/{normalized}"
        return normalized


class RequestBudget:
    """Counts direct requests and conservatively reserves external crawler capacity."""

    def __init__(
        self,
        *,
        max_requests: int,
        requests_per_second: float,
        cancellation_guard: CancellationGuard | None = None,
        job_id: str | None = None,
        clock: Callable[[], float] = time.monotonic,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> None:
        self._max_requests = max_requests
        self._requests_per_second = requests_per_second
        self._cancellation_guard = cancellation_guard
        self._job_id = job_id
        self._clock = clock
        self._sleeper = sleeper
        self._requests_used = 0
        self._last_request_at: float | None = None
        self._active_lease: BudgetLease | None = None

    @property
    def requests_used(self) -> int:
        return self._requests_used

    def restore(self, value: int) -> None:
        if isinstance(value, bool) or not isinstance(value, int) or value < self._requests_used:
            raise ValueError("request count cannot decrease")
        self._requests_used = value

    def reserve(self) -> None:
        self._raise_if_cancelled()
        if self._active_lease is not None:
            raise BudgetExceeded("request budget reserved by an external crawler")
        if self._requests_used >= self._max_requests:
            raise BudgetExceeded("request budget exhausted")
        self._apply_rate_limit()
        self._requests_used += 1

    def lease(self, max_requests: int) -> "BudgetLease":
        if isinstance(max_requests, bool) or not isinstance(max_requests, int) or max_requests <= 0:
            raise ValueError("lease allowance must be a positive integer")
        self._raise_if_cancelled()
        if self._active_lease is not None or self._requests_used + max_requests > self._max_requests:
            raise BudgetExceeded("request budget exhausted")
        lease = BudgetLease(self, max_requests)
        self._active_lease = lease
        return lease

    def _close_lease(self, lease: "BudgetLease") -> None:
        if self._active_lease is lease:
            self._requests_used += lease.max_requests
            self._active_lease = None

    def _raise_if_cancelled(self) -> None:
        if self._cancellation_guard is not None and self._job_id is not None:
            self._cancellation_guard.raise_if_cancelled(self._job_id)

    def _apply_rate_limit(self) -> None:
        now = self._clock()
        interval = 1 / self._requests_per_second
        if self._last_request_at is not None:
            delay = interval - (now - self._last_request_at)
            if delay > 0:
                self._sleeper(delay)
                now += delay
        self._last_request_at = now


@dataclass
class BudgetLease:
    _budget: RequestBudget
    max_requests: int
    _closed: bool = False

    def close(self) -> None:
        if not self._closed:
            self._budget._close_lease(self)
            self._closed = True
