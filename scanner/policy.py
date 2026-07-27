"""Local safety checks that must pass before a scanner request reaches transport."""

from __future__ import annotations

import posixpath
import time
from collections.abc import Iterable
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


def path_is_allowed(path: str, allowed_paths: Iterable[str]) -> bool:
    """Apply the request policy's path normalization and glob matching."""

    try:
        normalized_path = _normalize_policy_path(path)
    except PolicyViolation:
        return False
    return any(
        fnmatchcase(normalized_path, pattern) for pattern in allowed_paths
    )


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
        normalized_path = _normalize_policy_path(parsed.path or "/")

        if not path_is_allowed(
            normalized_path,
            self._profile.target.allowed_paths,
        ):
            raise PolicyViolation("request violates scanner safety policy")

        if is_state_change:
            raise PolicyViolation("request violates scanner safety policy")

        if is_login:
            if (
                request_method != self._profile.authentication.login.method
                or normalized_path
                != self._normalize_config_path(self._profile.authentication.login.path)
            ):
                raise PolicyViolation("request violates scanner safety policy")
            return

        if self._profile.safety_policy.state_change_policy != "deny":
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
        if self._active_lease is not None:
            raise ValueError("request count cannot be restored while a lease is active")
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

    def ensure_capacity(self, count: int) -> None:
        """Check a fixed upcoming request allowance without consuming it."""

        if isinstance(count, bool) or not isinstance(count, int) or count <= 0:
            raise ValueError("request capacity must be a positive integer")
        self._raise_if_cancelled()
        if (
            self._active_lease is not None
            or self._requests_used + count > self._max_requests
        ):
            raise BudgetExceeded("request budget exhausted")

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
            self._requests_used += lease._allowance
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


class BudgetLease:
    __slots__ = ("_budget", "_allowance", "_closed")

    def __init__(self, budget: RequestBudget, allowance: int) -> None:
        object.__setattr__(self, "_budget", budget)
        object.__setattr__(self, "_allowance", allowance)
        object.__setattr__(self, "_closed", False)

    def __setattr__(self, name: str, value: object) -> None:
        if name in {"_allowance", "max_requests"} and hasattr(self, "_allowance"):
            raise AttributeError("lease allowance is immutable")
        object.__setattr__(self, name, value)

    @property
    def max_requests(self) -> int:
        return self._allowance

    def close(self) -> None:
        if not self._closed:
            self._budget._close_lease(self)
            object.__setattr__(self, "_closed", True)


def _normalize_policy_path(path: str) -> str:
    if "%" in path:
        # Percent-encoded separators and dot segments can be decoded by a
        # downstream server differently from this process.
        raise PolicyViolation("request violates scanner safety policy")
    if ".." in path.split("/"):
        raise PolicyViolation("request violates scanner safety policy")
    normalized = posixpath.normpath(path)
    if not normalized.startswith("/"):
        normalized = f"/{normalized}"
    return normalized
