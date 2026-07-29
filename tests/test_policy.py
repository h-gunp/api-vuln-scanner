from __future__ import annotations

import pytest

from scanner.contracts import TargetProfile
from scanner.integration.backend_client import FakeBackendClient
from scanner.policy import (
    BudgetExceeded,
    CancellationGuard,
    CancellationRequested,
    PolicyEnforcer,
    PolicyViolation,
    RequestBudget,
)


@pytest.fixture
def profile() -> TargetProfile:
    return TargetProfile.model_validate(
        {
            "schema_version": "1.1",
            "scan_id": "scan-001",
            "target": {
                "base_url": "http://vuln-bank.local",
                "allowed_paths": ["/api/*", "/openapi.json"],
                "allowed_methods": ["GET"],
            },
            "discovery": {"sources": ["openapi"], "max_depth": 1},
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
                "max_requests": 3,
                "requests_per_second": 2,
                "state_change_policy": "deny",
                "approved_modules": ["authz", "input_validation", "data_exposure"],
            },
        }
    )


@pytest.fixture
def policy(profile: TargetProfile) -> PolicyEnforcer:
    return PolicyEnforcer(profile)


def test_login_bypasses_active_method_only(profile: TargetProfile, policy: PolicyEnforcer):
    policy.authorize(
        "POST",
        "http://vuln-bank.local/api/login",
        module_id=None,
        is_login=True,
        is_state_change=False,
    )
    with pytest.raises(PolicyViolation):
        policy.authorize(
            "POST",
            "http://attacker.local/api/login",
            module_id=None,
            is_login=True,
            is_state_change=False,
        )


def test_login_cannot_bypass_state_change_denial(policy: PolicyEnforcer):
    with pytest.raises(PolicyViolation):
        policy.authorize(
            "POST",
            "http://vuln-bank.local/api/login",
            module_id=None,
            is_login=True,
            is_state_change=True,
        )


def test_authn_transaction_and_post_probe_are_denied(
    profile: TargetProfile, policy: PolicyEnforcer
):
    for module_id in ("AUTHN-001", "TRANSACTION-001"):
        with pytest.raises(PolicyViolation):
            policy.authorize(
                "GET",
                "http://vuln-bank.local/api/accounts",
                module_id=module_id,
                is_login=False,
                is_state_change=False,
            )
    with pytest.raises(PolicyViolation):
        policy.authorize(
            "POST",
            "http://vuln-bank.local/api/accounts",
            module_id="INPUT-001",
            is_login=False,
            is_state_change=True,
        )


@pytest.mark.parametrize(
    "url",
    [
        "http://vuln-bank.local/api/../admin",
        "http://vuln-bank.local/api/%2e%2e/admin",
        "http://vuln-bank.local/api/%2F..%2Fadmin",
        "http://user@vuln-bank.local/api/accounts",
        "http://vuln-bank.local/api/accounts#fragment",
        "https://vuln-bank.local/api/accounts",
        "http://vuln-bank.local:80/api/accounts",
        "http://vuln-bank.local/private/accounts",
    ],
)
def test_policy_rejects_escaped_or_noncanonical_scope_urls(
    policy: PolicyEnforcer, url: str
):
    with pytest.raises(PolicyViolation):
        policy.authorize(
            "GET", url, module_id="BOLA-001", is_login=False, is_state_change=False
        )


def test_policy_normalizes_allowed_path_and_rejects_unknown_module(policy: PolicyEnforcer):
    policy.authorize(
        "GET",
        "http://vuln-bank.local/api/accounts/./one",
        module_id="BOLA-001",
        is_login=False,
        is_state_change=False,
    )
    with pytest.raises(PolicyViolation):
        policy.authorize(
            "GET",
            "http://vuln-bank.local/api/accounts",
            module_id="UNKNOWN-001",
            is_login=False,
            is_state_change=False,
        )


def test_request_budget_restores_count_and_rejects_last_overflow(profile: TargetProfile):
    budget = RequestBudget(max_requests=3, requests_per_second=100, clock=lambda: 0.0)
    budget.restore(2)
    assert budget.requests_used == 2
    budget.reserve()
    assert budget.requests_used == 3
    with pytest.raises(BudgetExceeded):
        budget.reserve()


def test_request_budget_never_resets_restored_count(profile: TargetProfile):
    budget = RequestBudget(max_requests=3, requests_per_second=100, clock=lambda: 0.0)
    budget.restore(2)
    with pytest.raises(ValueError):
        budget.restore(0)
    assert budget.requests_used == 2


def test_request_budget_applies_deterministic_rate_limit_sleep():
    now = [10.0]
    sleeps: list[float] = []
    budget = RequestBudget(
        max_requests=3,
        requests_per_second=2,
        clock=lambda: now[0],
        sleeper=sleeps.append,
    )
    budget.reserve()
    now[0] = 10.2
    budget.reserve()
    assert sleeps == [pytest.approx(0.3)]


def test_cancellation_is_checked_before_budget_reservation():
    backend = FakeBackendClient()
    backend.cancel("job-001")
    budget = RequestBudget(
        max_requests=3,
        requests_per_second=100,
        cancellation_guard=CancellationGuard(backend),
        job_id="job-001",
        clock=lambda: 0.0,
    )
    with pytest.raises(CancellationRequested):
        budget.reserve()
    assert budget.requests_used == 0


def test_katana_lease_exclusively_reserves_and_consumes_full_allowance():
    budget = RequestBudget(max_requests=3, requests_per_second=100, clock=lambda: 0.0)
    lease = budget.lease(2)
    assert budget.requests_used == 0
    with pytest.raises(BudgetExceeded):
        budget.reserve()
    lease.close()
    assert budget.requests_used == 2
    lease.close()
    assert budget.requests_used == 2
    budget.reserve()
    assert budget.requests_used == 3


def test_katana_lease_allowance_is_immutable_and_restore_is_blocked_while_leased():
    budget = RequestBudget(max_requests=3, requests_per_second=100, clock=lambda: 0.0)
    lease = budget.lease(2)

    with pytest.raises(AttributeError):
        lease.max_requests = 99
    with pytest.raises(ValueError, match="lease"):
        budget.restore(3)

    lease.close()
    assert budget.requests_used == 2
