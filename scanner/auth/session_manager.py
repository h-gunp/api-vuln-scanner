"""Private in-memory A/B authentication and discovered-value context."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Callable, Literal, Mapping
from urllib.parse import urljoin

import httpx
from pydantic_core import PydanticSerializationError, core_schema

from scanner.contracts import TargetProfile
from scanner.http_client import SafeHttpClient


class AuthenticationError(Exception):
    """A fixed, secret-free runtime authentication failure."""


class _RuntimeSecret:
    """A runtime-only scalar that becomes redacted when copied for serialization."""

    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        self._value = value

    def reveal(self) -> str:
        return self._value

    def __repr__(self) -> str:
        return "[REDACTED]"

    __str__ = __repr__

    def __hash__(self) -> int:
        return hash(self._value)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, _RuntimeSecret):
            return self._value == other._value
        return isinstance(other, str) and self._value == other

    def __deepcopy__(self, memo: dict[int, object]) -> str:
        return "[REDACTED]"


class _RuntimeOnly:
    @classmethod
    def __get_pydantic_core_schema__(
        cls, source_type: object, handler: Callable[[object], core_schema.CoreSchema]
    ) -> core_schema.CoreSchema:
        return core_schema.is_instance_schema(
            cls,
            serialization=core_schema.plain_serializer_function_ser_schema(
                cls._reject_serialization,
                return_schema=core_schema.any_schema(),
            ),
        )

    @staticmethod
    def _reject_serialization(value: object) -> object:
        raise PydanticSerializationError("runtime context cannot be serialized")


@dataclass
class ActorSession(_RuntimeOnly):
    actor_id: Literal["user_a", "user_b"]
    token: _RuntimeSecret | str | None = field(default=None, repr=False)
    cookies: dict[str, _RuntimeSecret | str] = field(default_factory=dict, repr=False)

    def __post_init__(self) -> None:
        if isinstance(self.token, str):
            self.token = _RuntimeSecret(self.token)
        self.cookies = {
            name: value if isinstance(value, _RuntimeSecret) else _RuntimeSecret(value)
            for name, value in self.cookies.items()
        }

    def authorization_headers(self) -> dict[str, str]:
        headers: dict[str, str] = {}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token.reveal()}"
        return headers


@dataclass
class RuntimeDiscoveryMetadata(_RuntimeOnly):
    actor_id: Literal["user_a", "user_b"]
    operation_id: str
    object_ids: dict[str, set[_RuntimeSecret]] = field(default_factory=dict, repr=False)
    parameter_examples: dict[tuple[str, str, str], set[_RuntimeSecret]] = field(
        default_factory=dict,
        repr=False,
    )


@dataclass
class RuntimeContext(_RuntimeOnly):
    scan_id: str
    sessions: dict[str, ActorSession] = field(default_factory=dict, repr=False)
    credentials: set[_RuntimeSecret] = field(default_factory=set, repr=False)
    object_ids: dict[str, dict[str, set[_RuntimeSecret]]] = field(default_factory=dict, repr=False)
    parameter_examples: dict[tuple[str, str, str], set[_RuntimeSecret]] = field(
        default_factory=dict,
        repr=False,
    )
    openapi_parameter_examples: dict[
        tuple[str, str, str], set[_RuntimeSecret]
    ] = field(default_factory=dict, repr=False)
    observed_parameter_examples: dict[
        tuple[str, str, str], set[_RuntimeSecret]
    ] = field(default_factory=dict, repr=False)
    required_inputs: dict[str, set[tuple[str, str]]] = field(
        default_factory=dict,
        repr=False,
    )

    def sensitive_values(self) -> set[str]:
        values = {credential.reveal() for credential in self.credentials}
        for session in self.sessions.values():
            if session.token:
                values.add(session.token.reveal())
            values.update(value.reveal() for value in session.cookies.values())
        for actor_objects in self.object_ids.values():
            for identifiers in actor_objects.values():
                values.update(identifier.reveal() for identifier in identifiers)
        for examples in self.parameter_examples.values():
            values.update(example.reveal() for example in examples)
        return values


class SessionManager:
    _OBJECT_KEYS = {
        "account_id": "account",
        "transaction_id": "transaction",
        "card_id": "card",
    }
    _OBSERVED_LOCATIONS = ("path", "query", "header", "body")

    def __init__(self, http_client: SafeHttpClient) -> None:
        self._http_client = http_client

    def authenticate(self, profile: TargetProfile) -> RuntimeContext:
        runtime = self._authenticate_runtime(profile)
        if runtime is None:
            raise AuthenticationError("runtime authentication failed")
        return runtime

    def _authenticate_runtime(self, profile: TargetProfile) -> RuntimeContext | None:
        runtime = RuntimeContext(scan_id=profile.scan_id)
        try:
            for actor in profile.authentication.actors:
                username = self._environment_value(actor.username_env)
                password = self._environment_value(actor.password_env)
                runtime.credentials.update({_RuntimeSecret(username), _RuntimeSecret(password)})
                runtime.sessions[actor.actor_id] = self._authenticate_actor(
                    profile, actor.actor_id, username, password
                )
        except Exception:
            return None
        return runtime

    def collect_response(
        self,
        runtime: RuntimeContext,
        *,
        actor_id: Literal["user_a", "user_b"],
        operation_id: str,
        body: object,
        observed_path: Mapping[str, object] | None = None,
        observed_query: Mapping[str, object] | None = None,
        observed_header: Mapping[str, object] | None = None,
        observed_body: Mapping[str, object] | None = None,
    ) -> RuntimeDiscoveryMetadata:
        actor_objects = runtime.object_ids.setdefault(actor_id, {})
        metadata = RuntimeDiscoveryMetadata(actor_id=actor_id, operation_id=operation_id)
        self._collect_object_ids(body, actor_objects, metadata.object_ids)
        for location, observed in zip(
            self._OBSERVED_LOCATIONS,
            (observed_path, observed_query, observed_header, observed_body),
            strict=True,
        ):
            self._collect_examples(
                runtime.parameter_examples,
                runtime.observed_parameter_examples,
                metadata.parameter_examples,
                operation_id,
                location,
                observed,
            )
        return metadata

    @staticmethod
    def _environment_value(name: str) -> str:
        value = os.environ.get(name)
        if not value:
            raise ValueError("missing runtime credential")
        return value

    def _authenticate_actor(
        self,
        profile: TargetProfile,
        actor_id: Literal["user_a", "user_b"],
        username: str,
        password: str,
    ) -> ActorSession:
        login = profile.authentication.login
        if login.content_type.casefold() != "application/json":
            raise ValueError("unsupported login content type")

        captured_token: _RuntimeSecret | None = None
        login_failed = False

        def consume_login_response(response: httpx.Response) -> None:
            nonlocal captured_token, login_failed
            if not 200 <= response.status_code < 300:
                login_failed = True
                return
            try:
                payload = response.json()
            except ValueError:
                login_failed = True
                return
            if not isinstance(payload, Mapping):
                login_failed = True
                return
            token = payload.get(login.session.token_field)
            if not isinstance(token, str) or not token:
                login_failed = True
                return
            captured_token = _RuntimeSecret(token)

        self._http_client.request(
            login.method,
            self._login_url(profile),
            is_login=True,
            headers={"Content-Type": login.content_type},
            json_body={
                login.username_field: username,
                login.password_field: password,
            },
            sensitive_values={username, password},
            login_response_consumer=consume_login_response,
        )
        if login_failed or captured_token is None:
            raise ValueError("missing login session")
        return ActorSession(
            actor_id=actor_id,
            token=captured_token,
        )

    @staticmethod
    def _login_url(profile: TargetProfile) -> str:
        return urljoin(
            f"{profile.target.base_url.rstrip('/')}/",
            profile.authentication.login.path.lstrip("/"),
        )

    def _collect_object_ids(
        self,
        value: object,
        actor_objects: dict[str, set[_RuntimeSecret]],
        metadata_objects: dict[str, set[_RuntimeSecret]],
    ) -> None:
        if isinstance(value, Mapping):
            for key, item in value.items():
                object_type = self._OBJECT_KEYS.get(key) if isinstance(key, str) else None
                if object_type is not None and self._is_scalar(item):
                    identifier = _RuntimeSecret(str(item))
                    actor_objects.setdefault(object_type, set()).add(identifier)
                    metadata_objects.setdefault(object_type, set()).add(identifier)
                self._collect_object_ids(item, actor_objects, metadata_objects)
        elif isinstance(value, (list, tuple)):
            for item in value:
                self._collect_object_ids(item, actor_objects, metadata_objects)

    @staticmethod
    def _collect_examples(
        runtime_examples: dict[tuple[str, str, str], set[_RuntimeSecret]],
        observed_examples: dict[tuple[str, str, str], set[_RuntimeSecret]],
        metadata_examples: dict[tuple[str, str, str], set[_RuntimeSecret]],
        operation_id: str,
        location: str,
        observed: Mapping[str, object] | None,
    ) -> None:
        if observed is None:
            return
        for field_name, value in observed.items():
            if SessionManager._is_scalar(value):
                key = (operation_id, location, field_name)
                example = _RuntimeSecret(str(value))
                runtime_examples.setdefault(key, set()).add(example)
                observed_examples.setdefault(key, set()).add(example)
                metadata_examples.setdefault(key, set()).add(example)

    @staticmethod
    def _is_scalar(value: object) -> bool:
        return isinstance(value, (str, int, float)) and not isinstance(value, bool)
