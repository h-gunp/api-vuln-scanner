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
    token: str | None = field(default=None, repr=False)
    cookies: dict[str, str] = field(default_factory=dict, repr=False)

    def authorization_headers(self) -> dict[str, str]:
        headers: dict[str, str] = {}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        if self.cookies:
            headers["Cookie"] = "; ".join(
                f"{name}={value}" for name, value in sorted(self.cookies.items())
            )
        return headers


@dataclass
class RuntimeDiscoveryMetadata(_RuntimeOnly):
    actor_id: Literal["user_a", "user_b"]
    operation_id: str
    object_ids: dict[str, set[str]] = field(default_factory=dict, repr=False)
    parameter_examples: dict[tuple[str, str, str], set[str]] = field(
        default_factory=dict,
        repr=False,
    )


@dataclass
class RuntimeContext(_RuntimeOnly):
    scan_id: str
    sessions: dict[str, ActorSession] = field(default_factory=dict, repr=False)
    credentials: set[str] = field(default_factory=set, repr=False)
    object_ids: dict[str, dict[str, set[str]]] = field(default_factory=dict, repr=False)
    parameter_examples: dict[tuple[str, str, str], set[str]] = field(
        default_factory=dict,
        repr=False,
    )
    required_inputs: dict[str, set[tuple[str, str]]] = field(
        default_factory=dict,
        repr=False,
    )

    def sensitive_values(self) -> set[str]:
        values = set(self.credentials)
        for session in self.sessions.values():
            if session.token:
                values.add(session.token)
            values.update(value for value in session.cookies.values() if value)
        for actor_objects in self.object_ids.values():
            for identifiers in actor_objects.values():
                values.update(identifiers)
        for examples in self.parameter_examples.values():
            values.update(examples)
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
        runtime = RuntimeContext(scan_id=profile.scan_id)
        try:
            for actor in profile.authentication.actors:
                username = self._environment_value(actor.username_env)
                password = self._environment_value(actor.password_env)
                runtime.credentials.update({username, password})
                runtime.sessions[actor.actor_id] = self._authenticate_actor(
                    profile, actor.actor_id, username, password
                )
        except Exception:
            raise AuthenticationError("runtime authentication failed") from None
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

        captured: dict[str, object] = {}

        def consume_login_response(response: httpx.Response) -> None:
            if not 200 <= response.status_code < 300:
                raise ValueError("login failed")
            try:
                payload = response.json()
            except ValueError:
                raise ValueError("malformed login response") from None
            if not isinstance(payload, Mapping):
                raise ValueError("malformed login response")
            token = payload.get(login.session.token_field)
            if not isinstance(token, str) or not token:
                raise ValueError("missing login session")
            captured["token"] = token
            captured["cookies"] = dict(response.cookies)

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
        token = captured.get("token")
        if not isinstance(token, str):
            raise ValueError("missing login session")
        cookies = captured.get("cookies")
        return ActorSession(
            actor_id=actor_id,
            token=token,
            cookies=dict(cookies) if isinstance(cookies, dict) else {},
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
        actor_objects: dict[str, set[str]],
        metadata_objects: dict[str, set[str]],
    ) -> None:
        if isinstance(value, Mapping):
            for key, item in value.items():
                object_type = self._OBJECT_KEYS.get(key) if isinstance(key, str) else None
                if object_type is not None and self._is_scalar(item):
                    identifier = str(item)
                    actor_objects.setdefault(object_type, set()).add(identifier)
                    metadata_objects.setdefault(object_type, set()).add(identifier)
                self._collect_object_ids(item, actor_objects, metadata_objects)
        elif isinstance(value, (list, tuple)):
            for item in value:
                self._collect_object_ids(item, actor_objects, metadata_objects)

    @staticmethod
    def _collect_examples(
        runtime_examples: dict[tuple[str, str, str], set[str]],
        metadata_examples: dict[tuple[str, str, str], set[str]],
        operation_id: str,
        location: str,
        observed: Mapping[str, object] | None,
    ) -> None:
        if observed is None:
            return
        for field_name, value in observed.items():
            if SessionManager._is_scalar(value):
                key = (operation_id, location, field_name)
                example = str(value)
                runtime_examples.setdefault(key, set()).add(example)
                metadata_examples.setdefault(key, set()).add(example)

    @staticmethod
    def _is_scalar(value: object) -> bool:
        return isinstance(value, (str, int, float)) and not isinstance(value, bool)
