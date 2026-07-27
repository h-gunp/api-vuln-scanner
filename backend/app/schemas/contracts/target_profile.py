from typing import Literal

from pydantic import Field, model_validator

from app.schemas.common import APIModel


class TargetScope(APIModel):
    base_url: str
    allowed_paths: list[str] = Field(min_length=1)
    allowed_methods: list[Literal["GET"]] = Field(default_factory=lambda: ["GET"])


class DiscoveryPolicy(APIModel):
    sources: list[Literal["openapi", "crawl"]] = Field(
        default_factory=lambda: ["openapi", "crawl"]
    )
    max_depth: int = Field(default=3, ge=0)


class SessionConfig(APIModel):
    type: Literal["bearer"]
    token_field: str


class LoginConfig(APIModel):
    method: Literal["POST"]
    path: str
    content_type: Literal["application/json"]
    username_field: str
    password_field: str
    session: SessionConfig


class ActorConfig(APIModel):
    actor_id: str
    username_env: str
    password_env: str


class AuthenticationConfig(APIModel):
    login: LoginConfig
    actors: list[ActorConfig] = Field(min_length=2)


class SafetyPolicy(APIModel):
    max_requests: int = Field(gt=0)
    requests_per_second: int = Field(gt=0)
    state_change_policy: Literal["deny"] = "deny"
    approved_modules: list[str] = Field(min_length=1)


class TargetProfile(APIModel):
    schema_version: Literal["1.1"] = "1.1"
    scan_id: str
    target: TargetScope
    discovery: DiscoveryPolicy
    authentication: AuthenticationConfig
    safety_policy: SafetyPolicy

    @model_validator(mode="after")
    def protect_credentials(self) -> "TargetProfile":
        for actor in self.authentication.actors:
            if not actor.username_env or not actor.password_env:
                raise ValueError("Actor credentials must reference environment variable names")
        return self

