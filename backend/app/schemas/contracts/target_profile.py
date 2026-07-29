from typing import Literal

from pydantic import Field, model_validator

from app.schemas.common import ArtifactModel


class TargetScope(ArtifactModel):
    base_url: str
    allowed_paths: list[str] = Field(min_length=1)
    allowed_methods: list[Literal["GET"]]


class DiscoveryPolicy(ArtifactModel):
    sources: list[Literal["openapi", "crawl"]]
    max_depth: int = Field(ge=0)


class SessionConfig(ArtifactModel):
    type: Literal["bearer"]
    token_field: str


class LoginConfig(ArtifactModel):
    method: Literal["POST"]
    path: str
    content_type: Literal["application/json"]
    username_field: str
    password_field: str
    session: SessionConfig


class ActorConfig(ArtifactModel):
    actor_id: str
    username_env: str
    password_env: str


class AuthenticationConfig(ArtifactModel):
    login: LoginConfig
    actors: list[ActorConfig] = Field(min_length=2, max_length=2)

    @model_validator(mode="after")
    def require_fixed_actor_set(self) -> "AuthenticationConfig":
        if {actor.actor_id for actor in self.actors} != {"user_a", "user_b"}:
            raise ValueError("actors must contain exactly user_a and user_b")
        return self


class SafetyPolicy(ArtifactModel):
    max_requests: int = Field(gt=0)
    requests_per_second: int = Field(gt=0)
    state_change_policy: Literal["deny"]
    approved_modules: list[
        Literal["authz", "input_validation", "data_exposure"]
    ] = Field(min_length=1)


class TargetProfile(ArtifactModel):
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

