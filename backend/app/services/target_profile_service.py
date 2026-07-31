import uuid
from urllib.parse import urlsplit

from app.core.config import Settings
from app.schemas.contracts.target_profile import (
    ActorConfig,
    AuthenticationConfig,
    DiscoveryPolicy,
    LoginConfig,
    SafetyPolicy,
    SessionConfig,
    TargetProfile,
    TargetScope,
)


class TargetProfileService:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def build(self, scan_id: uuid.UUID, target_url: str) -> TargetProfile:
        parsed = urlsplit(target_url)
        base_path = parsed.path.rstrip("/")
        allowed_pattern = f"{base_path}/*" if base_path else "/*"
        return TargetProfile(
            scan_id=str(scan_id),
            target=TargetScope(
                base_url=target_url,
                allowed_paths=[allowed_pattern],
                allowed_methods=["GET"],
            ),
            discovery=DiscoveryPolicy(
                sources=["openapi", "crawl"],
                max_depth=self.settings.discovery_max_depth,
            ),
            authentication=AuthenticationConfig(
                login=LoginConfig(
                    method="POST",
                    path="/api/login",
                    content_type="application/json",
                    username_field="username",
                    password_field="password",
                    session=SessionConfig(type="bearer", token_field="token"),
                ),
                actors=[
                    ActorConfig(
                        actor_id="user_a",
                        username_env=self.settings.user_a_username_env,
                        password_env=self.settings.user_a_password_env,
                    ),
                    ActorConfig(
                        actor_id="user_b",
                        username_env=self.settings.user_b_username_env,
                        password_env=self.settings.user_b_password_env,
                    ),
                ],
            ),
            safety_policy=SafetyPolicy(
                max_requests=self.settings.max_requests,
                requests_per_second=self.settings.requests_per_second,
                state_change_policy="deny",
                # TODO: Final module ID/category mapping contract pending.
                approved_modules=["authz", "input_validation", "data_exposure"],
            ),
        )

