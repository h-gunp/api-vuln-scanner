from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    app_env: Literal["development", "test", "production"] = "development"
    database_url: str = "postgresql+asyncpg://postgres:postgres@localhost:5432/security_scanner"
    redis_url: str = "redis://localhost:6379/0"
    artifact_root: Path = Path("artifacts")

    scanner_base_url: str = "http://scanner:8001"
    llm_base_url: str = "http://llm:8002"
    executor_base_url: str = "http://executor:8003"
    use_mock_integrations: bool = True
    task_mode: Literal["background", "arq", "disabled"] = "background"

    allow_private_targets: bool = False
    target_connect_timeout_seconds: float = Field(default=5.0, gt=0, le=60)
    max_requests: int = Field(default=300, gt=0)
    requests_per_second: int = Field(default=3, gt=0)
    discovery_max_depth: int = Field(default=3, ge=0, le=20)

    user_a_username_env: str = "USER_A_USERNAME"
    user_a_password_env: str = "USER_A_PASSWORD"
    user_b_username_env: str = "USER_B_USERNAME"
    user_b_password_env: str = "USER_B_PASSWORD"

    internal_auth_enabled: bool = False
    internal_service_token: str | None = None

    @field_validator("database_url")
    @classmethod
    def require_async_postgres_driver(cls, value: str) -> str:
        if not value.startswith("postgresql+asyncpg://"):
            raise ValueError("DATABASE_URL must use postgresql+asyncpg")
        return value


@lru_cache
def get_settings() -> Settings:
    return Settings()
