"""Environment-based configuration. Secrets are read from env only and never logged."""

from functools import lru_cache
from typing import Literal

from pydantic import Field, SecretStr, computed_field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=None, extra="ignore")

    environment: Literal["local", "test", "production"] = "local"
    log_level: str = "INFO"

    # Supabase project (local stack by default: `npm run db:start`).
    supabase_url: str = Field(default="http://127.0.0.1:54321")
    # Legacy HS256 secret. Optional. Only used when the project has not moved to asymmetric signing keys.
    supabase_jwt_secret: SecretStr | None = None
    # Server-only admin key. Used by the Supabase admin adapter for account deletion and storage signing.
    # Must never be sent to the frontend or the browser worker.
    supabase_service_role_key: SecretStr | None = None
    # Admin bearer for GoTrue's admin API. With asymmetric signing the admin API accepts only ES256 service-role
    # tokens, so this is a service_role JWT signed by the project's signing key. Same secrecy rules as the key above.
    supabase_admin_jwt: SecretStr | None = None

    # Runtime database role `app_api`. Subject to RLS. Never a superuser, never BYPASSRLS.
    database_url: SecretStr = Field(
        default=SecretStr("postgresql+psycopg://app_api:change-me@127.0.0.1:54322/postgres")
    )
    # Owner role used only by Alembic migrations. The application never connects with it.
    migration_database_url: SecretStr | None = None

    cors_origins: list[str] = Field(default_factory=lambda: ["http://127.0.0.1:3000", "http://localhost:3000"])

    @computed_field  # type: ignore[prop-decorator]
    @property
    def jwt_issuer(self) -> str:
        return f"{self.supabase_url.rstrip('/')}/auth/v1"

    @computed_field  # type: ignore[prop-decorator]
    @property
    def jwks_url(self) -> str:
        return f"{self.jwt_issuer}/.well-known/jwks.json"


@lru_cache
def get_settings() -> Settings:
    return Settings()
