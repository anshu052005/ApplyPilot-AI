"""Environment-based configuration. Secrets are read from env only and never logged."""

from functools import lru_cache
from pathlib import Path
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
    # Public anon key. Sent as the `apikey` header on admin calls. Not a secret.
    supabase_anon_key: str | None = None
    # Path to the private signing key file (JWK array). Read only by the admin token issuer. Mounted by the
    # secret store in production. Never sent to clients, logs, or the browser worker.
    supabase_signing_keys_path: Path | None = None
    # Storage verifies HS256 only. This secret mints short-lived Storage service tokens on the server.
    supabase_storage_signing_secret: SecretStr | None = None

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
