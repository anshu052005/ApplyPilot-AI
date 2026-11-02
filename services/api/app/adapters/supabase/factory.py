"""Process-wide singletons for the admin token issuer and admin client. Tests may override `get_admin_client`."""

from functools import lru_cache

from app.adapters.supabase.admin import SupabaseAdminClient
from app.adapters.supabase.admin_tokens import AdminTokenIssuer
from app.core.config import get_settings


@lru_cache
def get_token_issuer() -> AdminTokenIssuer:
    settings = get_settings()
    secret = settings.supabase_storage_signing_secret.get_secret_value() if settings.supabase_storage_signing_secret else None
    return AdminTokenIssuer(
        auth_issuer=settings.jwt_issuer,
        signing_key_path=settings.supabase_signing_keys_path,
        storage_signing_secret=secret,
    )


@lru_cache
def get_admin_client() -> SupabaseAdminClient:
    return SupabaseAdminClient(get_settings(), get_token_issuer())
