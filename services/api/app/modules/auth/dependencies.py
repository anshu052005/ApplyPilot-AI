from collections.abc import Iterator
from functools import lru_cache

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.db.session import get_db_for_user
from app.modules.auth.jwt_verifier import SupabaseJwtVerifier, TokenError, jwks_key_resolver
from app.shared.identity import CurrentUser

_bearer = HTTPBearer(auto_error=False)
_UNAUTHORIZED = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Not authenticated",
    headers={"WWW-Authenticate": "Bearer"},
)


@lru_cache
def get_verifier() -> SupabaseJwtVerifier:
    settings = get_settings()
    secret = settings.supabase_jwt_secret.get_secret_value() if settings.supabase_jwt_secret else None
    return SupabaseJwtVerifier(
        issuer=settings.jwt_issuer,
        key_resolver=jwks_key_resolver(settings.jwks_url),
        legacy_hs256_secret=secret,
    )


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
    verifier: SupabaseJwtVerifier = Depends(get_verifier),
) -> CurrentUser:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise _UNAUTHORIZED
    try:
        claims = verifier.verify(credentials.credentials)
    except TokenError:
        # Do not return the reason to the client. It is useful only to an attacker.
        raise _UNAUTHORIZED from None
    return CurrentUser(id=claims.user_id, email=claims.email)


def get_user_db(user: CurrentUser = Depends(get_current_user)) -> Iterator[Session]:
    """Database session bound to the verified user. All application queries use this dependency."""
    yield from get_db_for_user(user.id)
