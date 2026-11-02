from collections.abc import Iterator
from functools import lru_cache

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.db.session import get_db_for_user
from app.modules.auth import service as account_service
from app.modules.auth.jwks import JwksCache, http_document_fetcher
from app.modules.auth.jwt_verifier import SupabaseJwtVerifier, TokenError
from app.shared.identity import CurrentUser

_bearer = HTTPBearer(auto_error=False)
_UNAUTHORIZED = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Not authenticated",
    headers={"WWW-Authenticate": "Bearer"},
)


@lru_cache
def get_jwks_cache() -> JwksCache:
    return JwksCache(http_document_fetcher(get_settings().jwks_url))


@lru_cache
def get_verifier() -> SupabaseJwtVerifier:
    settings = get_settings()
    secret = settings.supabase_jwt_secret.get_secret_value() if settings.supabase_jwt_secret else None
    return SupabaseJwtVerifier(
        issuer=settings.jwt_issuer,
        key_resolver=get_jwks_cache().key_for,
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


def get_active_db(
    user: CurrentUser = Depends(get_current_user),
    db: Session = Depends(get_user_db),
) -> Session:
    """Session for data endpoints. Locks the account (HTTP 423) while its deletion is pending."""
    try:
        account_service.require_account_not_pending(db, user)
    except account_service.AccountDeletionPending:
        raise HTTPException(
            status_code=status.HTTP_423_LOCKED,
            detail="Account deletion is in progress. Your data is locked until it completes.",
        ) from None
    return db
