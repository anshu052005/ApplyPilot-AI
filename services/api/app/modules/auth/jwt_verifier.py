"""Verification of Supabase-issued access tokens.

Rules (see plan §15):
- Asymmetric algorithms (RS256, ES256) are verified against the project's JWKS. This is the default.
- HS256 is accepted only when a legacy shared secret is configured, and only with that secret.
- `none`, unknown algorithms, and algorithm confusion (an HMAC check using a public key) are rejected.
- `exp`, `iat`, `sub`, `aud`, `iss` are required. `aud` must be `authenticated` and `role` must be `authenticated`.
"""

import uuid
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import jwt
from jwt import PyJWKClient
from jwt.exceptions import PyJWKClientError

ASYMMETRIC_ALGORITHMS = ["RS256", "ES256"]
LEGACY_ALGORITHMS = ["HS256"]
REQUIRED_CLAIMS = ["exp", "iat", "sub", "aud", "iss"]
EXPECTED_AUDIENCE = "authenticated"
EXPECTED_ROLE = "authenticated"


class TokenError(Exception):
    """Raised for any token that must not be accepted. Maps to HTTP 401."""


@dataclass(frozen=True)
class VerifiedClaims:
    user_id: uuid.UUID
    email: str | None


KeyResolver = Callable[[str], Any]


def jwks_key_resolver(jwks_url: str) -> KeyResolver:
    """Returns a resolver that fetches signing keys by `kid`. PyJWKClient refreshes on an unknown kid."""
    client = PyJWKClient(jwks_url, cache_keys=True, lifespan=300)

    def resolve(kid: str) -> Any:
        try:
            return client.get_signing_key(kid).key
        except PyJWKClientError as exc:
            raise TokenError("unknown signing key") from exc

    return resolve


class SupabaseJwtVerifier:
    def __init__(
        self,
        issuer: str,
        key_resolver: KeyResolver | None = None,
        legacy_hs256_secret: str | None = None,
        leeway_seconds: int = 10,
    ) -> None:
        self._issuer = issuer
        self._key_resolver = key_resolver
        self._legacy_secret = legacy_hs256_secret
        self._leeway = leeway_seconds

    def verify(self, token: str) -> VerifiedClaims:
        if not token or token.count(".") != 2:
            raise TokenError("malformed token")
        try:
            header = jwt.get_unverified_header(token)
        except jwt.InvalidTokenError as exc:
            raise TokenError("malformed token") from exc

        alg = header.get("alg")
        if alg in ASYMMETRIC_ALGORITHMS:
            if self._key_resolver is None:
                raise TokenError("asymmetric tokens are not configured")
            kid = header.get("kid")
            if not kid:
                raise TokenError("missing kid")
            key = self._key_resolver(kid)
            claims = self._decode(token, key, ASYMMETRIC_ALGORITHMS)
        elif alg in LEGACY_ALGORITHMS:
            if not self._legacy_secret:
                raise TokenError("HS256 tokens are not accepted")
            claims = self._decode(token, self._legacy_secret, LEGACY_ALGORITHMS)
        else:
            raise TokenError("unsupported algorithm")

        return self._to_verified(claims)

    def _decode(self, token: str, key: Any, algorithms: list[str]) -> dict[str, Any]:
        try:
            return jwt.decode(
                token,
                key,
                algorithms=algorithms,
                audience=EXPECTED_AUDIENCE,
                issuer=self._issuer,
                leeway=self._leeway,
                options={"require": REQUIRED_CLAIMS},
            )
        except jwt.InvalidTokenError as exc:
            raise TokenError(str(type(exc).__name__)) from exc

    @staticmethod
    def _to_verified(claims: dict[str, Any]) -> VerifiedClaims:
        if claims.get("role") != EXPECTED_ROLE:
            raise TokenError("role not allowed")
        try:
            user_id = uuid.UUID(str(claims["sub"]))
        except (ValueError, KeyError) as exc:
            raise TokenError("invalid subject") from exc
        email = claims.get("email")
        return VerifiedClaims(user_id=user_id, email=email if isinstance(email, str) else None)
