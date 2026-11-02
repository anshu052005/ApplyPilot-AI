"""Short-lived administrative tokens, minted on demand on the server.

Nothing long-lived is stored. Each token lives at most ADMIN_TOKEN_LIFETIME_SECONDS (15 minutes). The issuer keeps
the most recent token in memory only, and renews it when less than RENEW_BEFORE_EXPIRY_SECONDS remains. Tokens are
never written to disk, logged, or returned to a client.

Two credentials are needed because the two services verify differently:
- GoTrue (Auth admin API) verifies asymmetric signatures only. It accepts an ES256 service_role token signed by the
  project's signing key. That key is loaded from SUPABASE_SIGNING_KEYS_PATH, a file mounted by the secret store.
- Storage verifies HS256 only. It accepts a service_role token signed with the project's JWT secret, read from
  SUPABASE_STORAGE_SIGNING_SECRET. That secret must not be exposed to clients.

The public anon key is sent as `apikey` on every call, because the gateway requires an apikey header.
"""

import json
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import jwt
from jwt.algorithms import ECAlgorithm

ADMIN_TOKEN_LIFETIME_SECONDS = 15 * 60
RENEW_BEFORE_EXPIRY_SECONDS = 5 * 60
# Claim `iss` used for the Storage service token. Matches the local stack's service key issuer.
STORAGE_TOKEN_ISSUER = "supabase-demo"


class AdminCredentialError(RuntimeError):
    """A required administrative credential is missing or unusable."""


@dataclass
class _CachedToken:
    token: str
    expires_at: float


def load_signing_key(path: Path) -> tuple[str, Any]:
    """Loads the project's private signing key. Returns (kid, private key). The file must contain a private key."""
    try:
        keys = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AdminCredentialError("signing key file is missing or unreadable") from exc
    if not isinstance(keys, list) or not keys:
        raise AdminCredentialError("signing key file has no keys")
    jwk = keys[0]
    if jwk.get("kty") != "EC" or "d" not in jwk or not jwk.get("kid"):
        raise AdminCredentialError("signing key file must contain an EC private key with a kid")
    return jwk["kid"], ECAlgorithm.from_jwk(json.dumps(jwk))


class AdminTokenIssuer:
    def __init__(
        self,
        *,
        auth_issuer: str,
        signing_key_path: Path | None,
        storage_signing_secret: str | None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._auth_issuer = auth_issuer
        self._signing_key_path = signing_key_path
        self._storage_secret = storage_signing_secret
        self._clock = clock
        self._lock = threading.Lock()
        self._auth_cache: _CachedToken | None = None
        self._storage_cache: _CachedToken | None = None
        self._signing_key: tuple[str, Any] | None = None

    def auth_admin_token(self) -> str:
        return self._get(
            "_auth_cache",
            lambda now: self._mint_auth_token(now),
        )

    def storage_admin_token(self) -> str:
        return self._get(
            "_storage_cache",
            lambda now: self._mint_storage_token(now),
        )

    def _get(self, slot: str, mint: Callable[[int], _CachedToken]) -> str:
        with self._lock:
            now = self._clock()
            cached: _CachedToken | None = getattr(self, slot)
            if cached is None or cached.expires_at - now <= RENEW_BEFORE_EXPIRY_SECONDS:
                cached = mint(int(now))
                setattr(self, slot, cached)
            return cached.token

    def _mint_auth_token(self, now: int) -> _CachedToken:
        if self._signing_key_path is None:
            raise AdminCredentialError("SUPABASE_SIGNING_KEYS_PATH is not set")
        if self._signing_key is None:
            self._signing_key = load_signing_key(self._signing_key_path)
        kid, private_key = self._signing_key
        exp = now + ADMIN_TOKEN_LIFETIME_SECONDS
        token = jwt.encode(
            {"iss": self._auth_issuer, "role": "service_role", "iat": now, "exp": exp},
            private_key,
            algorithm="ES256",
            headers={"kid": kid},
        )
        return _CachedToken(token=token, expires_at=float(exp))

    def _mint_storage_token(self, now: int) -> _CachedToken:
        if not self._storage_secret:
            raise AdminCredentialError("SUPABASE_STORAGE_SIGNING_SECRET is not set")
        exp = now + ADMIN_TOKEN_LIFETIME_SECONDS
        token = jwt.encode(
            {"iss": STORAGE_TOKEN_ISSUER, "role": "service_role", "iat": now, "exp": exp},
            self._storage_secret,
            algorithm="HS256",
        )
        return _CachedToken(token=token, expires_at=float(exp))
