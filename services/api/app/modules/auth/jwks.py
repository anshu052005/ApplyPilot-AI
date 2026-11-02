"""JWKS (public signing key) cache with rotation handling.

Rules:
- Only public keys are accepted. A JWKS document that contains private key material (`d`, `p`, `q`, ...)
  is rejected as a whole, because it means the server is misconfigured and must not be trusted.
- Only asymmetric algorithms are accepted (ES256, RS256). Symmetric keys (`kty: oct`) and `none` are refused.
- Keys are cached for `ttl_seconds`. Refreshes are throttled to one per `min_refresh_seconds`, so a flood of
  tokens with unknown `kid` values cannot turn into a flood of requests to Supabase.
- If a refresh fails, the previous keys keep working for at most `max_stale_seconds`. After that the cache
  fails closed. This keeps a short Supabase outage from logging everyone out, while a revoked key still
  stops being accepted in the long run.
"""

import logging
import threading
import time
from collections.abc import Callable
from typing import Any

import httpx
import jwt

from app.modules.auth.jwt_verifier import TokenError

logger = logging.getLogger(__name__)

ALLOWED_KEY_TYPES = {"EC": {"ES256"}, "RSA": {"RS256"}}
PRIVATE_MEMBERS = {"d", "p", "q", "dp", "dq", "qi", "k"}


class JwksDocumentError(Exception):
    """The JWKS document is malformed, or it contains private or unsupported key material."""


def parse_public_keys(document: dict[str, Any]) -> dict[str, Any]:
    """Converts a JWKS document into {kid: public key object}. Raises JwksDocumentError on any violation."""
    entries = document.get("keys")
    if not isinstance(entries, list):
        raise JwksDocumentError("JWKS has no 'keys' list")

    keys: dict[str, Any] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            raise JwksDocumentError("JWKS entry is not an object")
        if PRIVATE_MEMBERS & entry.keys():
            raise JwksDocumentError("JWKS publishes private key material; refusing the whole document")
        kty = entry.get("kty")
        if kty not in ALLOWED_KEY_TYPES:
            raise JwksDocumentError(f"unsupported key type {kty!r}")
        alg = entry.get("alg")
        if alg is not None and alg not in ALLOWED_KEY_TYPES[kty]:
            raise JwksDocumentError(f"unsupported algorithm {alg!r} for key type {kty}")
        kid = entry.get("kid")
        if not isinstance(kid, str) or not kid:
            raise JwksDocumentError("JWKS entry has no kid")
        try:
            keys[kid] = jwt.PyJWK(entry).key
        except Exception as exc:  # noqa: BLE001  (any parse failure means the document is unusable)
            raise JwksDocumentError(f"cannot load key {kid!r}") from exc
    return keys


class JwksCache:
    def __init__(
        self,
        fetch_document: Callable[[], dict[str, Any]],
        *,
        ttl_seconds: float = 600,
        min_refresh_seconds: float = 60,
        max_stale_seconds: float = 3600,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._fetch = fetch_document
        self._ttl = ttl_seconds
        self._min_refresh = min_refresh_seconds
        self._max_stale = max_stale_seconds
        self._clock = clock
        self._lock = threading.Lock()
        self._keys: dict[str, Any] = {}
        self._fetched_at: float | None = None
        self._last_attempt: float | None = None

    def key_for(self, kid: str) -> Any:
        with self._lock:
            now = self._clock()
            cache_is_stale = self._fetched_at is None or now - self._fetched_at >= self._ttl
            kid_missing = kid not in self._keys
            if (cache_is_stale or kid_missing) and self._refresh_allowed(now):
                self._refresh(now)
            if self._fetched_at is None or now - self._fetched_at > self._max_stale:
                raise TokenError("signing keys unavailable")
            key = self._keys.get(kid)
            if key is None:
                raise TokenError("unknown signing key")
            return key

    def _refresh_allowed(self, now: float) -> bool:
        return self._last_attempt is None or now - self._last_attempt >= self._min_refresh

    def _refresh(self, now: float) -> None:
        self._last_attempt = now
        try:
            document = self._fetch()
            keys = parse_public_keys(document)
        except (httpx.HTTPError, JwksDocumentError, ValueError) as exc:
            # Keep the previous keys. key_for() enforces max_stale_seconds.
            logger.warning("JWKS refresh failed: %s", type(exc).__name__)
            return
        if not keys:
            logger.warning("JWKS refresh returned no usable keys; keeping previous keys")
            return
        self._keys = keys  # replaced atomically under the lock
        self._fetched_at = now


def http_document_fetcher(url: str, client: httpx.Client | None = None) -> Callable[[], dict[str, Any]]:
    http = client or httpx.Client(timeout=5.0)

    def fetch() -> dict[str, Any]:
        response = http.get(url)
        response.raise_for_status()
        body = response.json()
        if not isinstance(body, dict):
            raise JwksDocumentError("JWKS response is not an object")
        return body

    return fetch
