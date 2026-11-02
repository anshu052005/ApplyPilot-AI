"""Signing key rotation, checked against the real local Auth service where the local build allows it.

Limitation, stated plainly: the local GoTrue build (v2.178) supports exactly one signing key and refuses to start
with two ("only 1 signing key is supported"). A live overlap window therefore cannot be produced locally.
What this module checks:
- Real GoTrue tokens and the real published JWKS for the current key.
- A second key that the test publishes alongside the real one, and signs with itself. The verifier and JWKS cache
  are the same code production uses. Only the publisher is simulated.
The live key swap (old key removed, tokens from the old key revoked) is performed by
scripts/local/rotate_signing_key.py and recorded in the verification report.
"""

import time
import uuid

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from jwt.algorithms import ECAlgorithm

from app.core.config import get_settings
from app.modules.auth.jwks import JwksCache, http_document_fetcher
from app.modules.auth.jwt_verifier import SupabaseJwtVerifier, TokenError


class FakeClock:
    def __init__(self) -> None:
        self.now = time.monotonic()

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class CountingFetcher:
    """Wraps the real JWKS fetch. Counts calls. Can serve a modified document or fail."""

    def __init__(self) -> None:
        self._real = http_document_fetcher(get_settings().jwks_url)
        self.calls = 0
        self.transform = lambda doc: doc
        self.fail = False

    def __call__(self) -> dict:
        self.calls += 1
        if self.fail:
            raise httpx.ConnectError("jwks unreachable")
        return self.transform(self._real())


def _second_key():
    private = ec.generate_private_key(ec.SECP256R1())
    public = ECAlgorithm.to_jwk(private.public_key())
    import json

    jwk = json.loads(public)
    kid = f"rotation-test-{uuid.uuid4().hex[:8]}"
    jwk.update({"kid": kid, "alg": "ES256", "use": "sig"})
    return kid, private, jwk


def _sign(kid: str, private, *, sub: str) -> str:
    now = int(time.time())
    return jwt.encode(
        {
            "sub": sub,
            "aud": "authenticated",
            "iss": get_settings().jwt_issuer,
            "iat": now,
            "exp": now + 600,
            "role": "authenticated",
        },
        private,
        algorithm="ES256",
        headers={"kid": kid},
    )


@pytest.fixture
def live_token(user_a):
    """A real token issued by the local Auth service with the current signing key."""
    return user_a.access_token


@pytest.fixture
def fetcher():
    return CountingFetcher()


@pytest.fixture
def clock():
    return FakeClock()


@pytest.fixture
def verifier(fetcher, clock):
    cache = JwksCache(fetcher, clock=clock, ttl_seconds=600, min_refresh_seconds=60, max_stale_seconds=3600)
    return SupabaseJwtVerifier(issuer=get_settings().jwt_issuer, key_resolver=cache.key_for)


def test_live_tokens_are_signed_by_a_key_in_the_published_jwks(live_token, fetcher, verifier):
    header = jwt.get_unverified_header(live_token)
    published = {key["kid"] for key in fetcher()["keys"]}
    assert header["alg"] == "ES256"
    assert header["kid"] in published
    assert str(verifier.verify(live_token).user_id)


def test_rotation_window_old_tokens_still_verify_and_new_tokens_use_the_new_key(
    live_token, fetcher, verifier, clock
):
    kid_new, private_new, jwk_new = _second_key()
    user_id = str(uuid.uuid4())
    old_kid = jwt.get_unverified_header(live_token)["kid"]

    fetcher.transform = lambda doc: {"keys": doc["keys"] + [jwk_new]}  # overlap: both keys published
    clock.advance(601)  # cache expires, so the new document is fetched

    assert verifier.verify(live_token).user_id is not None  # old token, old key: still valid
    new_token = _sign(kid_new, private_new, sub=user_id)
    assert jwt.get_unverified_header(new_token)["kid"] == kid_new
    assert str(verifier.verify(new_token).user_id) == user_id
    assert old_kid != kid_new


def test_revoked_key_is_rejected_after_rotation(live_token, fetcher, verifier, clock):
    kid_new, private_new, jwk_new = _second_key()
    user_id = str(uuid.uuid4())

    fetcher.transform = lambda doc: {"keys": [jwk_new]}  # old key removed from the published set
    clock.advance(601)

    with pytest.raises(TokenError):
        verifier.verify(live_token)
    assert str(verifier.verify(_sign(kid_new, private_new, sub=user_id)).user_id) == user_id


def test_unknown_kid_flood_causes_at_most_one_refresh(live_token, fetcher, verifier):
    verifier.verify(live_token)  # warm the cache
    before = fetcher.calls
    forged = _sign("never-published-kid", ec.generate_private_key(ec.SECP256R1()), sub=str(uuid.uuid4()))
    for _ in range(25):
        with pytest.raises(TokenError):
            verifier.verify(forged)
    assert fetcher.calls - before <= 1


def test_cache_serves_known_keys_without_refetching(live_token, fetcher, verifier):
    verifier.verify(live_token)
    before = fetcher.calls
    for _ in range(10):
        verifier.verify(live_token)
    assert fetcher.calls == before


def test_known_keys_survive_a_jwks_outage_within_the_grace_period(live_token, fetcher, verifier, clock):
    verifier.verify(live_token)
    fetcher.fail = True
    clock.advance(700)  # TTL expired, refresh fails, still within max_stale
    assert verifier.verify(live_token) is not None
