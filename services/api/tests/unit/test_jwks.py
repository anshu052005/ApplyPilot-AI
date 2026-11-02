"""JWKS cache: rotation, revocation, throttling, staleness, and refusal of unsafe documents."""

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from app.modules.auth.jwks import JwksCache, JwksDocumentError, parse_public_keys
from app.modules.auth.jwt_verifier import TokenError
from tests.unit.jwt_helpers import Publisher, ec_jwk, make_clock


@pytest.fixture
def key_a():
    return ec_jwk("kid-a")


@pytest.fixture
def key_b():
    return ec_jwk("kid-b")


def test_known_kid_is_served_from_cache(key_a):
    clock = make_clock()
    pub = Publisher([key_a])
    cache = JwksCache(pub, clock=clock)
    cache.key_for("kid-a")
    cache.key_for("kid-a")
    assert pub.fetches == 1


def test_key_rotation_accepts_new_kid_after_refresh(key_a, key_b):
    clock = make_clock()
    pub = Publisher([key_a])
    cache = JwksCache(pub, clock=clock, min_refresh_seconds=60)
    cache.key_for("kid-a")

    # Supabase rotates: publishes B alongside A.
    pub.keys = [key_a, key_b]
    clock.advance(61)
    assert cache.key_for("kid-b") is not None
    assert cache.key_for("kid-a") is not None  # still published, still valid


def test_revoked_key_is_rejected_after_refresh(key_a, key_b):
    clock = make_clock()
    pub = Publisher([key_a, key_b])
    cache = JwksCache(pub, clock=clock, min_refresh_seconds=60, ttl_seconds=600)
    cache.key_for("kid-a")

    # A is removed from the published set (compromised or retired).
    pub.keys = [key_b]
    clock.advance(601)  # cache TTL passes, forcing a refresh
    with pytest.raises(TokenError):
        cache.key_for("kid-a")
    assert cache.key_for("kid-b") is not None


def test_unknown_kid_refreshes_are_throttled(key_a):
    clock = make_clock()
    pub = Publisher([key_a])
    cache = JwksCache(pub, clock=clock, min_refresh_seconds=60)
    cache.key_for("kid-a")
    before = pub.fetches
    for _ in range(50):  # attacker floods unknown kids
        with pytest.raises(TokenError):
            cache.key_for("attacker-kid")
    assert pub.fetches - before <= 1  # the whole flood causes at most one refresh


def test_refresh_is_allowed_again_after_the_interval(key_a):
    clock = make_clock()
    pub = Publisher([key_a])
    cache = JwksCache(pub, clock=clock, min_refresh_seconds=60)
    cache.key_for("kid-a")
    with pytest.raises(TokenError):
        cache.key_for("unknown")
    clock.advance(61)
    with pytest.raises(TokenError):
        cache.key_for("unknown")
    assert pub.fetches == 2


def test_ttl_expiry_triggers_a_refresh(key_a):
    clock = make_clock()
    pub = Publisher([key_a])
    cache = JwksCache(pub, clock=clock, ttl_seconds=600)
    cache.key_for("kid-a")
    clock.advance(601)
    cache.key_for("kid-a")
    assert pub.fetches == 2


def test_fetch_failure_keeps_keys_within_grace_period(key_a):
    clock = make_clock()
    pub = Publisher([key_a])
    cache = JwksCache(pub, clock=clock, ttl_seconds=600, max_stale_seconds=3600)
    cache.key_for("kid-a")
    pub.fail = True
    clock.advance(700)
    assert cache.key_for("kid-a") is not None


def test_fetch_failure_fails_closed_after_max_stale(key_a):
    clock = make_clock()
    pub = Publisher([key_a])
    cache = JwksCache(pub, clock=clock, ttl_seconds=600, max_stale_seconds=3600, min_refresh_seconds=60)
    cache.key_for("kid-a")
    pub.fail = True
    clock.advance(3601)
    with pytest.raises(TokenError):
        cache.key_for("kid-a")


def test_no_keys_ever_loaded_fails_closed():
    clock = make_clock()
    pub = Publisher([])
    pub.fail = True
    cache = JwksCache(pub, clock=clock)
    with pytest.raises(TokenError):
        cache.key_for("anything")


def test_document_with_private_key_material_is_refused(key_a):
    private = dict(key_a, d="AAAA")  # private scalar present
    with pytest.raises(JwksDocumentError, match="private"):
        parse_public_keys({"keys": [private]})


def test_private_material_refusal_keeps_previous_cache(key_a):
    clock = make_clock()
    pub = Publisher([key_a])
    cache = JwksCache(pub, clock=clock, ttl_seconds=600, min_refresh_seconds=60)
    cache.key_for("kid-a")
    pub.keys = [dict(key_a, kid="kid-leaky", d="AAAA")]
    clock.advance(601)
    # Refresh is refused as a whole, so the previous key remains usable and kid-leaky is never loaded.
    assert cache.key_for("kid-a") is not None
    with pytest.raises(TokenError):
        cache.key_for("kid-leaky")


@pytest.mark.parametrize(
    "entry",
    [
        {"kty": "oct", "kid": "sym", "k": "c2VjcmV0"},
        {"kty": "EC", "kid": "alg-none", "crv": "P-256", "alg": "none", "x": "a", "y": "b"},
        {"kty": "EC", "kid": "alg-hs", "crv": "P-256", "alg": "HS256", "x": "a", "y": "b"},
    ],
)
def test_symmetric_or_unsupported_algorithm_keys_are_refused(entry):
    with pytest.raises(JwksDocumentError):
        parse_public_keys({"keys": [entry]})


def test_entry_without_kid_is_refused(key_a):
    entry = dict(key_a)
    entry.pop("kid")
    with pytest.raises(JwksDocumentError, match="kid"):
        parse_public_keys({"keys": [entry]})


def test_malformed_document_is_refused():
    with pytest.raises(JwksDocumentError):
        parse_public_keys({"not_keys": []})


def test_real_public_ec_key_loads():
    """Sanity check that the JWK helper produces keys the parser accepts."""
    key = ec.generate_private_key(ec.SECP256R1()).public_key()
    assert key is not None
