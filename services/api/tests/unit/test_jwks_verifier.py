"""End-to-end token checks through the JWKS cache: the path production uses for Supabase asymmetric tokens."""

import time

import pytest

from app.modules.auth.jwks import JwksCache
from app.modules.auth.jwt_verifier import SupabaseJwtVerifier, TokenError
from tests.unit.jwt_helpers import (
    ISSUER,
    USER_ID,
    Publisher,
    ec_jwk,
    make_clock,
    new_private_key,
    sign_es256,
    unique_kid,
)


@pytest.fixture
def setup():
    """A verifier backed by a JWKS cache that serves one published ES256 key."""
    kid = unique_kid()
    clock = make_clock()
    publisher = Publisher([ec_jwk(kid)])
    cache = JwksCache(publisher, clock=clock, min_refresh_seconds=60)
    verifier = SupabaseJwtVerifier(issuer=ISSUER, key_resolver=cache.key_for)
    return {"kid": kid, "clock": clock, "publisher": publisher, "cache": cache, "verifier": verifier}


def test_valid_token_is_accepted(setup):
    claims = setup["verifier"].verify(sign_es256(setup["kid"]))
    assert str(claims.user_id) == USER_ID
    assert claims.email == "a@example.com"


def test_invalid_signature_is_rejected(setup):
    """Same kid, but signed by a different private key. The published public key must not verify it."""
    forged = sign_es256(setup["kid"], key=new_private_key())
    with pytest.raises(TokenError):
        setup["verifier"].verify(forged)


def test_signature_with_tampered_claims_is_rejected(setup):
    token = sign_es256(setup["kid"])
    header, payload, signature = token.split(".")
    tampered_payload = payload[:-1] + ("A" if payload[-1] != "A" else "B")
    with pytest.raises(TokenError):
        setup["verifier"].verify(f"{header}.{tampered_payload}.{signature}")


def test_expired_token_is_rejected(setup):
    now = int(time.time())
    token = sign_es256(setup["kid"], {"iat": now - 7200, "exp": now - 3600})
    with pytest.raises(TokenError):
        setup["verifier"].verify(token)


def test_incorrect_issuer_is_rejected(setup):
    with pytest.raises(TokenError):
        setup["verifier"].verify(sign_es256(setup["kid"], {"iss": "https://attacker.example/auth/v1"}))


def test_incorrect_audience_is_rejected(setup):
    with pytest.raises(TokenError):
        setup["verifier"].verify(sign_es256(setup["kid"], {"aud": "service_role"}))


def test_anonymous_role_is_rejected(setup):
    with pytest.raises(TokenError):
        setup["verifier"].verify(sign_es256(setup["kid"], {"role": "anon"}))


def test_token_for_an_unpublished_kid_is_rejected(setup):
    with pytest.raises(TokenError):
        setup["verifier"].verify(sign_es256("unpublished-kid", key=new_private_key()))


def test_key_rotation_new_key_is_accepted_after_publish(setup):
    """Supabase rotates keys: a token signed with the new key fails until the JWKS is refreshed, then passes."""
    new_kid = unique_kid()
    new_key = ec_jwk(new_kid)  # generates and remembers the private half
    token = sign_es256(new_kid)

    with pytest.raises(TokenError):
        setup["verifier"].verify(token)  # not published yet

    setup["publisher"].keys = [setup["publisher"].keys[0], new_key]
    setup["clock"].advance(61)  # past the refresh throttle
    assert str(setup["verifier"].verify(token).user_id) == USER_ID


def test_old_key_still_accepted_while_published_during_rotation(setup):
    new_kid = unique_kid()
    setup["publisher"].keys = [setup["publisher"].keys[0], ec_jwk(new_kid)]
    setup["clock"].advance(61)
    assert str(setup["verifier"].verify(sign_es256(setup["kid"])).user_id) == USER_ID


def test_revoked_key_is_rejected_after_refresh(setup):
    new_kid = unique_kid()
    setup["publisher"].keys = [ec_jwk(new_kid)]  # old key removed
    setup["clock"].advance(601)  # cache TTL forces a refresh
    with pytest.raises(TokenError):
        setup["verifier"].verify(sign_es256(setup["kid"]))
    assert str(setup["verifier"].verify(sign_es256(new_kid)).user_id) == USER_ID
