import time
import uuid

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from app.modules.auth.jwt_verifier import SupabaseJwtVerifier, TokenError

ISSUER = "http://127.0.0.1:54321/auth/v1"
USER_ID = uuid.UUID("11111111-1111-4111-8111-111111111111")


@pytest.fixture(scope="module")
def rsa_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="module")
def ec_key():
    return ec.generate_private_key(ec.SECP256R1())


def _claims(**overrides):
    now = int(time.time())
    base = {
        "sub": str(USER_ID),
        "aud": "authenticated",
        "iss": ISSUER,
        "iat": now,
        "exp": now + 600,
        "role": "authenticated",
        "email": "a@example.com",
    }
    base.update(overrides)
    return {k: v for k, v in base.items() if v is not None}


def _verifier(public_key, legacy_secret=None):
    def resolve(kid):
        if kid != "good-kid":
            raise TokenError("unknown signing key")
        return public_key

    return SupabaseJwtVerifier(issuer=ISSUER, key_resolver=resolve, legacy_hs256_secret=legacy_secret)


def _rs256(private_key, claims, kid="good-kid"):
    return jwt.encode(claims, private_key, algorithm="RS256", headers={"kid": kid})


def test_valid_rs256_token_is_accepted(rsa_key):
    result = _verifier(rsa_key.public_key()).verify(_rs256(rsa_key, _claims()))
    assert result.user_id == USER_ID
    assert result.email == "a@example.com"


def test_valid_es256_token_is_accepted(ec_key):
    token = jwt.encode(_claims(), ec_key, algorithm="ES256", headers={"kid": "good-kid"})
    assert _verifier(ec_key.public_key()).verify(token).user_id == USER_ID


def test_expired_token_is_rejected(rsa_key):
    now = int(time.time())
    token = _rs256(rsa_key, _claims(exp=now - 3600, iat=now - 7200))
    with pytest.raises(TokenError):
        _verifier(rsa_key.public_key()).verify(token)


def test_wrong_audience_is_rejected(rsa_key):
    with pytest.raises(TokenError):
        _verifier(rsa_key.public_key()).verify(_rs256(rsa_key, _claims(aud="service_role")))


def test_wrong_issuer_is_rejected(rsa_key):
    with pytest.raises(TokenError):
        _verifier(rsa_key.public_key()).verify(_rs256(rsa_key, _claims(iss="https://evil.example/auth/v1")))


def test_anonymous_role_is_rejected(rsa_key):
    with pytest.raises(TokenError):
        _verifier(rsa_key.public_key()).verify(_rs256(rsa_key, _claims(role="anon")))


def test_missing_subject_is_rejected(rsa_key):
    with pytest.raises(TokenError):
        _verifier(rsa_key.public_key()).verify(_rs256(rsa_key, _claims(sub=None)))


def test_non_uuid_subject_is_rejected(rsa_key):
    with pytest.raises(TokenError):
        _verifier(rsa_key.public_key()).verify(_rs256(rsa_key, _claims(sub="not-a-uuid")))


def test_unknown_kid_is_rejected(rsa_key):
    with pytest.raises(TokenError):
        _verifier(rsa_key.public_key()).verify(_rs256(rsa_key, _claims(), kid="other-kid"))


def test_alg_none_is_rejected(rsa_key):
    token = jwt.encode(_claims(), key=None, algorithm="none")
    with pytest.raises(TokenError):
        _verifier(rsa_key.public_key()).verify(token)


def test_tampered_payload_is_rejected(rsa_key):
    header, _, signature = _rs256(rsa_key, _claims()).split(".")
    forged_payload = jwt.utils.base64url_encode(
        (
            '{"sub":"22222222-2222-4222-8222-222222222222","aud":"authenticated",'
            f'"iss":"{ISSUER}","iat":1,"exp":9999999999,"role":"authenticated"}}'
        ).encode()
    ).decode()
    with pytest.raises(TokenError):
        _verifier(rsa_key.public_key()).verify(f"{header}.{forged_payload}.{signature}")


def test_algorithm_confusion_hs256_with_public_key_is_rejected(rsa_key):
    """Classic attack: sign HS256 using the RSA public key bytes as the HMAC secret.

    PyJWT refuses to sign that way itself, so the forgery is built by hand with hmac.
    """
    import base64
    import hashlib
    import hmac
    import json

    public_pem = rsa_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    def b64(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    header = b64(json.dumps({"alg": "HS256", "typ": "JWT", "kid": "good-kid"}).encode())
    payload = b64(json.dumps(_claims()).encode())
    signature = b64(hmac.new(public_pem, f"{header}.{payload}".encode(), hashlib.sha256).digest())
    forged = f"{header}.{payload}.{signature}"

    # Verifier has the public key but no legacy secret, so HS256 must not be accepted at all.
    with pytest.raises(TokenError):
        _verifier(rsa_key.public_key()).verify(forged)


def test_hs256_rejected_when_no_legacy_secret_configured(rsa_key):
    forged = jwt.encode(_claims(), "some-secret-value-of-sufficient-length-1234", algorithm="HS256")
    with pytest.raises(TokenError):
        _verifier(rsa_key.public_key()).verify(forged)


def test_hs256_accepted_only_with_configured_legacy_secret(rsa_key):
    secret = "x" * 40
    token = jwt.encode(_claims(), secret, algorithm="HS256")
    assert _verifier(rsa_key.public_key(), legacy_secret=secret).verify(token).user_id == USER_ID
    wrong = jwt.encode(_claims(), "w" * 40, algorithm="HS256")
    with pytest.raises(TokenError):
        _verifier(rsa_key.public_key(), legacy_secret=secret).verify(wrong)


@pytest.mark.parametrize("garbage", ["", "abc", "a.b", "a.b.c", "eyJhbGciOiJSUzI1NiJ9.x.y"])
def test_malformed_tokens_are_rejected(rsa_key, garbage):
    with pytest.raises(TokenError):
        _verifier(rsa_key.public_key()).verify(garbage)
