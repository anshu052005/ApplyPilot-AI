"""Helpers for JWKS tests: EC key generation, public JWK export, token signing, and a controllable clock.

Private keys stay in this test module. They are never part of any JWKS document the code under test sees.
"""

import json
import time
import uuid

import httpx
import jwt
from cryptography.hazmat.primitives.asymmetric import ec

ISSUER = "http://127.0.0.1:54321/auth/v1"
AUDIENCE = "authenticated"
USER_ID = "11111111-1111-4111-8111-111111111111"

_PRIVATE_KEYS: dict[str, ec.EllipticCurvePrivateKey] = {}


def ec_jwk(kid: str) -> dict:
    """Creates a P-256 key, remembers its private half for signing, and returns only the public JWK."""
    private = ec.generate_private_key(ec.SECP256R1())
    _PRIVATE_KEYS[kid] = private
    public = json.loads(jwt.algorithms.ECAlgorithm.to_jwk(private.public_key()))
    public.update({"kid": kid, "alg": "ES256", "use": "sig"})
    return public


def publish(keys: list[dict]) -> dict:
    return {"keys": list(keys)}


def sign_es256(kid: str, claims: dict | None = None, *, key: ec.EllipticCurvePrivateKey | None = None) -> str:
    private = key or _PRIVATE_KEYS[kid]
    now = int(time.time())
    body = {
        "sub": USER_ID,
        "aud": AUDIENCE,
        "iss": ISSUER,
        "iat": now,
        "exp": now + 600,
        "role": "authenticated",
        "email": "a@example.com",
    }
    if claims:
        body.update(claims)
    body = {k: v for k, v in body.items() if v is not None}
    return jwt.encode(body, private, algorithm="ES256", headers={"kid": kid})


class Publisher:
    """Stands in for the Supabase JWKS endpoint. Counts fetches. Can be made to fail."""

    def __init__(self, keys: list[dict]) -> None:
        self.keys = list(keys)
        self.fetches = 0
        self.fail = False

    def __call__(self) -> dict:
        self.fetches += 1
        if self.fail:
            raise httpx.ConnectError("jwks unreachable")
        return publish(self.keys)


def new_private_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


class FakeClock:
    def __init__(self) -> None:
        self.now = 1_000_000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def make_clock() -> FakeClock:
    return FakeClock()


def unique_kid() -> str:
    return f"kid-{uuid.uuid4().hex[:8]}"
