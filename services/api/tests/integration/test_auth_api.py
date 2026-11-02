"""End-to-end auth through the API: real Supabase-issued tokens, real database, real RLS."""

import os
import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from app.main import create_app


@pytest.fixture
def client():
    with TestClient(create_app()) as test_client:
        yield test_client


def _auth(user) -> dict[str, str]:
    return {"Authorization": f"Bearer {user.access_token}"}


def test_health_is_public(client):
    assert client.get("/api/v1/health").json() == {"status": "ok"}


def test_me_requires_a_token(client):
    response = client.get("/api/v1/auth/me")
    assert response.status_code == 401
    assert response.json()["detail"] == "Not authenticated"


@pytest.mark.parametrize("header", ["Bearer not-a-jwt", "Bearer a.b.c", "Basic dXNlcjpwYXNz"])
def test_me_rejects_invalid_credentials(client, header):
    response = client.get("/api/v1/auth/me", headers={"Authorization": header})
    assert response.status_code == 401


def test_me_rejects_tampered_token(client, user_a):
    header, payload, signature = user_a.access_token.split(".")
    forged_payload = payload[:-2] + ("AA" if payload[-2:] != "AA" else "BB")
    response = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {header}.{forged_payload}.{signature}"})
    assert response.status_code == 401


def test_me_returns_the_callers_own_record(client, user_a, user_b):
    body_a = client.get("/api/v1/auth/me", headers=_auth(user_a)).json()
    body_b = client.get("/api/v1/auth/me", headers=_auth(user_b)).json()
    assert body_a["id"] == str(user_a.id)
    assert body_b["id"] == str(user_b.id)
    assert body_a["id"] != body_b["id"]


def test_me_is_idempotent(client, user_a):
    first = client.get("/api/v1/auth/me", headers=_auth(user_a)).json()
    second = client.get("/api/v1/auth/me", headers=_auth(user_a)).json()
    assert first == second


def test_account_deletion_requires_a_token(client):
    assert client.delete("/api/v1/auth/account").status_code == 401


def test_account_deletion_removes_only_the_callers_data(client, user_a, user_b, owner_sql):
    client.get("/api/v1/auth/me", headers=_auth(user_a))
    client.get("/api/v1/auth/me", headers=_auth(user_b))

    response = client.delete("/api/v1/auth/account", headers=_auth(user_a))
    assert response.status_code == 204

    assert owner_sql("SELECT count(*) FROM auth.users WHERE id = :id", {"id": user_a.id})[0][0] == 0
    assert owner_sql("SELECT count(*) FROM app_users WHERE id = :id", {"id": user_a.id})[0][0] == 0
    assert owner_sql("SELECT count(*) FROM app_users WHERE id = :id", {"id": user_b.id})[0][0] == 1
    assert client.get("/api/v1/auth/me", headers=_auth(user_b)).status_code == 200


def test_old_token_is_refused_after_account_deletion(client, user_a):
    """The JWT is still signed and unexpired, but the auth user is gone. The API must answer 401, not 500."""
    client.get("/api/v1/auth/me", headers=_auth(user_a))
    assert client.delete("/api/v1/auth/account", headers=_auth(user_a)).status_code == 204
    response = client.get("/api/v1/auth/me", headers=_auth(user_a))
    assert response.status_code == 401
    assert response.json()["detail"] == "Not authenticated"


# ---- asymmetric signing (JWKS) ----


def test_issued_tokens_are_asymmetric_and_accepted_through_jwks(client, user_a):
    import jwt as pyjwt

    header = pyjwt.get_unverified_header(user_a.access_token)
    assert header["alg"] == "ES256"
    assert header.get("kid"), "asymmetric tokens must carry a kid so the verifier can pick the public key"
    assert client.get("/api/v1/auth/me", headers=_auth(user_a)).status_code == 200


def test_jwks_endpoint_publishes_only_public_keys():
    import os

    import httpx

    base = os.environ["SUPABASE_URL"].rstrip("/")
    body = httpx.get(f"{base}/auth/v1/.well-known/jwks.json", timeout=10.0).json()
    assert body["keys"], "JWKS must publish at least one key"
    for key in body["keys"]:
        assert not ({"d", "p", "q", "dp", "dq", "qi", "k"} & key.keys()), "JWKS published private key material"


def test_hs256_token_signed_with_a_guessed_secret_is_refused(client, user_a):
    """Legacy HS256 is not configured for this API, so a token signed with any shared secret must be rejected."""
    import time

    import jwt as pyjwt

    now = int(time.time())
    forged = pyjwt.encode(
        {
            "sub": str(user_a.id),
            "aud": "authenticated",
            "iss": os.environ["SUPABASE_URL"].rstrip("/") + "/auth/v1",
            "iat": now,
            "exp": now + 600,
            "role": "authenticated",
        },
        "guessed-secret-value-of-sufficient-length-123456",
        algorithm="HS256",
    )
    response = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {forged}"})
    assert response.status_code == 401
