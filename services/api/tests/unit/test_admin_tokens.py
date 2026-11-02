"""Short-lived admin tokens: lifetime, renewal, missing credentials, and nothing persisted to disk."""

import json
from pathlib import Path

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from jwt.algorithms import ECAlgorithm

from app.adapters.supabase.admin_tokens import (
    ADMIN_TOKEN_LIFETIME_SECONDS,
    RENEW_BEFORE_EXPIRY_SECONDS,
    STORAGE_TOKEN_ISSUER,
    AdminCredentialError,
    AdminTokenIssuer,
)

ISSUER = "http://127.0.0.1:54321/auth/v1"
STORAGE_SECRET = "s" * 48


class Clock:
    def __init__(self, start: float = 1_700_000_000.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@pytest.fixture
def key_file(tmp_path: Path) -> Path:
    private = ec.generate_private_key(ec.SECP256R1())
    jwk = json.loads(ECAlgorithm.to_jwk(private))
    jwk.update({"kid": "kid-test-1", "alg": "ES256", "use": "sig", "key_ops": ["sign", "verify"]})
    path = tmp_path / "signing_keys.json"
    path.write_text(json.dumps([jwk]), encoding="utf-8")
    return path


@pytest.fixture
def issuer(key_file):
    clock = Clock()
    return AdminTokenIssuer(
        auth_issuer=ISSUER,
        signing_key_path=key_file,
        storage_signing_secret=STORAGE_SECRET,
        clock=clock,
    ), clock


def _public_key(key_file: Path):
    jwk = json.loads(key_file.read_text(encoding="utf-8"))[0]
    return ECAlgorithm.from_jwk(json.dumps({k: v for k, v in jwk.items() if k != "d"}))


def test_auth_token_is_es256_service_role_with_kid_and_at_most_15_minutes(issuer, key_file):
    admin, clock = issuer
    token = admin.auth_admin_token()
    header = jwt.get_unverified_header(token)
    claims = jwt.decode(token, _public_key(key_file), algorithms=["ES256"], options={"verify_aud": False, "verify_exp": False})

    assert header["alg"] == "ES256"
    assert header["kid"] == "kid-test-1"
    assert claims["role"] == "service_role"
    assert claims["iss"] == ISSUER
    assert claims["exp"] - claims["iat"] == ADMIN_TOKEN_LIFETIME_SECONDS
    assert ADMIN_TOKEN_LIFETIME_SECONDS <= 15 * 60


def test_storage_token_is_hs256_service_role_with_the_same_lifetime(issuer):
    admin, _ = issuer
    token = admin.storage_admin_token()
    claims = jwt.decode(token, STORAGE_SECRET, algorithms=["HS256"], options={"verify_exp": False})

    assert claims["role"] == "service_role"
    assert claims["iss"] == STORAGE_TOKEN_ISSUER
    assert claims["exp"] - claims["iat"] == ADMIN_TOKEN_LIFETIME_SECONDS


def test_token_is_reused_while_fresh(issuer):
    admin, clock = issuer
    first = admin.auth_admin_token()
    clock.advance(60)
    assert admin.auth_admin_token() == first


def test_token_is_renewed_before_it_expires(issuer):
    admin, clock = issuer
    first = admin.auth_admin_token()
    clock.advance(ADMIN_TOKEN_LIFETIME_SECONDS - RENEW_BEFORE_EXPIRY_SECONDS + 1)
    renewed = admin.auth_admin_token()
    assert renewed != first


def test_renewed_token_has_a_fresh_expiry(issuer, key_file):
    admin, clock = issuer
    admin.auth_admin_token()
    clock.advance(ADMIN_TOKEN_LIFETIME_SECONDS)
    renewed = admin.auth_admin_token()
    claims = jwt.decode(renewed, _public_key(key_file), algorithms=["ES256"], options={"verify_aud": False, "verify_exp": False})
    assert claims["exp"] > clock.now


def test_storage_token_is_renewed_on_the_same_rule(issuer):
    admin, clock = issuer
    first = admin.storage_admin_token()
    clock.advance(60)
    assert admin.storage_admin_token() == first
    clock.advance(ADMIN_TOKEN_LIFETIME_SECONDS)
    assert admin.storage_admin_token() != first


def test_missing_signing_key_path_is_a_clear_error():
    issuer = AdminTokenIssuer(auth_issuer=ISSUER, signing_key_path=None, storage_signing_secret=STORAGE_SECRET)
    with pytest.raises(AdminCredentialError, match="SUPABASE_SIGNING_KEYS_PATH"):
        issuer.auth_admin_token()


def test_missing_storage_secret_is_a_clear_error(key_file):
    issuer = AdminTokenIssuer(auth_issuer=ISSUER, signing_key_path=key_file, storage_signing_secret=None)
    with pytest.raises(AdminCredentialError, match="SUPABASE_STORAGE_SIGNING_SECRET"):
        issuer.storage_admin_token()


def test_public_only_key_file_cannot_mint_tokens(tmp_path):
    private = ec.generate_private_key(ec.SECP256R1())
    jwk = json.loads(ECAlgorithm.to_jwk(private.public_key()))
    jwk.update({"kid": "pub", "alg": "ES256", "use": "sig"})
    path = tmp_path / "public_only.json"
    path.write_text(json.dumps([jwk]), encoding="utf-8")
    issuer = AdminTokenIssuer(auth_issuer=ISSUER, signing_key_path=path, storage_signing_secret=None)
    with pytest.raises(AdminCredentialError, match="private"):
        issuer.auth_admin_token()


def test_unreadable_key_file_is_a_clear_error(tmp_path):
    issuer = AdminTokenIssuer(auth_issuer=ISSUER, signing_key_path=tmp_path / "missing.json", storage_signing_secret=None)
    with pytest.raises(AdminCredentialError):
        issuer.auth_admin_token()


def test_tokens_are_never_written_to_disk(issuer, tmp_path, monkeypatch):
    """Minting must not touch the filesystem. The only file read is the key file, which is never written."""
    admin, _ = issuer
    writes = []
    real_open = Path.open

    def spy_open(self, mode="r", *args, **kwargs):
        if any(flag in mode for flag in ("w", "a", "x", "+")):
            writes.append(str(self))
        return real_open(self, mode, *args, **kwargs)

    monkeypatch.setattr(Path, "open", spy_open)
    admin.auth_admin_token()
    admin.storage_admin_token()
    assert writes == []
