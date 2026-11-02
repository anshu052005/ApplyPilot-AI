"""Integration fixtures. These need the local Supabase stack running (`npm run db:start`).

Required environment (see .env.example and README). The tests fail loudly when the stack is absent
instead of passing silently:
  SUPABASE_URL, SUPABASE_ANON_KEY
  SUPABASE_SIGNING_KEYS_PATH       private signing key file (admin tokens are minted from it)
  SUPABASE_STORAGE_SIGNING_SECRET  mints short-lived Storage service tokens
  DATABASE_URL                     runtime role app_api
  MIGRATION_DATABASE_URL           owner role, used only for migrations and catalog checks
  APP_API_DB_PASSWORD              password for app_api, embedded by the baseline migration
"""

import os
import subprocess
import warnings
import sys
import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import httpx
import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine

API_ROOT = Path(__file__).resolve().parents[2]
REQUIRED_ENV = (
    "SUPABASE_URL",
    "SUPABASE_ANON_KEY",
    "SUPABASE_SIGNING_KEYS_PATH",
    "SUPABASE_STORAGE_SIGNING_SECRET",
    "DATABASE_URL",
    "MIGRATION_DATABASE_URL",
    "APP_API_DB_PASSWORD",
)


@pytest.fixture(scope="session", autouse=True)
def require_local_stack() -> None:
    missing = [name for name in REQUIRED_ENV if not os.environ.get(name)]
    if missing:
        pytest.fail(
            "Integration tests need the local Supabase stack. Missing env vars: "
            + ", ".join(missing)
            + ". Start Docker Desktop, run `npm run db:start`, then export the values from `npx supabase status -o env`."
        )


@pytest.fixture(scope="session")
def owner_engine(require_local_stack) -> Engine:
    engine = create_engine(os.environ["MIGRATION_DATABASE_URL"], future=True)
    yield engine
    engine.dispose()


@pytest.fixture(scope="session", autouse=True)
def migrated(require_local_stack) -> None:
    """Applies the Alembic migrations to the local database once per test session."""
    result = subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head"],
        cwd=API_ROOT,
        env=os.environ.copy(),
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        pytest.fail(f"alembic upgrade head failed:\n{result.stdout}\n{result.stderr}")


@dataclass(frozen=True)
class TestUser:
    id: uuid.UUID
    email: str
    password: str
    access_token: str


def _signup(email: str, password: str) -> TestUser:
    base = os.environ["SUPABASE_URL"].rstrip("/")
    response = httpx.post(
        f"{base}/auth/v1/signup",
        headers={"apikey": os.environ["SUPABASE_ANON_KEY"], "Content-Type": "application/json"},
        json={"email": email, "password": password},
        timeout=15.0,
    )
    response.raise_for_status()
    body = response.json()
    if "access_token" not in body:
        pytest.fail(
            "Sign-up did not return a session. Check that email confirmation is disabled in supabase/config.toml."
        )
    return TestUser(
        id=uuid.UUID(body["user"]["id"]),
        email=email,
        password=password,
        access_token=body["access_token"],
    )


@pytest.fixture(scope="session")
def _created_user_ids() -> Iterator[list[uuid.UUID]]:
    """Tracks users created by the tests and removes them afterwards, with their stored objects."""
    from app.adapters.supabase.factory import get_admin_client
    from app.db.models.core import AppUser  # noqa: F401  (ensures mappers are configured)

    ids: list[uuid.UUID] = []
    yield ids
    admin = get_admin_client()
    for user_id in ids:
        try:
            for key in admin.list_object_keys("candidate-files", f"{user_id}/"):
                admin.delete_object("candidate-files", key)
            admin.delete_auth_user(user_id)
        except Exception as exc:  # noqa: BLE001  (teardown must not hide the real test result)
            warnings.warn(f"cleanup failed for a test user: {type(exc).__name__}", stacklevel=1)


@pytest.fixture
def make_user(_created_user_ids):
    def factory() -> TestUser:
        suffix = uuid.uuid4().hex[:12]
        user = _signup(f"test-{suffix}@applypilot.test", f"Passw0rd-{suffix}")
        _created_user_ids.append(user.id)
        return user

    return factory


@pytest.fixture
def user_a(make_user) -> TestUser:
    return make_user()


@pytest.fixture
def user_b(make_user) -> TestUser:
    return make_user()


@pytest.fixture
def owner_sql(owner_engine):
    """Runs SQL as the owner role. Used for catalog checks and for verifying data outside RLS."""

    def run(statement: str, params: dict | None = None):
        with owner_engine.begin() as conn:
            return conn.execute(text(statement), params or {}).fetchall()

    return run
