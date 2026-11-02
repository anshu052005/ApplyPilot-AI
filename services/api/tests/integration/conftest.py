"""Integration fixtures. These need the local Supabase stack running (`npm run db:start`).

Required environment (see .env.example and README). The tests fail loudly when the stack is absent
instead of passing silently:
  SUPABASE_URL, SUPABASE_ANON_KEY, SUPABASE_SERVICE_ROLE_KEY, SUPABASE_JWT_SECRET (optional, legacy HS256)
  DATABASE_URL            runtime role app_api
  MIGRATION_DATABASE_URL  owner role, used only for migrations and catalog checks
  APP_API_DB_PASSWORD     password for app_api, embedded by the baseline migration
"""

import os
import subprocess
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
    "SUPABASE_SERVICE_ROLE_KEY",
    "SUPABASE_ADMIN_JWT",
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
    ids: list[uuid.UUID] = []
    yield ids
    base = os.environ["SUPABASE_URL"].rstrip("/")
    key = os.environ["SUPABASE_SERVICE_ROLE_KEY"]
    headers = {"apikey": key, "Authorization": f"Bearer {key}", "Content-Type": "application/json"}
    with httpx.Client(timeout=15.0) as client:
        for user_id in ids:
            # Remove the user's stored objects first. Their metadata rows cascade with the user.
            listed = client.post(
                f"{base}/storage/v1/object/list/candidate-files",
                headers=headers,
                json={"prefix": f"{user_id}/", "limit": 1000, "offset": 0},
            )
            if listed.status_code == 200 and listed.json():
                keys = [
                    item["name"] if str(item["name"]).startswith(f"{user_id}/") else f"{user_id}/{item['name']}"
                    for item in listed.json() if item.get("name")
                ]
                if keys:
                    client.request(
                        "DELETE",
                        f"{base}/storage/v1/object/candidate-files",
                        headers=headers,
                        json={"prefixes": keys},
                    )
            client.delete(
                f"{base}/auth/v1/admin/users/{user_id}",
                headers={"apikey": key, "Authorization": f"Bearer {os.environ['SUPABASE_ADMIN_JWT']}"},
            )


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
