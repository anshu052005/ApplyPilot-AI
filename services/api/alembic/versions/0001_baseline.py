"""Baseline: app roles, user-owned tables, RLS identity function and policies.

Security model (see plan §15):
- `app_api` is the runtime role. It is NOT a superuser, has NO BYPASSRLS, and does not own the tables.
  Every user-owned table has FORCE ROW LEVEL SECURITY, so the owner is subject to policies too.
- Policies compare `user_id` with `public.app_current_user_id()`, which reads the verified `sub` from
  `request.jwt.claims`. Without a verified identity the function returns NULL and policies match nothing.
- `anon` and `authenticated` (Supabase PostgREST roles) get no privileges on application tables.
- `app_jobs` (background jobs) is created as NOLOGIN. It is enabled in M5 with narrow functions only.

Revision ID: 0001_baseline
Revises:
Create Date: 2026-11-02
"""

import os
import re
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0001_baseline"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_PASSWORD_PATTERN = re.compile(r"^[A-Za-z0-9_\-]{24,}$")
USER_OWNED_TABLES = ("app_users", "audit_logs")


def _app_api_password() -> str:
    password = os.environ.get("APP_API_DB_PASSWORD", "")
    if not _PASSWORD_PATTERN.fullmatch(password):
        raise RuntimeError(
            "APP_API_DB_PASSWORD must be at least 24 characters of letters, digits, '_' or '-'. "
            "It is embedded in a DDL statement, so other characters are rejected."
        )
    return password


def upgrade() -> None:
    password = _app_api_password()

    # Roles. Created once, then (re)configured on every run. Passwords are never stored in the migration.
    op.execute(
        """
        DO $$
        BEGIN
          IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app_api') THEN
            CREATE ROLE app_api NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION;
          END IF;
          IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app_jobs') THEN
            CREATE ROLE app_jobs NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION;
          END IF;
        END
        $$;
        """
    )
    op.execute(f"ALTER ROLE app_api WITH LOGIN NOSUPERUSER NOBYPASSRLS PASSWORD '{password}';")

    # Identity function used by every policy. Fails closed: no claim means NULL, which matches no row.
    op.execute(
        """
        CREATE OR REPLACE FUNCTION public.app_current_user_id() RETURNS uuid
        LANGUAGE sql STABLE
        SET search_path = pg_catalog
        AS $$
          SELECT (NULLIF(current_setting('request.jwt.claims', true), '')::jsonb ->> 'sub')::uuid
        $$;
        """
    )

    op.create_table(
        "app_users",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("email", sa.String(length=320), nullable=True),
        sa.Column("display_name", sa.String(length=200), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["id"], ["auth.users.id"], name="fk_app_users_id_auth_users", ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id", name="pk_app_users"),
    )

    op.create_table(
        "audit_logs",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("action", sa.String(length=100), nullable=False),
        sa.Column("target", sa.String(length=200), nullable=True),
        sa.Column("details", postgresql.JSONB(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["app_users.id"], name="fk_audit_logs_user_id_app_users", ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id", name="pk_audit_logs"),
    )
    op.create_index("ix_audit_logs_user_id", "audit_logs", ["user_id"])

    # Row Level Security: enabled and forced on every user-owned table.
    for table in USER_OWNED_TABLES:
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY;")

    # app_users: a user can see, create, change and delete only their own record.
    op.execute(
        """
        CREATE POLICY app_users_select ON app_users FOR SELECT TO app_api
          USING (id = public.app_current_user_id());
        CREATE POLICY app_users_insert ON app_users FOR INSERT TO app_api
          WITH CHECK (id = public.app_current_user_id());
        CREATE POLICY app_users_update ON app_users FOR UPDATE TO app_api
          USING (id = public.app_current_user_id()) WITH CHECK (id = public.app_current_user_id());
        CREATE POLICY app_users_delete ON app_users FOR DELETE TO app_api
          USING (id = public.app_current_user_id());
        """
    )

    # audit_logs: append-only from the application. No UPDATE or DELETE policy or grant exists.
    op.execute(
        """
        CREATE POLICY audit_logs_select ON audit_logs FOR SELECT TO app_api
          USING (user_id = public.app_current_user_id());
        CREATE POLICY audit_logs_insert ON audit_logs FOR INSERT TO app_api
          WITH CHECK (user_id = public.app_current_user_id());
        """
    )

    # Grants. The runtime role gets only what the policies allow. Supabase's default privileges are revoked.
    op.execute(
        """
        GRANT USAGE ON SCHEMA public TO app_api;
        GRANT SELECT, INSERT, UPDATE, DELETE ON app_users TO app_api;
        GRANT SELECT, INSERT ON audit_logs TO app_api;
        GRANT USAGE, SELECT ON SEQUENCE audit_logs_id_seq TO app_api;
        REVOKE ALL ON app_users, audit_logs FROM PUBLIC, anon, authenticated;
        """
    )


def downgrade() -> None:
    # Roles are left in place: they may own grants in other databases. Only application objects are removed.
    op.execute("DROP POLICY IF EXISTS audit_logs_insert ON audit_logs;")
    op.execute("DROP POLICY IF EXISTS audit_logs_select ON audit_logs;")
    op.execute("DROP POLICY IF EXISTS app_users_delete ON app_users;")
    op.execute("DROP POLICY IF EXISTS app_users_update ON app_users;")
    op.execute("DROP POLICY IF EXISTS app_users_insert ON app_users;")
    op.execute("DROP POLICY IF EXISTS app_users_select ON app_users;")
    op.drop_index("ix_audit_logs_user_id", table_name="audit_logs")
    op.drop_table("audit_logs")
    op.drop_table("app_users")
    op.execute("DROP FUNCTION IF EXISTS public.app_current_user_id();")
