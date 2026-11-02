"""Remove Supabase default grants from public tables.

Supabase grants anon and authenticated full privileges on every new table in `public`
(ALTER DEFAULT PRIVILEGES). That exposes Alembic's own `alembic_version` table through PostgREST, and
would expose every future table by default. This migration:
- revokes all privileges on `alembic_version` from PUBLIC, anon and authenticated;
- removes the default privileges for anon and authenticated on new tables and sequences in `public`.

Later migrations must still grant the app_api role explicitly (see the 0001 baseline).

Revision ID: 0002_harden_public_grants
Revises: 0001_baseline
Create Date: 2026-11-02
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0002_harden_public_grants"
down_revision: str | None = "0001_baseline"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute("REVOKE ALL ON alembic_version FROM PUBLIC, anon, authenticated;")
    op.execute("ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON TABLES FROM anon, authenticated;")
    op.execute("ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON SEQUENCES FROM anon, authenticated;")


def downgrade() -> None:
    # Restoring Supabase's permissive defaults would re-expose data. Intentionally a no-op.
    pass
