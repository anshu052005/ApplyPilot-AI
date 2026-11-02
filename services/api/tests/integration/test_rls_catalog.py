"""Catalog-level guarantees: every user-owned table is protected, and runtime roles cannot bypass RLS."""

import pytest
from sqlalchemy import text

from app.db.base import USER_OWNED_TABLES


@pytest.mark.parametrize("table", USER_OWNED_TABLES)
def test_user_owned_table_has_rls_enabled_and_forced(owner_engine, table):
    with owner_engine.connect() as conn:
        row = conn.execute(
            text("SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE oid = to_regclass(:name)"),
            {"name": f"public.{table}"},
        ).one_or_none()
    assert row is not None, f"table {table} does not exist"
    assert row.relrowsecurity is True, f"RLS not enabled on {table}"
    assert row.relforcerowsecurity is True, f"RLS not forced on {table} (owner would bypass policies)"


def test_app_api_role_cannot_bypass_rls(owner_sql):
    rows = owner_sql("SELECT rolsuper, rolbypassrls, rolinherit FROM pg_roles WHERE rolname = 'app_api'")
    assert len(rows) == 1
    rolsuper, rolbypassrls, rolinherit = rows[0]
    assert rolsuper is False
    assert rolbypassrls is False
    assert rolinherit is False


@pytest.mark.parametrize("role", ["anon", "authenticated"])
def test_supabase_public_roles_have_no_privileges_on_app_tables(owner_sql, role):
    rows = owner_sql(
        """
        SELECT table_name, privilege_type
        FROM information_schema.role_table_grants
        WHERE grantee = :role AND table_schema = 'public'
        """,
        {"role": role},
    )
    assert rows == [], f"{role} has privileges on application tables: {rows}"


def test_identity_function_fails_closed_without_claims(owner_sql):
    """With no claim set, the identity function returns NULL, which matches no row."""
    rows = owner_sql(
        """
        SELECT public.app_current_user_id() IS NULL
        """
    )
    assert rows[0][0] is True
