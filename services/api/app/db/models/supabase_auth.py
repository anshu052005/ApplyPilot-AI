"""Read-only description of the Supabase-managed `auth.users` table.

Supabase owns the `auth` schema. Application migrations reference it with a foreign key but never
create, alter or drop it. This placeholder exists only so SQLAlchemy can resolve the foreign key.
It is not part of any migration.
"""

from sqlalchemy import Column, Table, Uuid

from app.db.base import Base

auth_users = Table(
    "users",
    Base.metadata,
    Column("id", Uuid(as_uuid=True), primary_key=True),
    schema="auth",
    extend_existing=True,
)
