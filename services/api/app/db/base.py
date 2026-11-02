from sqlalchemy import MetaData
from sqlalchemy.orm import DeclarativeBase

# Explicit naming convention keeps constraint names stable across migrations.
NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING_CONVENTION)


# Tables whose rows belong to a single user. Every one of them must have RLS enabled and forced.
# tests/integration/test_rls_catalog.py checks this list against the live database catalog.
USER_OWNED_TABLES: tuple[str, ...] = ("app_users", "audit_logs", "candidate_files")
