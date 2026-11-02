"""Database sessions.

Every application query runs through `open_user_session(...)`. It sets `request.jwt.claims` for the
current transaction, so the RLS policies (`app_current_user_id()`) see the verified user. Without a
verified user the claim is empty and policies return no rows (fail closed).

The session never uses a service-role key or a superuser connection.
"""

import json
import uuid
from collections.abc import Iterator
from functools import lru_cache

from sqlalchemy import Connection, create_engine, event, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import get_settings


def make_engine(url: str) -> Engine:
    return create_engine(url, pool_pre_ping=True, future=True)


@lru_cache
def get_engine() -> Engine:
    return make_engine(get_settings().database_url.get_secret_value())


@lru_cache
def get_session_factory() -> sessionmaker[Session]:
    return sessionmaker(bind=get_engine(), expire_on_commit=False, autoflush=True)


def _apply_rls_claims(session: Session, transaction, connection: Connection) -> None:
    """Runs at the start of every transaction, so the identity survives commits within the session."""
    user_id: uuid.UUID | None = session.info.get("rls_user_id")
    claims = {"sub": str(user_id), "role": "authenticated"} if user_id else {}
    connection.execute(
        text("select set_config('request.jwt.claims', :claims, true)"),
        {"claims": json.dumps(claims)},
    )


def open_user_session(factory: sessionmaker[Session], user_id: uuid.UUID | None) -> Session:
    session = factory()
    session.info["rls_user_id"] = user_id
    event.listen(session, "after_begin", _apply_rls_claims)
    return session


def get_db_for_user(user_id: uuid.UUID | None) -> Iterator[Session]:
    """Yields a session bound to `user_id`. Commits on success, rolls back on error."""
    session = open_user_session(get_session_factory(), user_id)
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
