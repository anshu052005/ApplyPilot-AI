"""Proves at the database layer that one user cannot read, modify or delete another user's rows.

Every query here runs as `app_api` (the runtime role) through `open_user_session`, which sets the
identity exactly as the API does. Each check uses a fresh session, because a failed statement aborts its transaction.
"""

import uuid

import pytest
from sqlalchemy import func, select, text, update, delete
from sqlalchemy.exc import DBAPIError

from app.db.models.core import AppUser, AuditLog
from app.db.session import get_session_factory, open_user_session


def _session(user_id: uuid.UUID | None):
    return open_user_session(get_session_factory(), user_id)


@pytest.fixture
def seeded(user_a, user_b):
    """Creates one app_users row per user, each created inside that user's own identity."""
    for user in (user_a, user_b):
        with _session(user.id) as db:
            db.add(AppUser(id=user.id, email=user.email, display_name=f"name-{user.id}"))
            db.commit()
    return user_a, user_b


def test_user_sees_only_their_own_app_user_row(seeded):
    a, b = seeded
    with _session(a.id) as db:
        rows = db.scalars(select(AppUser)).all()
        assert [r.id for r in rows] == [a.id]
        assert db.get(AppUser, b.id) is None


def test_user_cannot_update_another_users_row(seeded):
    a, b = seeded
    with _session(b.id) as db:
        result = db.execute(update(AppUser).where(AppUser.id == a.id).values(display_name="pwned"))
        db.commit()
        assert result.rowcount == 0
    with _session(a.id) as db:
        assert db.get(AppUser, a.id).display_name == f"name-{a.id}"


def test_user_cannot_delete_another_users_row(seeded):
    a, b = seeded
    with _session(b.id) as db:
        result = db.execute(delete(AppUser).where(AppUser.id == a.id))
        db.commit()
        assert result.rowcount == 0
    with _session(a.id) as db:
        assert db.get(AppUser, a.id) is not None


def test_user_cannot_insert_a_row_owned_by_another_user(user_a, user_b):
    with _session(user_a.id) as db:
        db.add(AppUser(id=user_a.id, email=user_a.email))
        db.commit()
    with pytest.raises(DBAPIError, match="row-level security"):
        with _session(user_b.id) as db:
            db.add(AppUser(id=user_a.id, email="attacker@example.com"))
            db.commit()


def test_unauthenticated_session_sees_no_rows(seeded):
    with _session(None) as db:
        assert db.scalar(select(func.count()).select_from(AppUser)) == 0
        assert db.scalar(select(func.count()).select_from(AuditLog)) == 0


def test_audit_logs_are_scoped_to_their_owner(seeded):
    a, b = seeded
    with _session(a.id) as db:
        db.add(AuditLog(user_id=a.id, action="test.created", target="fixture"))
        db.commit()
    with _session(b.id) as db:
        assert db.scalar(select(func.count()).select_from(AuditLog)) == 0
    with pytest.raises(DBAPIError, match="row-level security"):
        with _session(b.id) as db:
            db.add(AuditLog(user_id=a.id, action="forged.entry"))
            db.commit()


def test_audit_logs_are_append_only_for_the_application(seeded):
    a, _ = seeded
    with _session(a.id) as db:
        db.add(AuditLog(user_id=a.id, action="test.immutable"))
        db.commit()
    with pytest.raises(DBAPIError, match="permission denied"):
        with _session(a.id) as db:
            db.execute(text("UPDATE audit_logs SET action = 'changed' WHERE user_id = :u"), {"u": a.id})
            db.commit()
    with pytest.raises(DBAPIError, match="permission denied"):
        with _session(a.id) as db:
            db.execute(text("DELETE FROM audit_logs WHERE user_id = :u"), {"u": a.id})
            db.commit()


@pytest.mark.parametrize("role", ["anon", "authenticated"])
def test_supabase_public_roles_cannot_read_app_tables(owner_engine, seeded, role):
    with owner_engine.connect() as conn:
        conn.execute(text(f"SET ROLE {role}"))
        with pytest.raises(DBAPIError, match="permission denied"):
            conn.execute(text("SELECT count(*) FROM app_users")).scalar()
        conn.rollback()
