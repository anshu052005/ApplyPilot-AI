from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.adapters.supabase.admin import SupabaseAdminClient
from app.db.models.core import AppUser
from app.shared.identity import CurrentUser


class AccountNoLongerExists(Exception):
    """The token is still signed and unexpired, but the auth user was deleted. Maps to HTTP 401."""


def get_or_create_app_user(db: Session, user: CurrentUser) -> AppUser:
    """Returns the caller's app record, creating it on first use. RLS allows only the caller's own id."""
    record = db.get(AppUser, user.id)
    try:
        if record is None:
            record = AppUser(id=user.id, email=user.email)
            db.add(record)
            db.flush()
        elif user.email and record.email != user.email:
            record.email = user.email
            db.flush()
    except IntegrityError as exc:
        # The only foreign key on app_users is to auth.users, so this means the auth user is gone.
        raise AccountNoLongerExists() from exc
    return record


def delete_account(user: CurrentUser, admin: SupabaseAdminClient) -> None:
    """Deletes the Supabase auth user. The foreign key cascades to app_users and audit_logs.

    The auth delete runs first. If it fails, nothing has changed and the request can be retried.
    Storage object deletion is added in M3, when candidate files exist.
    """
    admin.delete_auth_user(user.id)
