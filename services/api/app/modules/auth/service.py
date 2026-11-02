"""Account service: app record creation and the account deletion workflow.

Deletion workflow (idempotent, resumable):
1. Mark the account as deletion-requested. From now on data endpoints return 423.
2. Storage: list every object under the user's prefix, union with the metadata rows, delete each object, then
   delete its metadata row. A missing object counts as deleted.
3. Verify Storage is empty for the user's prefix. Only then continue.
4. Delete the Auth user. The foreign keys cascade to app_users, candidate_files and audit_logs.

If any step fails, the request stops, the failure is recorded as a machine code, and the account stays in the
deletion-pending state. A retry repeats the same steps. Nothing is reported as completed while personal files
remain in Storage.
"""

from datetime import UTC, datetime
from enum import Enum

import httpx
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.adapters.supabase.admin import AdminNotConfigured, AuthAdminError, StorageError, SupabaseAdminClient
from app.db.models.core import AppUser, CandidateFile
from app.shared.identity import CurrentUser

CANDIDATE_BUCKET = "candidate-files"


class AccountNoLongerExists(Exception):
    """The token is still signed and unexpired, but the auth user was deleted. Maps to HTTP 401."""


class AccountDeletionPending(Exception):
    """A data endpoint was called while deletion is pending. Maps to HTTP 423."""


class DeletionOutcome(str, Enum):
    COMPLETED = "completed"
    PENDING = "pending"


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


def require_account_not_pending(db: Session, user: CurrentUser) -> None:
    record = db.get(AppUser, user.id)
    if record is not None and record.deletion_requested_at is not None:
        raise AccountDeletionPending()


def _purge_candidate_files(db: Session, user: CurrentUser, admin: SupabaseAdminClient) -> None:
    prefix = f"{user.id}/"
    rows = {row.object_key: row for row in db.scalars(select(CandidateFile).where(CandidateFile.user_id == user.id))}
    stored = set(admin.list_object_keys(CANDIDATE_BUCKET, prefix))

    for key in sorted(set(rows) | stored):
        admin.delete_object(CANDIDATE_BUCKET, key)
        row = rows.get(key)
        if row is not None:
            db.delete(row)
            db.flush()

    # Verify before anything irreversible happens. Storage must be empty for this user.
    if admin.list_object_keys(CANDIDATE_BUCKET, prefix):
        raise StorageError("objects remain after cleanup")


def _record_failure(db: Session, record: AppUser, code: str) -> DeletionOutcome:
    record.deletion_last_error = code
    db.flush()
    return DeletionOutcome.PENDING


def request_account_deletion(db: Session, user: CurrentUser, admin: SupabaseAdminClient) -> DeletionOutcome:
    record = get_or_create_app_user(db, user)
    if record.deletion_requested_at is None:
        record.deletion_requested_at = datetime.now(UTC)
    # Commit the pending state before any destructive step. Other requests now see the lock, and a crash
    # leaves the account locked rather than half-deleted.
    db.commit()

    try:
        _purge_candidate_files(db, user, admin)
    except (StorageError, httpx.HTTPError):
        return _record_failure(db, record, "storage_cleanup_failed")
    except AdminNotConfigured:
        return _record_failure(db, record, "admin_not_configured")

    # Commit the cleanup before the Auth delete. Otherwise the cascade from auth.users waits on row locks held
    # by this transaction, which deadlocks until the gateway times out (observed as HTTP 504).
    db.commit()

    try:
        admin.delete_auth_user(user.id)
    except (AuthAdminError, httpx.HTTPError):
        return _record_failure(db, record, "auth_delete_failed")
    except AdminNotConfigured:
        return _record_failure(db, record, "admin_not_configured")

    return DeletionOutcome.COMPLETED
