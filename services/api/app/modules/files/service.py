"""Candidate file operations. Every function takes the verified user and checks ownership before acting.

Ownership is enforced twice: explicit `user_id` filters here, and RLS in the database. A file that belongs to
someone else is reported as not found (404), so file IDs cannot be probed.
"""

import hashlib
import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.adapters.supabase.admin import StorageError, SupabaseAdminClient
from app.db.models.core import CandidateFile
from app.modules.auth.service import get_or_create_app_user
from app.modules.files.validation import EXTENSION_BY_KIND, MIME_BY_KIND, safe_display_name, sniff_document_kind
from app.shared.identity import CurrentUser

BUCKET = "candidate-files"
DOWNLOAD_URL_TTL_SECONDS = 120


class FileNotFound(Exception):
    pass


class UnsupportedFile(Exception):
    """Wrong type, size, or content. `status_code` is set for the HTTP layer."""

    def __init__(self, status_code: int, message: str) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.message = message


class StorageUnavailable(Exception):
    pass


def upload_candidate_file(
    db: Session,
    user: CurrentUser,
    *,
    data: bytes,
    declared_mime: str | None,
    filename: str | None,
    admin: SupabaseAdminClient,
) -> CandidateFile:
    if not data:
        raise UnsupportedFile(422, "The file is empty.")

    # candidate_files references app_users. The row is created on first use, the same way /auth/me does it.
    get_or_create_app_user(db, user)

    kind = sniff_document_kind(data)
    if kind is None:
        raise UnsupportedFile(415, "Only PDF and DOCX files are accepted.")
    if declared_mime != MIME_BY_KIND[kind]:
        raise UnsupportedFile(415, "The file type does not match its content.")

    file_id = uuid.uuid4()
    # Server-built key. The client's filename never reaches the storage path.
    object_key = f"{user.id}/{file_id}.{EXTENSION_BY_KIND[kind]}"
    mime = MIME_BY_KIND[kind]

    try:
        admin.upload_object(BUCKET, object_key, data, mime)
    except StorageError as exc:
        raise StorageUnavailable("Could not store the file.") from exc

    record = CandidateFile(
        id=file_id,
        user_id=user.id,
        bucket=BUCKET,
        object_key=object_key,
        original_filename=safe_display_name(filename),
        mime_type=mime,
        size_bytes=len(data),
        sha256=hashlib.sha256(data).hexdigest(),
    )
    try:
        db.add(record)
        db.flush()
    except Exception:
        # The metadata insert failed, so remove the object we just wrote. Best effort: a leftover object is
        # harmless because it is unreferenced and under the user's prefix.
        try:
            admin.delete_object(BUCKET, object_key)
        except StorageError:
            pass
        raise
    return record


def get_owned_file(db: Session, user: CurrentUser, file_id: uuid.UUID) -> CandidateFile:
    record = db.scalar(
        select(CandidateFile).where(CandidateFile.id == file_id, CandidateFile.user_id == user.id)
    )
    if record is None:
        raise FileNotFound()
    return record


def create_download_url(db: Session, user: CurrentUser, file_id: uuid.UUID, admin: SupabaseAdminClient) -> str:
    record = get_owned_file(db, user, file_id)
    try:
        return admin.create_signed_download_url(record.bucket, record.object_key, DOWNLOAD_URL_TTL_SECONDS)
    except StorageError as exc:
        raise StorageUnavailable("Could not create a download link.") from exc


def delete_candidate_file(db: Session, user: CurrentUser, file_id: uuid.UUID, admin: SupabaseAdminClient) -> None:
    record = get_owned_file(db, user, file_id)
    try:
        admin.delete_object(record.bucket, record.object_key)
    except StorageError as exc:
        # The row stays, so the operation can be retried.
        raise StorageUnavailable("Could not delete the file. Try again.") from exc
    db.delete(record)
    db.flush()
