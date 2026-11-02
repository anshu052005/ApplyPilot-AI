import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, File, HTTPException, Response, UploadFile, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.adapters.supabase.admin import SupabaseAdminClient
from app.core.config import get_settings
from app.db.models.core import CandidateFile
from app.modules.auth.dependencies import get_current_user, get_user_db
from app.modules.files import service
from app.modules.files.validation import MAX_FILE_BYTES
from app.shared.identity import CurrentUser

router = APIRouter(prefix="/files", tags=["files"])


class FileOut(BaseModel):
    id: uuid.UUID
    original_filename: str
    mime_type: str
    size_bytes: int
    sha256: str
    created_at: datetime


class DownloadUrlOut(BaseModel):
    url: str
    expires_in_seconds: int


def get_admin_client() -> SupabaseAdminClient:
    return SupabaseAdminClient(get_settings())


def _to_out(record: CandidateFile) -> FileOut:
    return FileOut(
        id=record.id,
        original_filename=record.original_filename,
        mime_type=record.mime_type,
        size_bytes=record.size_bytes,
        sha256=record.sha256,
        created_at=record.created_at,
    )


def _http_error(exc: service.UnsupportedFile) -> HTTPException:
    return HTTPException(status_code=exc.status_code, detail=exc.message)


@router.post("", response_model=FileOut, status_code=status.HTTP_201_CREATED)
def upload_file(
    file: UploadFile = File(...),
    user: CurrentUser = Depends(get_current_user),
    db: Session = Depends(get_user_db),
    admin: SupabaseAdminClient = Depends(get_admin_client),
) -> FileOut:
    # Read one byte past the limit, so an oversize upload is detected without loading it all.
    data = file.file.read(MAX_FILE_BYTES + 1)
    if len(data) > MAX_FILE_BYTES:
        raise HTTPException(status_code=status.HTTP_413_CONTENT_TOO_LARGE, detail="The file is larger than 10 MB.")
    try:
        record = service.upload_candidate_file(
            db,
            user,
            data=data,
            declared_mime=file.content_type,
            filename=file.filename,
            admin=admin,
        )
    except service.UnsupportedFile as exc:
        raise _http_error(exc) from None
    except service.StorageUnavailable as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc)) from None
    return _to_out(record)


@router.get("/{file_id}", response_model=FileOut)
def get_file(
    file_id: uuid.UUID,
    user: CurrentUser = Depends(get_current_user),
    db: Session = Depends(get_user_db),
) -> FileOut:
    try:
        return _to_out(service.get_owned_file(db, user, file_id))
    except service.FileNotFound:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="File not found") from None


@router.post("/{file_id}/download-url", response_model=DownloadUrlOut)
def create_download_url(
    file_id: uuid.UUID,
    user: CurrentUser = Depends(get_current_user),
    db: Session = Depends(get_user_db),
    admin: SupabaseAdminClient = Depends(get_admin_client),
) -> DownloadUrlOut:
    try:
        url = service.create_download_url(db, user, file_id, admin)
    except service.FileNotFound:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="File not found") from None
    except service.StorageUnavailable as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc)) from None
    return DownloadUrlOut(url=url, expires_in_seconds=service.DOWNLOAD_URL_TTL_SECONDS)


@router.delete("/{file_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_file(
    file_id: uuid.UUID,
    user: CurrentUser = Depends(get_current_user),
    db: Session = Depends(get_user_db),
    admin: SupabaseAdminClient = Depends(get_admin_client),
) -> Response:
    try:
        service.delete_candidate_file(db, user, file_id, admin)
    except service.FileNotFound:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="File not found") from None
    except service.StorageUnavailable as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc)) from None
    return Response(status_code=status.HTTP_204_NO_CONTENT)
