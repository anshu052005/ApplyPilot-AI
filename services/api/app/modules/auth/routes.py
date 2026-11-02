from fastapi import APIRouter, Depends, HTTPException, Response, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.adapters.supabase.admin import SupabaseAdminClient
from app.adapters.supabase.factory import get_admin_client
from app.modules.auth import service
from app.modules.auth.dependencies import get_active_db, get_current_user, get_user_db
from app.shared.identity import CurrentUser

router = APIRouter(prefix="/auth", tags=["auth"])


class MeResponse(BaseModel):
    id: str
    email: str | None
    display_name: str | None


class DeletionPendingResponse(BaseModel):
    status: str
    detail: str


def _unauthenticated() -> HTTPException:
    return HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")


@router.get("/me", response_model=MeResponse, responses={423: {"description": "Account deletion in progress"}})
def read_me(user: CurrentUser = Depends(get_current_user), db: Session = Depends(get_active_db)) -> MeResponse:
    try:
        record = service.get_or_create_app_user(db, user)
    except service.AccountNoLongerExists:
        raise _unauthenticated() from None
    return MeResponse(id=str(record.id), email=record.email, display_name=record.display_name)


@router.delete(
    "/account",
    status_code=status.HTTP_204_NO_CONTENT,
    responses={
        202: {"model": DeletionPendingResponse, "description": "Deletion started but not complete. Retry."},
        204: {"description": "Deletion complete. Storage and Auth are both clean."},
    },
)
def delete_account(
    user: CurrentUser = Depends(get_current_user),
    db: Session = Depends(get_user_db),
    admin: SupabaseAdminClient = Depends(get_admin_client),
) -> Response:
    """Idempotent. Allowed while deletion is pending, so a failed run can be retried."""
    try:
        outcome = service.request_account_deletion(db, user, admin)
    except service.AccountNoLongerExists:
        raise _unauthenticated() from None

    if outcome is service.DeletionOutcome.COMPLETED:
        return Response(status_code=status.HTTP_204_NO_CONTENT)
    body = DeletionPendingResponse(
        status="pending",
        detail="Deletion has not finished. Your data stays locked until it completes. Retry this request.",
    )
    return JSONResponse(status_code=status.HTTP_202_ACCEPTED, content=body.model_dump())
