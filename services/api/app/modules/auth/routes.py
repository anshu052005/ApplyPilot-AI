from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.adapters.supabase.admin import SupabaseAdminClient
from app.core.config import get_settings
from app.modules.auth import service
from app.modules.auth.dependencies import get_current_user, get_user_db
from app.shared.identity import CurrentUser

router = APIRouter(prefix="/auth", tags=["auth"])


class MeResponse(BaseModel):
    id: str
    email: str | None
    display_name: str | None


def get_admin_client() -> SupabaseAdminClient:
    return SupabaseAdminClient(get_settings())


@router.get("/me", response_model=MeResponse)
def read_me(user: CurrentUser = Depends(get_current_user), db: Session = Depends(get_user_db)) -> MeResponse:
    try:
        record = service.get_or_create_app_user(db, user)
    except service.AccountNoLongerExists:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated") from None
    return MeResponse(id=str(record.id), email=record.email, display_name=record.display_name)


@router.delete("/account", status_code=status.HTTP_204_NO_CONTENT)
def delete_account(
    user: CurrentUser = Depends(get_current_user),
    admin: SupabaseAdminClient = Depends(get_admin_client),
) -> Response:
    service.delete_account(user, admin)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
