"""Supabase Admin API client.

This is the ONLY module that reads the service-role key. It is used for operations that Supabase
exposes only through the admin API (deleting an auth user). It is never used for application data
reads or writes, because the service role bypasses RLS. tests/unit/test_service_role_scope.py enforces this.
"""

import uuid

import httpx

from app.core.config import Settings


class AdminNotConfigured(RuntimeError):
    pass


class SupabaseAdminClient:
    def __init__(self, settings: Settings, http: httpx.Client | None = None) -> None:
        if settings.supabase_service_role_key is None:
            raise AdminNotConfigured("SUPABASE_SERVICE_ROLE_KEY is not set")
        self._base_url = settings.supabase_url.rstrip("/")
        self._key = settings.supabase_service_role_key.get_secret_value()
        self._http = http or httpx.Client(timeout=10.0)

    def delete_auth_user(self, user_id: uuid.UUID) -> None:
        response = self._http.delete(
            f"{self._base_url}/auth/v1/admin/users/{user_id}",
            headers={"apikey": self._key, "Authorization": f"Bearer {self._key}"},
        )
        if response.status_code == 404:
            return  # Already gone: deletion is idempotent.
        response.raise_for_status()
