"""Supabase Admin and Storage client.

This is the ONLY module that reads the service-role key. The service role bypasses RLS and Storage access
rules, so it is used only for the operations listed below, and each caller checks ownership first:
- deleting an auth user (account deletion), using the admin JWT
- writing, signing, deleting and reading objects in the private `candidate-files` bucket

It is never used for application table reads or writes. tests/unit/test_service_role_scope.py enforces this.
"""

import uuid
from typing import Any

import httpx

from app.core.config import Settings


class AdminNotConfigured(RuntimeError):
    pass


class StorageError(RuntimeError):
    pass


class SupabaseAdminClient:
    def __init__(self, settings: Settings, http: httpx.Client | None = None) -> None:
        if settings.supabase_service_role_key is None:
            raise AdminNotConfigured("SUPABASE_SERVICE_ROLE_KEY is not set")
        self._base_url = settings.supabase_url.rstrip("/")
        self._key = settings.supabase_service_role_key.get_secret_value()
        self._admin_jwt = settings.supabase_admin_jwt.get_secret_value() if settings.supabase_admin_jwt else None
        self._http = http or httpx.Client(timeout=10.0)

    def _headers(self, extra: dict[str, str] | None = None) -> dict[str, str]:
        """Storage and gateway calls: the service-role key is both apikey and bearer."""
        headers = {"apikey": self._key, "Authorization": f"Bearer {self._key}"}
        if extra:
            headers.update(extra)
        return headers

    def _auth_admin_headers(self) -> dict[str, str]:
        """GoTrue admin calls. GoTrue verifies the bearer against the signing keys, so it needs the admin JWT."""
        if not self._admin_jwt:
            raise AdminNotConfigured("SUPABASE_ADMIN_JWT is not set (required for account deletion)")
        return {"apikey": self._key, "Authorization": f"Bearer {self._admin_jwt}"}

    # ---- auth ----

    def delete_auth_user(self, user_id: uuid.UUID) -> None:
        response = self._http.delete(
            f"{self._base_url}/auth/v1/admin/users/{user_id}", headers=self._auth_admin_headers()
        )
        if response.status_code == 404:
            return  # Already gone: deletion is idempotent.
        response.raise_for_status()

    # ---- storage ----

    def upload_object(self, bucket: str, object_key: str, content: bytes, content_type: str) -> None:
        response = self._http.post(
            f"{self._base_url}/storage/v1/object/{bucket}/{object_key}",
            headers=self._headers({"Content-Type": content_type, "x-upsert": "false"}),
            content=content,
        )
        if response.status_code >= 400:
            raise StorageError(f"upload failed with status {response.status_code}")

    def create_signed_download_url(self, bucket: str, object_key: str, expires_in_seconds: int) -> str:
        response = self._http.post(
            f"{self._base_url}/storage/v1/object/sign/{bucket}/{object_key}",
            headers=self._headers({"Content-Type": "application/json"}),
            json={"expiresIn": expires_in_seconds},
        )
        if response.status_code >= 400:
            raise StorageError(f"signing failed with status {response.status_code}")
        body: dict[str, Any] = response.json()
        signed_path = body.get("signedURL")
        if not isinstance(signed_path, str) or not signed_path.startswith("/"):
            raise StorageError("unexpected signing response")
        return f"{self._base_url}/storage/v1{signed_path}"

    def delete_object(self, bucket: str, object_key: str) -> None:
        response = self._http.request(
            "DELETE",
            f"{self._base_url}/storage/v1/object/{bucket}",
            headers=self._headers({"Content-Type": "application/json"}),
            json={"prefixes": [object_key]},
        )
        if response.status_code >= 400:
            raise StorageError(f"delete failed with status {response.status_code}")

    def download_object(self, bucket: str, object_key: str) -> bytes:
        response = self._http.get(
            f"{self._base_url}/storage/v1/object/authenticated/{bucket}/{object_key}",
            headers=self._headers(),
        )
        if response.status_code >= 400:
            raise StorageError(f"download failed with status {response.status_code}")
        return response.content
