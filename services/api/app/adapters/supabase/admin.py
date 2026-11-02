"""Supabase Admin and Storage client.

This module is the only place that calls Auth admin and Storage with administrative credentials. Each call
uses a short-lived token from AdminTokenIssuer. The public anon key is the `apikey` for every call.

Callers must check ownership before calling any method here. The admin credentials bypass RLS and Storage
access rules, so they must never be used for application table reads or writes.
tests/unit/test_service_role_scope.py enforces where this module and the signing material may be used.
"""

import uuid
from typing import Any

import httpx

from app.adapters.supabase.admin_tokens import AdminCredentialError, AdminTokenIssuer
from app.core.config import Settings

BUCKET_NAME = "candidate-files"


class AdminNotConfigured(RuntimeError):
    pass


class StorageError(RuntimeError):
    pass


class AuthAdminError(RuntimeError):
    pass


class SupabaseAdminClient:
    def __init__(self, settings: Settings, issuer: AdminTokenIssuer, http: httpx.Client | None = None) -> None:
        if settings.supabase_anon_key is None:
            raise AdminNotConfigured("SUPABASE_ANON_KEY is not set")
        self._base_url = settings.supabase_url.rstrip("/")
        self._apikey = settings.supabase_anon_key
        self._issuer = issuer
        self._http = http or httpx.Client(timeout=10.0)

    def _storage_headers(self, extra: dict[str, str] | None = None) -> dict[str, str]:
        try:
            token = self._issuer.storage_admin_token()
        except AdminCredentialError as exc:
            raise AdminNotConfigured(str(exc)) from exc
        headers = {"apikey": self._apikey, "Authorization": f"Bearer {token}"}
        if extra:
            headers.update(extra)
        return headers

    def _auth_admin_headers(self) -> dict[str, str]:
        try:
            token = self._issuer.auth_admin_token()
        except AdminCredentialError as exc:
            raise AdminNotConfigured(str(exc)) from exc
        return {"apikey": self._apikey, "Authorization": f"Bearer {token}"}

    # ---- auth ----

    def delete_auth_user(self, user_id: uuid.UUID) -> None:
        """Deletes the Auth user. Idempotent: an already-deleted user counts as success."""
        response = self._http.delete(
            f"{self._base_url}/auth/v1/admin/users/{user_id}", headers=self._auth_admin_headers()
        )
        if response.status_code == 404:
            return
        if response.status_code >= 400:
            raise AuthAdminError(f"auth delete failed with status {response.status_code}")

    # ---- storage ----

    def upload_object(self, bucket: str, object_key: str, content: bytes, content_type: str) -> None:
        response = self._http.post(
            f"{self._base_url}/storage/v1/object/{bucket}/{object_key}",
            headers=self._storage_headers({"Content-Type": content_type, "x-upsert": "false"}),
            content=content,
        )
        if response.status_code >= 400:
            raise StorageError(f"upload failed with status {response.status_code}")

    def create_signed_download_url(self, bucket: str, object_key: str, expires_in_seconds: int) -> str:
        response = self._http.post(
            f"{self._base_url}/storage/v1/object/sign/{bucket}/{object_key}",
            headers=self._storage_headers({"Content-Type": "application/json"}),
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
        """Deletes one object. Idempotent: deleting a missing object succeeds."""
        response = self._http.request(
            "DELETE",
            f"{self._base_url}/storage/v1/object/{bucket}",
            headers=self._storage_headers({"Content-Type": "application/json"}),
            json={"prefixes": [object_key]},
        )
        if response.status_code >= 400:
            raise StorageError(f"delete failed with status {response.status_code}")

    def list_object_keys(self, bucket: str, prefix: str) -> list[str]:
        """Returns every object key under `prefix`, following pagination. Keys are full paths."""
        keys: list[str] = []
        offset = 0
        page_size = 100
        while True:
            response = self._http.post(
                f"{self._base_url}/storage/v1/object/list/{bucket}",
                headers=self._storage_headers({"Content-Type": "application/json"}),
                json={"prefix": prefix, "limit": page_size, "offset": offset},
            )
            if response.status_code >= 400:
                raise StorageError(f"listing failed with status {response.status_code}")
            items = response.json()
            for item in items:
                name = str(item.get("name", ""))
                if not name:
                    continue
                full = name if name.startswith(prefix) else f"{prefix}{name}"
                if item.get("id") is not None:  # files have an id, folders do not
                    keys.append(full)
            if len(items) < page_size:
                return keys
            offset += page_size

    def download_object(self, bucket: str, object_key: str) -> bytes:
        response = self._http.get(
            f"{self._base_url}/storage/v1/object/authenticated/{bucket}/{object_key}",
            headers=self._storage_headers(),
        )
        if response.status_code >= 400:
            raise StorageError(f"download failed with status {response.status_code}")
        return response.content
