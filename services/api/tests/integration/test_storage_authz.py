"""Storage authorization against the real local Storage service.

Covers: upload authorization and validation, user-scoped object paths, cross-user access (metadata, download
links, deletion), signed-URL lifetime, a private bucket with no direct client access, and the declared bucket
configuration.
"""

import hashlib
import io
import os
import time
import uuid
import zipfile

import httpx
import jwt
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from app.adapters.supabase.admin import SupabaseAdminClient, StorageError
from app.core.config import get_settings
from app.main import create_app

PDF_BYTES = b"%PDF-1.7\n" + b"candidate resume content\n" * 40
TEXT_BYTES = b"plain text is not an accepted document"
PDF_MIME = "application/pdf"
DOCX_MIME = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"


def make_docx() -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", "<Types/>")
        archive.writestr("word/document.xml", "<document>cv</document>")
    return buffer.getvalue()


@pytest.fixture
def client():
    with TestClient(create_app()) as test_client:
        yield test_client


@pytest.fixture
def admin():
    return SupabaseAdminClient(get_settings())


@pytest.fixture
def storage_base():
    return get_settings().supabase_url.rstrip("/") + "/storage/v1"


def _auth(user) -> dict[str, str]:
    return {"Authorization": f"Bearer {user.access_token}"}


def _upload(client, user, data: bytes, mime: str | None, filename: str = "cv.pdf"):
    return client.post(
        "/api/v1/files",
        headers=_auth(user),
        files={"file": (filename, data, mime) if mime is not None else (filename, data)},
    )


@pytest.fixture
def uploaded_a(client, user_a):
    response = _upload(client, user_a, PDF_BYTES, PDF_MIME)
    assert response.status_code == 201, response.text
    return response.json()


# ---- upload authorization and validation ----


def test_upload_requires_authentication(client):
    response = client.post("/api/v1/files", files={"file": ("cv.pdf", PDF_BYTES, PDF_MIME)})
    assert response.status_code == 401


def test_pdf_upload_is_stored_under_the_owners_prefix(client, user_a, owner_sql, admin, uploaded_a):
    key = owner_sql("SELECT object_key FROM candidate_files WHERE id = :id", {"id": uploaded_a["id"]})[0][0]
    assert key.startswith(f"{user_a.id}/")
    assert key.endswith(".pdf")
    assert admin.download_object("candidate-files", key) == PDF_BYTES


def test_metadata_records_size_and_sha256(uploaded_a):
    assert uploaded_a["size_bytes"] == len(PDF_BYTES)
    assert uploaded_a["sha256"] == hashlib.sha256(PDF_BYTES).hexdigest()
    assert uploaded_a["mime_type"] == PDF_MIME


def test_docx_upload_is_accepted(client, user_a):
    response = _upload(client, user_a, make_docx(), DOCX_MIME, filename="cv.docx")
    assert response.status_code == 201, response.text
    assert response.json()["mime_type"] == DOCX_MIME


def test_declared_mime_must_match_the_content(client, user_a):
    response = _upload(client, user_a, PDF_BYTES, DOCX_MIME)
    assert response.status_code == 415


def test_text_content_is_rejected_even_when_declared_as_pdf(client, user_a):
    response = _upload(client, user_a, TEXT_BYTES, PDF_MIME)
    assert response.status_code == 415


# httpx infers a type from the filename when none is given, so a generic type is used to test the generic case.
@pytest.mark.parametrize("declared", ["text/plain", "image/png", "application/x-msdownload", "application/octet-stream"])
def test_disallowed_declared_types_are_rejected(client, user_a, declared):
    response = _upload(client, user_a, PDF_BYTES, declared)
    assert response.status_code == 415


def test_oversize_upload_is_rejected(client, user_a):
    too_big = b"%PDF-" + b"0" * (10 * 1024 * 1024)
    response = _upload(client, user_a, too_big, PDF_MIME)
    assert response.status_code == 413


def test_empty_upload_is_rejected(client, user_a):
    response = _upload(client, user_a, b"", PDF_MIME)
    assert response.status_code in (415, 422)


def test_client_filename_cannot_change_the_storage_path(client, user_a, user_b, owner_sql, uploaded_a):
    response = _upload(client, user_a, PDF_BYTES, PDF_MIME, filename=f"../../{user_b.id}/stolen.pdf")
    assert response.status_code == 201, response.text
    key = owner_sql("SELECT object_key FROM candidate_files WHERE id = :id", {"id": response.json()["id"]})[0][0]
    assert key.startswith(f"{user_a.id}/")
    assert str(user_b.id) not in key
    assert ".." not in key


# ---- cross-user access ----


def test_other_user_cannot_read_file_metadata(client, user_b, uploaded_a):
    response = client.get(f"/api/v1/files/{uploaded_a['id']}", headers=_auth(user_b))
    assert response.status_code == 404


def test_other_user_cannot_create_a_download_link(client, user_b, uploaded_a):
    response = client.post(f"/api/v1/files/{uploaded_a['id']}/download-url", headers=_auth(user_b))
    assert response.status_code == 404


def test_other_user_cannot_delete_the_file(client, user_b, user_a, uploaded_a, admin, owner_sql):
    response = client.delete(f"/api/v1/files/{uploaded_a['id']}", headers=_auth(user_b))
    assert response.status_code == 404
    still_there = owner_sql("SELECT count(*) FROM candidate_files WHERE id = :id", {"id": uploaded_a["id"]})[0][0]
    assert still_there == 1
    key = owner_sql("SELECT object_key FROM candidate_files WHERE id = :id", {"id": uploaded_a["id"]})[0][0]
    assert admin.download_object("candidate-files", key) == PDF_BYTES


def test_missing_and_foreign_files_look_identical(client, user_b, uploaded_a):
    """A probe for a real file owned by someone else must not differ from a probe for a non-existent file."""
    foreign = client.get(f"/api/v1/files/{uploaded_a['id']}", headers=_auth(user_b))
    missing = client.get(f"/api/v1/files/{uuid.uuid4()}", headers=_auth(user_b))
    assert foreign.status_code == missing.status_code == 404
    assert foreign.json() == missing.json()


def test_storage_api_refuses_direct_access_with_another_users_token(
    storage_base, user_a, user_b, uploaded_a, owner_sql
):
    key = owner_sql("SELECT object_key FROM candidate_files WHERE id = :id", {"id": uploaded_a["id"]})[0][0]
    anon_key = os.environ["SUPABASE_ANON_KEY"]
    response = httpx.get(
        f"{storage_base}/object/candidate-files/{key}",
        headers={"apikey": anon_key, "Authorization": f"Bearer {user_b.access_token}"},
        timeout=10.0,
    )
    assert response.status_code != 200
    assert response.content != PDF_BYTES


def test_anonymous_direct_access_to_the_bucket_is_refused(storage_base, uploaded_a, owner_sql):
    key = owner_sql("SELECT object_key FROM candidate_files WHERE id = :id", {"id": uploaded_a["id"]})[0][0]
    anon = os.environ["SUPABASE_ANON_KEY"]
    public_path = httpx.get(f"{storage_base}/object/public/candidate-files/{key}", timeout=10.0)
    authed_path = httpx.get(
        f"{storage_base}/object/candidate-files/{key}", headers={"apikey": anon}, timeout=10.0
    )
    listing = httpx.post(
        f"{storage_base}/object/list/candidate-files",
        headers={"apikey": anon, "Authorization": f"Bearer {anon}", "Content-Type": "application/json"},
        json={"prefix": "", "limit": 10, "offset": 0},
        timeout=10.0,
    )
    assert public_path.status_code != 200
    assert authed_path.status_code != 200
    assert not (listing.status_code == 200 and listing.json())


# ---- download links ----


def test_owner_gets_a_short_lived_signed_link_that_returns_the_file(client, user_a, uploaded_a):
    response = client.post(f"/api/v1/files/{uploaded_a['id']}/download-url", headers=_auth(user_a))
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["expires_in_seconds"] <= 120

    token = body["url"].split("token=", 1)[1]
    claims = jwt.decode(token, options={"verify_signature": False})
    remaining = claims["exp"] - time.time()
    assert 0 < remaining <= 130, f"signed URL lifetime is {remaining:.0f}s, expected at most 120s"

    fetched = httpx.get(body["url"], timeout=10.0)
    assert fetched.status_code == 200
    assert fetched.content == PDF_BYTES


def test_signed_link_is_not_issued_for_a_non_owned_file_even_if_the_url_is_guessed(client, user_b, uploaded_a):
    response = client.post(f"/api/v1/files/{uploaded_a['id']}/download-url", headers=_auth(user_b))
    assert response.status_code == 404
    assert "url" not in response.json()


# ---- deletion ----


def test_owner_can_delete_their_file_and_the_object_is_removed(client, user_a, uploaded_a, admin, owner_sql):
    key = owner_sql("SELECT object_key FROM candidate_files WHERE id = :id", {"id": uploaded_a["id"]})[0][0]
    response = client.delete(f"/api/v1/files/{uploaded_a['id']}", headers=_auth(user_a))
    assert response.status_code == 204
    assert client.get(f"/api/v1/files/{uploaded_a['id']}", headers=_auth(user_a)).status_code == 404
    with pytest.raises(StorageError):
        admin.download_object("candidate-files", key)


# ---- bucket configuration ----


def test_bucket_matches_the_declared_configuration(admin, storage_base):
    settings = get_settings()
    response = httpx.get(
        f"{storage_base}/bucket/candidate-files",
        headers={"apikey": settings.supabase_service_role_key.get_secret_value(),
                 "Authorization": f"Bearer {settings.supabase_service_role_key.get_secret_value()}"},
        timeout=10.0,
    )
    assert response.status_code == 200, response.text
    bucket = response.json()
    assert bucket["public"] is False
    assert bucket["file_size_limit"] == 10 * 1024 * 1024
    assert sorted(bucket["allowed_mime_types"]) == sorted([PDF_MIME, DOCX_MIME])
