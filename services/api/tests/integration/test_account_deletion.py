"""Account deletion against the real local stack, with injected Storage and Auth failures.

The fault injection wraps the real admin client and fails chosen calls. Everything else (Storage, Auth,
Postgres, RLS and cascades) is the real service.
"""

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from app.adapters.supabase.admin import AuthAdminError, StorageError
from app.adapters.supabase.factory import get_admin_client
from app.main import create_app

PDF = b"%PDF-1.7\n" + b"resume body\n" * 30


class FaultyAdmin:
    """Delegates to the real client, except where a failure is injected."""

    def __init__(
        self,
        real,
        *,
        fail_delete_keys=(),
        fail_auth_times: int = 0,
        fail_all_deletes: bool = False,
        silent_delete_keys=(),
    ):
        self._real = real
        self.fail_delete_keys = set(fail_delete_keys)
        self.fail_auth_times = fail_auth_times
        self.fail_all_deletes = fail_all_deletes
        self.silent_delete_keys = set(silent_delete_keys)

    def delete_object(self, bucket, object_key):
        if self.fail_all_deletes or object_key in self.fail_delete_keys:
            raise StorageError("injected storage failure")
        if object_key in self.silent_delete_keys:
            return None  # Reports success, but the object stays in Storage.
        return self._real.delete_object(bucket, object_key)

    def delete_auth_user(self, user_id):
        if self.fail_auth_times > 0:
            self.fail_auth_times -= 1
            raise AuthAdminError("injected auth failure")
        return self._real.delete_auth_user(user_id)

    def __getattr__(self, name):
        return getattr(self._real, name)


@pytest.fixture
def real_admin():
    return get_admin_client()


@pytest.fixture
def make_client():
    """Returns a factory that builds a TestClient whose admin dependency is the given object."""
    clients = []

    def build(admin=None):
        app = create_app()
        if admin is not None:
            app.dependency_overrides[get_admin_client] = lambda: admin
        test_client = TestClient(app)
        test_client.__enter__()
        clients.append(test_client)
        return test_client

    yield build
    for test_client in clients:
        test_client.__exit__(None, None, None)


def _auth(user):
    return {"Authorization": f"Bearer {user.access_token}"}


def _upload(client, user, filename="cv.pdf"):
    response = client.post(
        "/api/v1/files", headers=_auth(user), files={"file": (filename, PDF, "application/pdf")}
    )
    assert response.status_code == 201, response.text
    return response.json()["id"]


def _object_key(owner_sql, file_id):
    return owner_sql("SELECT object_key FROM candidate_files WHERE id = :id", {"id": file_id})[0][0]


def _stored_keys(real_admin, user):
    return real_admin.list_object_keys("candidate-files", f"{user.id}/")


def _app_user_state(owner_sql, user):
    rows = owner_sql(
        "SELECT deletion_requested_at IS NOT NULL, deletion_last_error FROM app_users WHERE id = :id",
        {"id": user.id},
    )
    return rows[0] if rows else None


def _auth_user_exists(owner_sql, user) -> bool:
    return owner_sql("SELECT count(*) FROM auth.users WHERE id = :id", {"id": user.id})[0][0] == 1


# ---- happy path ----


def test_full_deletion_removes_every_object_row_and_the_auth_user(make_client, real_admin, user_a, owner_sql):
    client = make_client()
    file_1 = _upload(client, user_a, "one.pdf")
    file_2 = _upload(client, user_a, "two.pdf")
    # An orphan: an object under the user's prefix with no metadata row. It must be removed too.
    real_admin.upload_object("candidate-files", f"{user_a.id}/orphan-{file_1[:8]}.pdf", PDF, "application/pdf")
    assert len(_stored_keys(real_admin, user_a)) == 3

    response = client.delete("/api/v1/auth/account", headers=_auth(user_a))

    assert response.status_code == 204
    assert _stored_keys(real_admin, user_a) == []
    assert owner_sql("SELECT count(*) FROM candidate_files WHERE user_id = :u", {"u": user_a.id})[0][0] == 0
    assert not _auth_user_exists(owner_sql, user_a)
    assert owner_sql("SELECT count(*) FROM app_users WHERE id = :u", {"u": user_a.id})[0][0] == 0


# ---- partial failure, lock, retry ----


def test_partial_storage_failure_returns_pending_and_locks_the_account(
    make_client, real_admin, user_a, owner_sql
):
    client = make_client()
    file_1 = _upload(client, user_a, "one.pdf")
    file_2 = _upload(client, user_a, "two.pdf")
    keys = {file_1: _object_key(owner_sql, file_1), file_2: _object_key(owner_sql, file_2)}
    # Cleanup deletes in sorted key order and stops at the first failure. Fail the key that sorts last, so the
    # other file is deleted first. Random file ids would otherwise make the expected count flaky.
    failing_file = max(keys, key=keys.get)
    healthy_file = min(keys, key=keys.get)
    faulty = FaultyAdmin(real_admin, fail_delete_keys={keys[failing_file]})
    failing_client = make_client(faulty)

    response = failing_client.delete("/api/v1/auth/account", headers=_auth(user_a))

    assert response.status_code == 202, response.text
    assert response.json()["status"] == "pending"
    # Never report success while personal files remain.
    assert _stored_keys(real_admin, user_a) == [keys[failing_file]]
    assert owner_sql("SELECT count(*) FROM candidate_files WHERE id = :id", {"id": healthy_file})[0][0] == 0
    assert owner_sql("SELECT count(*) FROM candidate_files WHERE id = :id", {"id": failing_file})[0][0] == 1
    state = _app_user_state(owner_sql, user_a)
    assert state == (True, "storage_cleanup_failed")
    assert _auth_user_exists(owner_sql, user_a), "Auth account must not be deleted while files remain"


def test_storage_delete_that_reports_success_but_leaves_the_object_is_caught(
    make_client, real_admin, user_a, owner_sql
):
    """The post-cleanup verification is the only guard for this case. Without it, the Auth user would be
    deleted while the object still exists, orphaning personal data in Storage."""
    client = make_client()
    file_id = _upload(client, user_a)
    key = _object_key(owner_sql, file_id)
    faulty = make_client(FaultyAdmin(real_admin, silent_delete_keys={key}))
    try:
        response = faulty.delete("/api/v1/auth/account", headers=_auth(user_a))

        assert response.status_code == 202, response.text
        assert _stored_keys(real_admin, user_a) == [key], "the object really is still in Storage"
        assert _auth_user_exists(owner_sql, user_a), "Auth user must not be deleted while Storage holds files"
        assert _app_user_state(owner_sql, user_a) == (True, "storage_cleanup_failed")
    finally:
        real_admin.delete_object("candidate-files", key)


def test_pending_account_cannot_reach_its_data(make_client, real_admin, user_a, owner_sql):
    client = make_client()
    file_id = _upload(client, user_a)
    faulty_client = make_client(FaultyAdmin(real_admin, fail_all_deletes=True))
    assert faulty_client.delete("/api/v1/auth/account", headers=_auth(user_a)).status_code == 202

    assert client.get("/api/v1/auth/me", headers=_auth(user_a)).status_code == 423
    assert client.get(f"/api/v1/files/{file_id}", headers=_auth(user_a)).status_code == 423
    assert client.post(f"/api/v1/files/{file_id}/download-url", headers=_auth(user_a)).status_code == 423
    assert client.delete(f"/api/v1/files/{file_id}", headers=_auth(user_a)).status_code == 423
    upload = client.post(
        "/api/v1/files", headers=_auth(user_a), files={"file": ("x.pdf", PDF, "application/pdf")}
    )
    assert upload.status_code == 423


def test_retry_after_storage_failure_completes_the_deletion(make_client, real_admin, user_a, owner_sql):
    client = make_client()
    _upload(client, user_a, "one.pdf")
    file_2 = _upload(client, user_a, "two.pdf")
    key_2 = _object_key(owner_sql, file_2)
    make_client(FaultyAdmin(real_admin, fail_delete_keys={key_2})).delete(
        "/api/v1/auth/account", headers=_auth(user_a)
    )

    response = client.delete("/api/v1/auth/account", headers=_auth(user_a))

    assert response.status_code == 204
    assert _stored_keys(real_admin, user_a) == []
    assert not _auth_user_exists(owner_sql, user_a)


def test_repeated_requests_while_pending_are_safe_and_do_not_report_success(
    make_client, real_admin, user_a, owner_sql
):
    client = make_client()
    _upload(client, user_a)
    failing = make_client(FaultyAdmin(real_admin, fail_all_deletes=True))

    for _ in range(3):
        response = failing.delete("/api/v1/auth/account", headers=_auth(user_a))
        assert response.status_code == 202
    assert len(_stored_keys(real_admin, user_a)) == 1
    assert _app_user_state(owner_sql, user_a) == (True, "storage_cleanup_failed")

    assert client.delete("/api/v1/auth/account", headers=_auth(user_a)).status_code == 204


def test_auth_failure_after_storage_is_clean_is_pending_and_retryable(make_client, real_admin, user_a, owner_sql):
    client = make_client()
    file_id = _upload(client, user_a)
    faulty = make_client(FaultyAdmin(real_admin, fail_auth_times=1))

    first = faulty.delete("/api/v1/auth/account", headers=_auth(user_a))

    assert first.status_code == 202
    assert _stored_keys(real_admin, user_a) == []
    assert owner_sql("SELECT count(*) FROM candidate_files WHERE id = :id", {"id": file_id})[0][0] == 0
    assert _auth_user_exists(owner_sql, user_a)
    assert _app_user_state(owner_sql, user_a) == (True, "auth_delete_failed")

    second = client.delete("/api/v1/auth/account", headers=_auth(user_a))
    assert second.status_code == 204
    assert not _auth_user_exists(owner_sql, user_a)


def test_request_after_completion_is_refused(make_client, user_a):
    client = make_client()
    assert client.delete("/api/v1/auth/account", headers=_auth(user_a)).status_code == 204
    again = client.delete("/api/v1/auth/account", headers=_auth(user_a))
    assert again.status_code == 401


# ---- cross-user ----


def test_deleting_one_account_never_touches_another_users_data(make_client, real_admin, user_a, user_b, owner_sql):
    client = make_client()
    file_a = _upload(client, user_a)
    _upload(client, user_b)
    keys_a_before = _stored_keys(real_admin, user_a)

    response = client.delete("/api/v1/auth/account", headers=_auth(user_b))

    assert response.status_code == 204
    assert _stored_keys(real_admin, user_a) == keys_a_before
    assert _auth_user_exists(owner_sql, user_a)
    assert owner_sql("SELECT count(*) FROM candidate_files WHERE id = :id", {"id": file_a})[0][0] == 1
    assert client.get(f"/api/v1/files/{file_a}", headers=_auth(user_a)).status_code == 200
    assert client.post(f"/api/v1/files/{file_a}/download-url", headers=_auth(user_a)).status_code == 200


def test_user_cannot_delete_another_users_file_during_their_own_deletion(make_client, real_admin, user_a, user_b, owner_sql):
    client = make_client()
    file_a = _upload(client, user_a)
    faulty = make_client(FaultyAdmin(real_admin, fail_all_deletes=True))
    assert faulty.delete("/api/v1/auth/account", headers=_auth(user_b)).status_code in (202, 204)

    response = client.delete(f"/api/v1/files/{file_a}", headers=_auth(user_b))

    assert response.status_code == 404
    assert len(_stored_keys(real_admin, user_a)) == 1


def test_user_a_is_unaffected_by_user_bs_pending_state(make_client, real_admin, user_a, user_b):
    client = make_client()
    _upload(client, user_a)
    faulty = make_client(FaultyAdmin(real_admin, fail_all_deletes=True))
    faulty.delete("/api/v1/auth/account", headers=_auth(user_b))

    assert client.get("/api/v1/auth/me", headers=_auth(user_a)).status_code == 200


# ---- structural guarantees ----


def test_every_foreign_key_to_app_users_cascades_on_delete(owner_sql):
    """New user-owned tables must cascade, so the Auth delete removes all of a user's rows."""
    rows = owner_sql(
        """
        SELECT conrelid::regclass::text, confdeltype
        FROM pg_constraint
        WHERE contype = 'f' AND confrelid = 'public.app_users'::regclass
        """
    )
    assert rows, "expected at least one foreign key to app_users"
    for table, delete_action in rows:
        assert delete_action == "c", f"{table} must use ON DELETE CASCADE"


def test_storage_listing_returns_full_keys_under_the_prefix(make_client, real_admin, user_a, owner_sql):
    client = make_client()
    file_id = _upload(client, user_a)
    keys = _stored_keys(real_admin, user_a)
    assert keys == [_object_key(owner_sql, file_id)]
    assert all(key.startswith(f"{user_a.id}/") for key in keys)
