from app.core.logging import redact


def test_jwt_is_redacted():
    text = "token=eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signaturepart123"
    out = redact(text)
    assert "signaturepart123" not in out
    assert "[REDACTED_JWT]" in out


def test_database_password_is_redacted():
    text = "connecting to postgresql+psycopg://app_api:SuperSecretPassword123@127.0.0.1:54322/postgres"
    out = redact(text)
    assert "SuperSecretPassword123" not in out
    assert "app_api" in out


def test_plain_text_is_unchanged():
    assert redact("user created") == "user created"
