"""Scope of administrative credentials and signing material.

Admin calls bypass RLS and Storage access rules, and the signing key can mint tokens for any user. These tests keep
each of them in the modules that are allowed to touch them.
"""

from pathlib import Path

APP_DIR = Path(__file__).resolve().parents[2] / "app"

# Modules allowed to read the storage signing secret or the signing key path.
SECRET_ALLOWED_IN = {
    "core/config.py",
    "adapters/supabase/admin_tokens.py",
    "adapters/supabase/factory.py",
}
SECRET_TOKENS = (
    "supabase_storage_signing_secret",
    "SUPABASE_STORAGE_SIGNING_SECRET",
    "supabase_signing_keys_path",
    "SUPABASE_SIGNING_KEYS_PATH",
)

# Modules allowed to use the Supabase admin client.
ADMIN_CLIENT_ALLOWED_IN = {
    "adapters/supabase/admin.py",
    "adapters/supabase/factory.py",
    "modules/auth/routes.py",
    "modules/auth/service.py",
    "modules/files/routes.py",
    "modules/files/service.py",
}


def _relative(path: Path) -> str:
    return path.relative_to(APP_DIR).as_posix()


def test_signing_material_is_referenced_only_in_allowed_modules():
    offenders = []
    for path in APP_DIR.rglob("*.py"):
        relative = _relative(path)
        text = path.read_text(encoding="utf-8")
        if any(token in text for token in SECRET_TOKENS) and relative not in SECRET_ALLOWED_IN:
            offenders.append(relative)
    assert offenders == [], f"signing material referenced outside allowed modules: {offenders}"


def test_admin_client_is_used_only_by_allowed_modules():
    offenders = []
    for path in APP_DIR.rglob("*.py"):
        relative = _relative(path)
        if relative not in ADMIN_CLIENT_ALLOWED_IN and "SupabaseAdminClient" in path.read_text(encoding="utf-8"):
            offenders.append(relative)
    assert offenders == [], f"admin client used outside allowed modules: {offenders}"


def test_no_static_service_role_key_is_configured():
    """The long-lived service-role key was removed. Admin access uses short-lived minted tokens only."""
    config = (APP_DIR / "core" / "config.py").read_text(encoding="utf-8")
    assert "supabase_service_role_key" not in config
    assert "supabase_admin_jwt" not in config
    for path in APP_DIR.rglob("*.py"):
        assert "SUPABASE_SERVICE_ROLE_KEY" not in path.read_text(encoding="utf-8"), _relative(path)
