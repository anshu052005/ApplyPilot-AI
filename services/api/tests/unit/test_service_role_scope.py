"""The service-role key bypasses RLS. These tests confine its use to the admin adapter and config."""

from pathlib import Path

APP_DIR = Path(__file__).resolve().parents[2] / "app"
KEY_ALLOWED_IN = {
    APP_DIR / "core" / "config.py",
    APP_DIR / "adapters" / "supabase" / "admin.py",
}
KEY_TOKENS = ("supabase_service_role_key", "SUPABASE_SERVICE_ROLE_KEY")
ADMIN_CLIENT_ALLOWED_IN = {"admin.py", "routes.py", "service.py"}


def test_service_role_key_is_referenced_only_in_config_and_admin_adapter():
    offenders = []
    for path in APP_DIR.rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        if any(token in text for token in KEY_TOKENS) and path not in KEY_ALLOWED_IN:
            offenders.append(str(path.relative_to(APP_DIR)))
    assert offenders == [], f"service-role key referenced outside allowed modules: {offenders}"


def test_admin_client_is_used_only_by_auth_module():
    offenders = []
    for path in APP_DIR.rglob("*.py"):
        if path.name not in ADMIN_CLIENT_ALLOWED_IN and "SupabaseAdminClient" in path.read_text(encoding="utf-8"):
            offenders.append(str(path.relative_to(APP_DIR)))
    assert offenders == [], f"admin client used outside allowed modules: {offenders}"
