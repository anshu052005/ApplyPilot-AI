"""Creates or updates the Storage buckets declared in supabase/config.toml. Idempotent.

Why this exists: Supabase CLI 2.34.3 declares buckets in config.toml but does not create them on `supabase start`
(verified: the bucket list stayed empty). This script is the reproducible way to get them, and it reads the same
config.toml, so the declaration stays the single source of truth.

Run after `npx supabase start`:
    services/api/.venv/Scripts/python scripts/local/provision_storage.py

It needs SUPABASE_URL, SUPABASE_ANON_KEY and SUPABASE_STORAGE_SIGNING_SECRET from the local, gitignored .env.
It mints a 15-minute service token per run. No static service-role key is used. Nothing secret is printed.
"""

import re
import sys
import time
import tomllib
from pathlib import Path

import httpx
import jwt

ROOT = Path(__file__).resolve().parents[2]
CONFIG = ROOT / "supabase" / "config.toml"
ENV_FILE = ROOT / ".env"

SIZE_UNITS = {"B": 1, "KB": 1000, "KIB": 1024, "MB": 1000**2, "MIB": 1024**2, "GB": 1000**3, "GIB": 1024**3}


def parse_size(text: str) -> int:
    match = re.fullmatch(r"\s*(\d+)\s*([A-Za-z]+)\s*", text)
    if not match or match.group(2).upper() not in SIZE_UNITS:
        raise ValueError(f"unsupported size {text!r}")
    return int(match.group(1)) * SIZE_UNITS[match.group(2).upper()]


def read_env(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip() and not line.lstrip().startswith("#") and "=" in line:
            key, _, value = line.partition("=")
            values[key.strip()] = value.strip()
    return values


def desired_buckets() -> list[dict]:
    declared = tomllib.loads(CONFIG.read_text(encoding="utf-8")).get("storage", {}).get("buckets", {})
    buckets = []
    for name, settings in declared.items():
        buckets.append(
            {
                "id": name,
                "name": name,
                "public": bool(settings.get("public", False)),
                "file_size_limit": parse_size(settings["file_size_limit"]),
                "allowed_mime_types": list(settings.get("allowed_mime_types", [])),
            }
        )
    return buckets


def main() -> int:
    if not ENV_FILE.exists():
        print("Missing .env. Copy .env.example and fill in the Supabase values first.")
        return 1
    env = read_env(ENV_FILE)
    base = env["SUPABASE_URL"].rstrip("/")
    now = int(time.time())
    token = jwt.encode(
        {"iss": "supabase-demo", "role": "service_role", "iat": now, "exp": now + 900},
        env["SUPABASE_STORAGE_SIGNING_SECRET"],
        algorithm="HS256",
    )
    headers = {"apikey": env["SUPABASE_ANON_KEY"], "Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    buckets = desired_buckets()
    if not buckets:
        print("No buckets declared in supabase/config.toml.")
        return 0

    with httpx.Client(timeout=15.0) as client:
        for bucket in buckets:
            body = {k: v for k, v in bucket.items() if k != "id"}
            exists = client.get(f"{base}/storage/v1/bucket/{bucket['id']}", headers=headers)
            if exists.status_code == 200:
                response = client.put(f"{base}/storage/v1/bucket/{bucket['id']}", headers=headers, json=body)
                action = "updated"
            elif exists.status_code == 404:
                response = client.post(f"{base}/storage/v1/bucket", headers=headers, json=bucket)
                action = "created"
            else:
                print(f"{bucket['id']}: unexpected status {exists.status_code}")
                return 1
            if response.status_code >= 400:
                print(f"{bucket['id']}: {action} failed with status {response.status_code}")
                return 1
            print(f"{bucket['id']}: {action} (public={bucket['public']}, limit={bucket['file_size_limit']} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
