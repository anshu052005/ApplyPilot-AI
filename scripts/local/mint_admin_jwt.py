"""Mints the local admin JWT (role service_role, ES256) and writes it to the gitignored .env.

Why: with asymmetric signing enabled, the local GoTrue admin API rejects the HS256 service-role key
("signing method HS256 is invalid"). A service_role JWT signed with the project's own signing key is accepted.
Storage does not accept ES256 and keeps using the HS256 service-role key, so both values are needed.

The token is a bearer credential with service-role power. Treat it like SUPABASE_SERVICE_ROLE_KEY:
it stays in the gitignored .env, is read only by app/adapters/supabase/admin.py, and is never printed.

Run after `npx supabase start` (the signing key must exist first):
    services/api/.venv/Scripts/python scripts/local/mint_admin_jwt.py
"""

import json
import re
import sys
import time
from pathlib import Path

import jwt
from jwt.algorithms import ECAlgorithm

ROOT = Path(__file__).resolve().parents[2]
KEY_FILE = ROOT / "supabase" / "signing_keys.json"
ENV_FILE = ROOT / ".env"
VALID_FOR_SECONDS = 365 * 24 * 3600
ISSUER = "http://127.0.0.1:54321/auth/v1"


def main() -> int:
    if not KEY_FILE.exists():
        print("No signing key found. Run scripts/local/generate_signing_key.py first.")
        return 1
    if not ENV_FILE.exists():
        print("Missing .env. Copy .env.example and fill in the Supabase values first.")
        return 1

    jwk = json.loads(KEY_FILE.read_text(encoding="utf-8"))[0]
    private_key = ECAlgorithm.from_jwk(json.dumps(jwk))
    now = int(time.time())
    token = jwt.encode(
        {"iss": ISSUER, "role": "service_role", "iat": now, "exp": now + VALID_FOR_SECONDS},
        private_key,
        algorithm="ES256",
        headers={"kid": jwk["kid"]},
    )

    text = ENV_FILE.read_text(encoding="utf-8")
    line = f"SUPABASE_ADMIN_JWT={token}"
    if re.search(r"^SUPABASE_ADMIN_JWT=", text, flags=re.M):
        text = re.sub(r"^SUPABASE_ADMIN_JWT=.*$", line, text, flags=re.M)
    else:
        text = text.rstrip("\n") + "\n" + line + "\n"
    ENV_FILE.write_text(text, encoding="utf-8")
    print("Wrote SUPABASE_ADMIN_JWT to .env (valid for 365 days, value not printed).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
