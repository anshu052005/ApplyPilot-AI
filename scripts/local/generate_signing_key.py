"""Creates the local JWT signing key that the Supabase local Auth service uses (ES256).

Output: supabase/signing_keys.json (gitignored). The file holds a PRIVATE key. It is read only by the
local Auth container, through `signing_keys_path` in supabase/config.toml. It must never be copied to the
frontend, the browser worker, logs or Git. The script never overwrites an existing key, because replacing
it would invalidate every session that was signed with it.

Run with the API virtualenv, which has `cryptography` and PyJWT:
    services/api/.venv/Scripts/python scripts/local/generate_signing_key.py
"""

import json
import sys
import uuid
from pathlib import Path

import jwt
from cryptography.hazmat.primitives.asymmetric import ec

ROOT = Path(__file__).resolve().parents[2]
TARGET = ROOT / "supabase" / "signing_keys.json"


def main() -> int:
    if TARGET.exists():
        print(f"Signing key already exists at {TARGET.relative_to(ROOT)}. Nothing changed.")
        return 0

    private_key = ec.generate_private_key(ec.SECP256R1())
    jwk = json.loads(jwt.algorithms.ECAlgorithm.to_jwk(private_key))
    # key_ops is required: without it the local GoTrue reports "no signing key detected" and exits.
    jwk.update({"kid": str(uuid.uuid4()), "alg": "ES256", "use": "sig", "key_ops": ["sign", "verify"]})

    TARGET.write_text(json.dumps([jwk], indent=2) + "\n", encoding="utf-8")
    print(f"Created local signing key at {TARGET.relative_to(ROOT)} (private, gitignored).")
    print(f"kid={jwk['kid']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
