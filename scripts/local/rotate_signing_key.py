"""Rotates the local signing key. This REVOKES the old key: every token signed with it stops verifying.

The local GoTrue build supports one signing key at a time, so rotation is a replacement, not an overlap:
1. The old private key is removed from supabase/signing_keys.json and not kept anywhere.
2. A new ES256 key is written in its place.
3. The stack must be restarted for Auth to load the new key:
       npx supabase stop && docker rm -f supabase_vector_ApplyPilot_AI && npx supabase start
   `stop` keeps the data volumes. Vector may need removing first (it is a logging sidecar).

Requires --confirm, because every existing session on the local stack will be invalidated.
Only the public part of the new key is printed.
"""

import json
import sys
import uuid
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ec
from jwt.algorithms import ECAlgorithm

ROOT = Path(__file__).resolve().parents[2]
KEY_FILE = ROOT / "supabase" / "signing_keys.json"


def main(argv: list[str]) -> int:
    if "--confirm" not in argv:
        print("Refusing to rotate without --confirm. Rotation revokes every token signed with the current key.")
        return 2
    if not KEY_FILE.exists():
        print("No signing key file to rotate. Run scripts/local/generate_signing_key.py first.")
        return 1

    old_kid = json.loads(KEY_FILE.read_text(encoding="utf-8"))[0].get("kid", "unknown")
    private = ec.generate_private_key(ec.SECP256R1())
    jwk = json.loads(ECAlgorithm.to_jwk(private))
    jwk.update({"kid": str(uuid.uuid4()), "alg": "ES256", "use": "sig", "key_ops": ["sign", "verify"]})
    KEY_FILE.write_text(json.dumps([jwk], indent=2) + "\n", encoding="utf-8")

    public_view = {k: v for k, v in jwk.items() if k != "d"}
    print(f"Replaced the signing key. Old kid={old_kid}. New kid={jwk['kid']}.")
    print("New public key:", json.dumps(public_view))
    print("Restart the stack so Auth loads the new key (see the module docstring).")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
