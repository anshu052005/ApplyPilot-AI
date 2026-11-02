# ADR 0002: Signing keys, administrative access and production limits

Status: accepted for local development. Production design proposed, to be confirmed before deployment (M8).

## Context

Local Supabase (CLI 2.34.3, GoTrue v2.178) signs user tokens with an ES256 key stored in `supabase/signing_keys.json`.
The API server needs two privileged capabilities that user tokens cannot provide:

1. Auth admin operations, such as deleting an Auth user during account deletion.
2. Storage operations, such as listing, deleting and signing objects in the private `candidate-files` bucket.

For local development the implementation mints short-lived admin tokens in the API process
(`app/adapters/supabase/admin_tokens.py`). The ES256 admin token is signed with the same private key that signs
user tokens. This means **any process that holds that key can mint a token for any user.**

## Local development limitation (accepted)

- The API process reads `supabase/signing_keys.json`, which contains the private signing key.
- Anyone with that file can mint tokens for any user, including admin tokens.
- Local GoTrue supports exactly one signing key, so an overlap window cannot be exercised locally. Rotation is a
  replacement, performed by `scripts/local/rotate_signing_key.py --confirm`, which revokes every existing token.
- The file is gitignored and never overwritten by the setup scripts.

This is acceptable only on a developer machine. It must not be used unchanged in any shared or hosted environment.

## Production design

### User authentication and JWT verification

- Use Supabase-managed JWT signing keys (asymmetric). Supabase holds the private key. The API holds only the public
  side, obtained from the project's JWKS endpoint, as it does locally. The API never needs the private key.
- Rotation uses Supabase's standby → current → previously-used → revoked lifecycle. Standby keys appear in JWKS before
  they sign, so caches can refresh first. Revocation of the old key is done only after the cache-propagation window
  and the access-token lifetime have passed. The current JWKS cache (throttled refresh, max stale, fail-closed) covers
  the verifier side.
- Source: Supabase docs, "JWT Signing Keys" (supabase.com/docs/guides/auth/signing-keys) and "JSON Web Token"
  (supabase.com/docs/guides/auth/jwts).

### Administrative access (separate from user authentication)

- Hosted Supabase recommends **secret API keys** (`sb_secret_...`) in place of the legacy `service_role` JWT. They are
  opaque server-side keys, several can be issued and rotated independently, and they are rejected from browsers. The
  legacy keys are scheduled to be retired.
- Source: Supabase docs, "API keys" and "Migrating to publishable and secret API keys"
  (supabase.com/docs/guides/getting-started/api-keys, supabase.com/docs/guides/getting-started/migrating-to-new-api-keys).
- Production admin calls (Auth admin and Storage) therefore use a **secret API key** held in the secret manager. The API
  does not mint admin tokens and never sees the user-token signing key.
- **Not yet confirmed:** whether the Storage REST endpoints accept `sb_secret_` keys as the bearer credential, and
  whether the Auth admin endpoints accept them without a JWT. Confirm against a hosted test project before M8 sign-off.
  If either does not, the fallback is a short-lived service token issued by the Supabase-managed key, not a
  self-minted one.

### Separation of duties

| Capability | Who holds it | Where it runs |
|---|---|---|
| Sign user tokens (private JWT key) | Supabase (managed) | Supabase Auth only |
| Verify user tokens (public JWKS) | API | API process |
| Administrative API calls (secret API key) | API, from secret manager | API process only, never the browser or the worker |
| Database migrations (owner role) | Migration job | CI or deploy step, never the API runtime |
| Runtime database (`app_api`, no BYPASSRLS) | API | API process |

The browser holds only the publishable key. The worker holds no Supabase credential in M2.

### Secrets management

- Production secrets (secret API key, database passwords, Storage signing secret if still used) come from a managed
  secret store with access logging and rotation. They are injected at process start. They are not stored in `.env`
  files, images, logs or the repository.
- `.env` is a local-development file only and is gitignored.

## Consequences

- The local stack keeps the working implementation. Its limitations are documented here and in `CLAUDE.md`.
- Before any hosted deployment: remove `SUPABASE_SIGNING_KEYS_PATH` from the API environment; switch admin calls to a
  secret API key from the secret store; confirm the Storage and Auth admin behaviour in the open item above; run a
  rotation drill on the hosted project using the standby-and-rotate sequence.
- `SUPABASE_STORAGE_SIGNING_SECRET` in `.env` is root-equivalent for Storage. It must move to the secret store, or be
  replaced by a secret API key, before deployment.
