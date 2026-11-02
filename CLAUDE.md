# ApplyPilot AI: project instructions

Read `C:\Users\user\.claude\plans\continue-async-ocean.md` for the approved architecture. §15 is the current source of truth.

## Layout
- `apps/web`: Next.js (App Router), TypeScript, Tailwind. Uses supabase-js for auth only. No direct database access.
- `services/api`: FastAPI, SQLAlchemy 2, Alembic, PyJWT. Owns all application data access.
- `services/browser_worker`: not yet created (M5).
- `supabase/`: local stack config only (`config.toml`). Schema is owned by Alembic.

## Non-negotiable rules
1. **Application data goes through `get_user_db` / `get_db_for_user`** (`services/api/app/db/session.py`). Those sessions run as `app_api`, which is subject to RLS.
2. **Never use the service-role key for data access.** It is read only in `app/core/config.py` and `app/adapters/supabase/admin.py`. `tests/unit/test_service_role_scope.py` enforces this.
3. **Never use a superuser or owner connection at runtime.** `MIGRATION_DATABASE_URL` is for Alembic only.
4. **Every new user-owned table** must: carry `user_id` (or `id` referencing `auth.users`), be added to `USER_OWNED_TABLES` in `app/db/base.py`, get RLS enabled and forced in an Alembic migration, get explicit policies for `app_api`, and get cross-user tests in `tests/integration/`.
5. **Fail closed.** Missing or invalid identity returns 401 or zero rows. Cross-user access returns 404, not 403.
6. **Browser worker, LLM and browser sessions** are out of scope until their milestones. Do not add stubs that pretend to work.
7. The frontend never receives the service-role key. `NEXT_PUBLIC_*` values are public by design.

## Commands
- Start the local stack (Docker Desktop must be running): `npm install` then `npm run db:start`
- Export Supabase values: `npx supabase status -o env`
- Migrate: `cd services/api && MIGRATION_DATABASE_URL=... python -m alembic upgrade head`
- API unit tests: `cd services/api && .venv/Scripts/python -m pytest tests/unit`
- API integration tests (stack required): `.venv/Scripts/python -m pytest tests/integration -rs`
- Frontend: `cd apps/web && npm run typecheck && npm run build`
- API dev server: `cd services/api && .venv/Scripts/python -m uvicorn app.main:app --reload`

## Local setup order (Supabase local stack)
1. Docker Desktop running.
2. `npm install` (project-local Supabase CLI), then `npm run db:start`.
3. `services/api/.venv/Scripts/python scripts/local/generate_signing_key.py` creates `supabase/signing_keys.json` (private, gitignored, never overwritten).
4. Restart the stack with `npx supabase stop` then `npx supabase start` when the signing key changes (stop keeps data).
5. Copy `.env.example` to `.env` and fill the values from `npx supabase status -o env`. Leave `SUPABASE_JWT_SECRET` empty.
6. `services/api/.venv/Scripts/python scripts/local/mint_admin_jwt.py` writes `SUPABASE_ADMIN_JWT` into `.env`.
7. `services/api/.venv/Scripts/python scripts/local/provision_storage.py` creates or updates the buckets declared in `supabase/config.toml`. Idempotent.
8. `cd services/api && python -m alembic upgrade head` (with `MIGRATION_DATABASE_URL` and `APP_API_DB_PASSWORD` set).

## Pinned versions and why
- Supabase CLI `2.34.3` (project-local via `npx`). Chosen to be at least two weeks old at install. It does NOT create storage buckets from config.toml, so `provision_storage.py` does.
- Next `16.4.2`, React `19.3.1`, supabase-js `2.118.0`, Tailwind `4.3.3`, TypeScript `5.9.x`. TypeScript 7 is avoided because Next relies on the TS 5 compiler API.
- Python 3.11.9. Dependencies pinned in `services/api/requirements*.txt`.

## Auth and signing decisions
- User tokens are ES256, signed by the local Auth service with `supabase/signing_keys.json`. FastAPI verifies them against the JWKS endpoint via `app/modules/auth/jwks.py` (throttled refresh, rotation, fail-closed after max stale).
- The signing key needs `key_ops: ["sign", "verify"]`. Without it local GoTrue exits with "no signing key detected".
- GoTrue's admin API accepts only ES256 service_role tokens once asymmetric signing is on. Storage accepts only the HS256 service key. Hence two credentials: `SUPABASE_SERVICE_ROLE_KEY` (Storage, apikey) and `SUPABASE_ADMIN_JWT` (GoTrue admin).
- Production: configure asymmetric signing keys in the hosted project and point `SUPABASE_URL` at it. Confirm the admin credential model for the hosted project before deploying (open item).

## Storage decisions
- Bucket `candidate-files`: private, 10 MiB, PDF and DOCX only. Declared in `supabase/config.toml`, created by `provision_storage.py`.
- Storage's own RLS on `storage.objects` is left as Supabase ships it (no client policies), so clients cannot reach objects. All access goes through the API, which checks ownership and returns signed URLs valid for 120 seconds.
- Object keys are server-built as `<user_id>/<file_id>.<ext>`. Client filenames are display-only.

## Decisions recorded so far
- Supabase local stack replaces a local Postgres container. Alembic owns all application tables, RLS and grants.
- The database identity function is `public.app_current_user_id()`, which reads `request.jwt.claims`. This is equivalent to `auth.uid()` and does not depend on the Supabase version.
- Account deletion deletes the Supabase auth user first. The foreign key cascades to `app_users` and `audit_logs`, so a failed deletion can be retried.
- Storage deletion will be added in M3, when candidate files exist.

## Status
- M2 (Foundation): in progress. See the plan for scope.
