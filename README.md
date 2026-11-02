# ApplyPilot AI

A job application assistant. You stay in control: nothing is submitted without your explicit approval.

Status: **Milestone 2 (Foundation)**. Authentication and per-user data isolation. See `CLAUDE.md` for architecture rules and commands.

## Prerequisites
- Node.js 24+, npm
- Python 3.11 (the API was built with 3.11.9)
- Docker Desktop, running

## Setup

```bash
# 1. Local Supabase stack (Postgres, Auth, Storage) and the Supabase CLI
npm install
npm run db:start
services/api/.venv/Scripts/python scripts/local/generate_signing_key.py   # ES256 signing key (gitignored)
npx supabase stop && npx supabase start                                          # pick up the signing key
npx supabase status -o env        # copy the values into .env (leave SUPABASE_JWT_SECRET empty)
services/api/.venv/Scripts/python scripts/local/mint_admin_jwt.py                 # adds SUPABASE_ADMIN_JWT to .env
services/api/.venv/Scripts/python scripts/local/provision_storage.py              # creates the candidate-files bucket

# 2. API
cd services/api
python -m venv .venv
.venv/Scripts/python -m pip install -r requirements-dev.txt
# Set MIGRATION_DATABASE_URL, APP_API_DB_PASSWORD, DATABASE_URL (see .env.example), then:
.venv/Scripts/python -m alembic upgrade head

# 3. Frontend
cd ../../apps/web
npm install
# Create .env.local with the NEXT_PUBLIC_* values from .env.example
npm run dev
```

## Tests

```bash
# API unit tests (no database needed)
cd services/api && .venv/Scripts/python -m pytest tests/unit

# API integration tests (local stack must be running; they fail loudly if it is not)
cd services/api && .venv/Scripts/python -m pytest tests/integration -rs

# Frontend
cd apps/web && npm run typecheck && npm run build
```

## Security model in brief
- The browser talks to Supabase only for sign-in and sign-up.
- FastAPI verifies each Supabase JWT and never uses the service-role key for data.
- Application queries run as the `app_api` database role. Row Level Security limits every query to the signed-in user's rows.
- See `docs/` (added as decisions are finalized) and the architecture plan for details.
