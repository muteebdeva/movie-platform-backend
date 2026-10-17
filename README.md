# movie-platform-backend

Shared authentication backend and PostgreSQL database for the movie platform
(`muteeb-movie`) and the admin panel (`muteeb-movie-admin`).

Single source of truth for user identity: email/password accounts, sessions,
roles, email verification, and password reset — used by both frontends.

## Layout

- `api/` — Vercel serverless functions (deployed as their own Vercel project)
  - `api/auth/` — signup, signin, signout, me, verify-email,
    request-password-reset, reset-password, admin/bootstrap
  - `api/_lib/` — db, passwords (scrypt), sessions, rate limiting, email,
    validation, audit, CORS, response helpers
- `migrations/` — versioned SQL migrations (`scripts/migrate.ts` applies them)
- `scripts/` — migrate, smoke tests
- `docs/` — SETUP.md, ENV.md, INTEGRATION.md (frontend wiring guide)
- `integrations/vercel-proxy/` — copy-paste `/api/auth/*` proxy routes for the
  frontends (keeps cookies first-party per domain)

## Quick start

See `docs/SETUP.md`. In short:

1. Create a free Neon Postgres database, copy the pooled connection string.
2. `cp .env.example .env` and fill in `DATABASE_URL`.
3. `npm install && npm run migrate`
4. Deploy to Vercel, set the env vars from `docs/ENV.md`.

## Security notes

- Passwords: scrypt (N=16384, r=8, p=1) via Node's built-in crypto. Never
  plaintext, never logged, never returned.
- Sessions: 256-bit random tokens, SHA-256 hashed at rest, HttpOnly cookies.
- Public signup can only create `role = 'user'`. Admin is granted via the
  one-time `admin/bootstrap` endpoint guarded by `BOOTSTRAP_SECRET`.
- Rate limiting is enforced in Postgres (per IP / per email).
- Security events are audit-logged without secrets.
